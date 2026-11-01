package eu.kuklin.nodetide.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import eu.kuklin.nodetide.crypto.EncryptionKeyPair
import eu.kuklin.nodetide.crypto.KeySigner
import eu.kuklin.nodetide.crypto.toHex
import eu.kuklin.nodetide.protocol.Events
import eu.kuklin.nodetide.crypto.SigningKeyPair
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

private val Context.identityDataStore: DataStore<Preferences> by preferencesDataStore(name = "identity")

/**
 * The identities held on this phone. Several accounts can be kept; one is active, and the screens that ask for "the current
 * identity" get the active one. Everything is stored as one [AccountBook] document.
 */
class IdentityStore(private val context: Context) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    companion object {
        private val BOOK_KEY = stringPreferencesKey("accounts_v2")
    }

    /** All accounts and the active one. */
    val book: Flow<AccountBook> = context.identityDataStore.data.map { AccountBook.decode(it[BOOK_KEY]) }

    val accounts: Flow<List<Account>> = book.map { it.accounts }

    /** The active account's identity. */
    val identity: Flow<LocalIdentity?> = book.map { it.current?.identity }

    /** Alias for identity flow (used by UI screens). */
    val currentIdentity: Flow<LocalIdentity?> get() = identity

    /** The active account's cached sigchain as raw events (control chain, then content track). */
    val sigchain: Flow<List<JsonObject>> = book.map { it.current?.chain ?: emptyList() }

    private suspend fun update(change: (AccountBook) -> AccountBook) {
        context.identityDataStore.edit { prefs ->
            prefs[BOOK_KEY] = change(AccountBook.decode(prefs[BOOK_KEY])).encode()
        }
    }

    /**
     * Create a new identity and add it as an account (the active one): a master key (which only manages the identity), a
     * device key for daily use that the master authorizes, and the first two events of the chain (genesis and add_device).
     */
    suspend fun createIdentity(
        name: String?,
        distributionPoints: List<String> = emptyList()
    ): LocalIdentity {
        val master = SigningKeyPair.generate()
        val masterEncryption = EncryptionKeyPair.generate()
        val device = SigningKeyPair.generate()
        val deviceEncryption = EncryptionKeyPair.generate()
        val now = System.currentTimeMillis() / 1000

        val genesis = Events.genesis(
            KeySigner(master), masterEncryption.publicKeyHex, now, name?.takeIf { it.isNotBlank() }, distributionPoints.ifEmpty { null },
        )
        val identityHash = Events.identityHash(genesis)
        val addDevice = Events.addDevice(
            KeySigner(master), identityHash, now, device.publicKeyHex, deviceEncryption.publicKeyHex, "Android",
        )

        val identity = LocalIdentity(
            identityHash = identityHash,
            name = name,
            signingSecretKey = master.secretKeyHex,
            signingPublicKey = master.publicKeyHex,
            encryptionSecretKey = masterEncryption.secretKey.toHex(),
            encryptionPublicKey = masterEncryption.publicKeyHex,
            distributionPoints = distributionPoints,
            createdAt = now,
            isDevice = false,
            deviceSigningSecretKey = device.secretKeyHex,
            deviceSigningPublicKey = device.publicKeyHex,
            deviceEncryptionSecretKey = deviceEncryption.secretKey.toHex(),
            deviceEncryptionPublicKey = deviceEncryption.publicKeyHex,
        )
        update { it.with(Account(identity, listOf(genesis, addDevice)), makeActive = true) }
        return identity
    }

    /**
     * Attach as a device to an existing identity (added as an account, the active one).
     */
    suspend fun attachAsDevice(
        masterIdentityHash: String,
        masterSigchain: List<JsonObject>,
        deviceLabel: String?
    ): LocalIdentity {
        val signingKeyPair = SigningKeyPair.generate()
        val timestamp = System.currentTimeMillis() / 1000

        // Get master identity info from genesis
        val genesis = masterSigchain.firstOrNull { (it["type"] as? JsonPrimitive)?.content == "genesis" }
            ?: throw IllegalArgumentException("No genesis event in sigchain")
        fun text(key: String) = (genesis[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

        val identity = LocalIdentity(
            identityHash = masterIdentityHash,
            name = text("name"),
            signingSecretKey = signingKeyPair.secretKeyHex,
            signingPublicKey = signingKeyPair.publicKeyHex,
            encryptionSecretKey = null,
            encryptionPublicKey = text("encryption_pubkey"),
            distributionPoints = (genesis["distribution_points"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content } ?: emptyList(),
            createdAt = timestamp,
            isDevice = true,
            masterIdentityHash = masterIdentityHash
        )
        // (the chain is updated when the AddDevice event is submitted)
        update { it.with(Account(identity, masterSigchain), makeActive = true) }
        return identity
    }

    /** Update the cached sigchain of the active account (or of [hash]). */
    suspend fun updateSigchain(events: List<JsonObject>, hash: String? = null) {
        update { book -> (hash ?: book.current?.hash)?.let { book.withChain(it, events) } ?: book }
    }

    /** Make another account the active one. */
    suspend fun setActive(hash: String) = update { it.activate(hash) }

    /** Remove one account from this phone (its keys go with it). */
    suspend fun removeAccount(hash: String) = update { it.without(hash) }

    /** Remove the active account. */
    suspend fun clear() = update { book -> book.current?.let { book.without(it.hash) } ?: book }

    /** Remove every account. */
    suspend fun clearAll() = update { AccountBook() }

    /** Get the active identity synchronously (for one-time reads). */
    suspend fun getIdentity(): LocalIdentity? = identity.first()

    /** Alias for getIdentity (used by UI screens). */
    suspend fun getCurrentIdentity(): LocalIdentity? = getIdentity()

    /** Get the active account's sigchain synchronously. */
    suspend fun getSigchain(): List<JsonObject> = sigchain.first()

    /** Add or update an account for this identity (e.g. one that is only watched) and make it the active one. */
    suspend fun saveIdentity(identity: LocalIdentity) = update { it.with(Account(identity), makeActive = true) }

    /** Remove the active account (alias for clear). */
    suspend fun clearIdentity() = clear()
}
