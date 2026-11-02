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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

private val Context.identityDataStore: DataStore<Preferences> by preferencesDataStore(name = "identity")

/**
 * The identities held on this phone. Several accounts can be kept; one is active, and the screens that ask for "the current
 * identity" get the active one. Everything is stored as one [AccountBook] document.
 */
class IdentityStore(
    private val context: Context,
    /** Seals the stored accounts; on a phone, an Android Keystore key. */
    private val box: SecretBox = AesGcmBox { KeystoreKey.get() },
) {
    companion object {
        private val SEALED_KEY = stringPreferencesKey("accounts_v3")        // encrypted
        private val PLAIN_KEY = stringPreferencesKey("accounts_v2")         // an earlier development build kept it in clear
        private val OLD_KEYS = listOf(stringPreferencesKey("local_identity"), stringPreferencesKey("sigchain"))
    }

    private fun load(prefs: Preferences): Loaded {
        prefs[SEALED_KEY]?.let { return SealedBook.open(it, box) }
        prefs[PLAIN_KEY]?.let { return Loaded.Ok(AccountBook.decode(it)) }   // read until migrate() has sealed it
        return Loaded.Ok(AccountBook())
    }

    private val loaded: Flow<Loaded> = context.identityDataStore.data.map(::load)

    /** All accounts and the active one (empty while the stored data cannot be opened: see [problem]). */
    val book: Flow<AccountBook> = loaded.map { (it as? Loaded.Ok)?.book ?: AccountBook() }

    /** Why the stored accounts cannot be opened, or null. While set, nothing is written over them. */
    val problem: Flow<String?> = loaded.map { (it as? Loaded.Unreadable)?.reason }

    val accounts: Flow<List<Account>> = book.map { it.accounts }

    /** The active account's identity. */
    val identity: Flow<LocalIdentity?> = book.map { it.current?.identity }

    /** Alias for identity flow (used by UI screens). */
    val currentIdentity: Flow<LocalIdentity?> get() = identity

    /** The active account's cached sigchain as raw events (control chain, then content track). */
    val sigchain: Flow<List<JsonObject>> = book.map { it.current?.chain ?: emptyList() }

    /** Thrown instead of overwriting accounts that exist but cannot be opened. */
    class Unreadable(reason: String) : IllegalStateException("the stored accounts cannot be opened: $reason")

    /** Apply a change and write the book back sealed. If the stored data is unreadable, nothing is written. */
    private suspend fun update(change: (AccountBook) -> AccountBook) {
        context.identityDataStore.edit { prefs ->
            when (val now = load(prefs)) {
                is Loaded.Unreadable -> throw Unreadable(now.reason)
                is Loaded.Ok -> {
                    prefs[SEALED_KEY] = SealedBook.seal(change(now.book), box)
                    prefs.remove(PLAIN_KEY)
                }
            }
        }
    }

    /** Seal anything an earlier build left in clear, and delete it. Safe to call on every start. */
    suspend fun migrate() {
        context.identityDataStore.edit { prefs ->
            val plain = prefs[PLAIN_KEY]
            if (plain != null && prefs[SEALED_KEY] == null) prefs[SEALED_KEY] = SealedBook.seal(AccountBook.decode(plain), box)
            prefs.remove(PLAIN_KEY)
            OLD_KEYS.forEach { prefs.remove(it) }
        }
    }

    /** The user's decision to give up on accounts that cannot be opened: forget them so a new start is possible. */
    suspend fun discardUnreadable() {
        context.identityDataStore.edit { prefs ->
            if (load(prefs) is Loaded.Unreadable) prefs.remove(SEALED_KEY)
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

    /**
     * This phone became a device of an identity whose master key lives elsewhere (pairing by QR). The account has no master key:
     * only the device keys, which the master authorized on the chain.
     */
    suspend fun addPairedDevice(
        identityHash: String,
        name: String?,
        masterPublicKey: String,
        distributionPoints: List<String>,
        chain: List<JsonObject>,
        device: SigningKeyPair,
        deviceEncryption: EncryptionKeyPair,
    ): LocalIdentity {
        val identity = LocalIdentity(
            identityHash = identityHash,
            name = name,
            signingSecretKey = "",                    // no master key here
            signingPublicKey = masterPublicKey,
            encryptionSecretKey = null,
            encryptionPublicKey = null,
            distributionPoints = distributionPoints,
            isDevice = true,
            masterIdentityHash = identityHash,
            deviceSigningSecretKey = device.secretKeyHex,
            deviceSigningPublicKey = device.publicKeyHex,
            deviceEncryptionSecretKey = deviceEncryption.secretKey.toHex(),
            deviceEncryptionPublicKey = deviceEncryption.publicKeyHex,
        )
        update { it.with(Account(identity, chain), makeActive = true) }
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

    /** Remove every account (also when they cannot be opened). */
    suspend fun clearAll() = context.identityDataStore.edit { prefs ->
        prefs.remove(SEALED_KEY)
        prefs.remove(PLAIN_KEY)
    }.let { }

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
