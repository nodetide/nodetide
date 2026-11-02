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
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
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
        // Which account is active, kept next to the sealed book (a hash is public): switching accounts must not re-encrypt everything.
        private val ACTIVE_KEY = stringPreferencesKey("active_account")
        private const val TAG = "IdentityStore"
        private val OLD_KEYS = listOf(stringPreferencesKey("local_identity"), stringPreferencesKey("sigchain"))
    }

    // Opening the book is an AES-GCM decryption with a hardware-backed key (StrongBox on many phones: one operation at a time and
    // slow). It must happen once per change, off the main thread, and not once per screen: so there is ONE shared flow of the
    // opened book, and the result is also remembered (never a failure: that may be temporary, say a locked phone).
    @Volatile private var opened: Pair<String, Loaded.Ok>? = null

    private fun load(prefs: Preferences): Loaded {
        val result: Loaded = prefs[SEALED_KEY]?.let { sealed ->
            opened?.takeIf { it.first == sealed }?.second ?: run {
                val started = System.nanoTime()
                val r = SealedBook.open(sealed, box)
                Log.d(TAG, "opened the accounts in ${(System.nanoTime() - started) / 1_000_000} ms (${sealed.length} characters)")
                if (r is Loaded.Ok) opened = sealed to r
                r
            }
        } ?: prefs[PLAIN_KEY]?.let { Loaded.Ok(AccountBook.decode(it)) }   // read until migrate() has sealed it
          ?: Loaded.Ok(AccountBook())
        // the active account is its own small setting: it wins over the one recorded inside the sealed book
        val active = prefs[ACTIVE_KEY]
        if (result is Loaded.Ok && active != null && active in result.book && result.book.active != active) {
            return Loaded.Ok(result.book.copy(active = active))
        }
        return result
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private val retry = MutableStateFlow(0)

    /** Null until the stored data has been opened for the first time. */
    private val loaded: StateFlow<Loaded?> = combine(context.identityDataStore.data, retry) { prefs, _ -> load(prefs) as Loaded? }
        .flowOn(Dispatchers.Default)
        .stateIn(scope, SharingStarted.Eagerly, null)

    /**
     * Try again if the accounts could not be opened: the Keystore refuses while the phone is locked, which is not the same as the
     * key being gone. Called when the app comes to the front; does nothing while they are open.
     */
    fun reopen() {
        if (loaded.value is Loaded.Unreadable) retry.update { it + 1 }
    }

    /** All accounts and the active one (empty while the stored data cannot be opened: see [problem]). Emits once the data is open. */
    val book: Flow<AccountBook> = loaded.filterNotNull().map { (it as? Loaded.Ok)?.book ?: AccountBook() }

    /** Why the stored accounts cannot be opened, or null. While set, nothing is written over them. */
    val problem: Flow<String?> = loaded.filterNotNull().map { (it as? Loaded.Unreadable)?.reason }

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
                    val changed = change(now.book)
                    val started = System.nanoTime()
                    prefs[SEALED_KEY] = SealedBook.seal(changed, box)
                    Log.d(TAG, "sealed the accounts in ${(System.nanoTime() - started) / 1_000_000} ms")
                    prefs.remove(PLAIN_KEY)
                    changed.current?.hash?.let { prefs[ACTIVE_KEY] = it } ?: prefs.remove(ACTIVE_KEY)
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

    /** Make another account the active one. Only the small "active" setting is written: no encryption, so it is instant. */
    suspend fun setActive(hash: String) {
        context.identityDataStore.edit { prefs ->
            val now = load(prefs)
            if (now is Loaded.Ok && hash in now.book) prefs[ACTIVE_KEY] = hash
        }
    }

    /** Remove one account from this phone (its keys go with it). */
    suspend fun removeAccount(hash: String) = update { it.without(hash) }

    /** Remove the active account. */
    suspend fun clear() = update { book -> book.current?.let { book.without(it.hash) } ?: book }

    /** Remove every account (also when they cannot be opened). */
    suspend fun clearAll() = context.identityDataStore.edit { prefs ->
        prefs.remove(SEALED_KEY)
        prefs.remove(PLAIN_KEY)
        prefs.remove(ACTIVE_KEY)
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
