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
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

private val Context.identityDataStore: DataStore<Preferences> by preferencesDataStore(name = "identity")

class IdentityStore(private val context: Context) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    companion object {
        private val IDENTITY_KEY = stringPreferencesKey("local_identity")
        private val SIGCHAIN_KEY = stringPreferencesKey("sigchain")
    }

    /**
     * Get the current local identity.
     */
    val identity: Flow<LocalIdentity?> = context.identityDataStore.data.map { prefs ->
        prefs[IDENTITY_KEY]?.let { json.decodeFromString<LocalIdentity>(it) }
    }

    /**
     * Alias for identity flow (used by UI screens).
     */
    val currentIdentity: Flow<LocalIdentity?> get() = identity

    /**
     * The cached sigchain as raw events (control chain, then content track).
     */
    val sigchain: Flow<List<JsonObject>> = context.identityDataStore.data.map { prefs ->
        prefs[SIGCHAIN_KEY]?.let { decodeEvents(it) } ?: emptyList()
    }

    private fun decodeEvents(text: String): List<JsonObject> =
        Json.parseToJsonElement(text).jsonArray.map { it.jsonObject }

    private fun encodeEvents(events: List<JsonObject>): String = JsonArray(events).toString()

    /**
     * Create a new identity: a master key (which only manages the identity), a device key for daily use that the master
     * authorizes, and the first two events of the chain (genesis and add_device).
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

        context.identityDataStore.edit { prefs ->
            prefs[IDENTITY_KEY] = json.encodeToString(identity)
            prefs[SIGCHAIN_KEY] = encodeEvents(listOf(genesis, addDevice))
        }
        return identity
    }

    /**
     * Attach as a device to an existing identity.
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

        // Save identity (sigchain will be updated when AddDevice event is submitted)
        context.identityDataStore.edit { prefs ->
            prefs[IDENTITY_KEY] = json.encodeToString(identity)
            prefs[SIGCHAIN_KEY] = encodeEvents(masterSigchain)
        }

        return identity
    }

    /**
     * Update the cached sigchain.
     */
    suspend fun updateSigchain(events: List<JsonObject>) {
        context.identityDataStore.edit { prefs ->
            prefs[SIGCHAIN_KEY] = encodeEvents(events)
        }
    }

    /**
     * Clear identity data.
     */
    suspend fun clear() {
        context.identityDataStore.edit { prefs ->
            prefs.remove(IDENTITY_KEY)
            prefs.remove(SIGCHAIN_KEY)
        }
    }

    /**
     * Get identity synchronously (for one-time reads).
     */
    suspend fun getIdentity(): LocalIdentity? = identity.first()

    /**
     * Alias for getIdentity (used by UI screens).
     */
    suspend fun getCurrentIdentity(): LocalIdentity? = getIdentity()

    /**
     * Get sigchain synchronously.
     */
    suspend fun getSigchain(): List<JsonObject> = sigchain.first()

    /**
     * Save identity directly.
     */
    suspend fun saveIdentity(identity: LocalIdentity) {
        context.identityDataStore.edit { prefs ->
            prefs[IDENTITY_KEY] = json.encodeToString(identity)
        }
    }

    /**
     * Clear identity (alias for clear).
     */
    suspend fun clearIdentity() = clear()
}
