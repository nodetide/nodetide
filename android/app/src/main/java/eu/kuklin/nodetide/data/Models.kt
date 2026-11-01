package eu.kuklin.nodetide.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Local identity stored on device.
 */
@Serializable
data class LocalIdentity(
    val identityHash: String,
    val name: String?,
    val signingSecretKey: String,  // Hex-encoded Ed25519 secret key
    val signingPublicKey: String,  // Hex-encoded Ed25519 public key
    val encryptionSecretKey: String?,
    val encryptionPublicKey: String?,
    val distributionPoints: List<String> = emptyList(),
    val createdAt: Long = System.currentTimeMillis() / 1000,
    val isDevice: Boolean = false,  // True if attached as device, false if master
    val masterIdentityHash: String? = null,  // If device, the master identity hash
    // The key used every day. The master key (above) only manages the identity: it authorizes this one.
    val deviceSigningSecretKey: String? = null,
    val deviceSigningPublicKey: String? = null,
    val deviceEncryptionSecretKey: String? = null,
    val deviceEncryptionPublicKey: String? = null,
)

/**
 * A sigchain event as the screens show it. The events themselves are kept as raw JSON ([raw]): the identity hash and every
 * signature are over the exact canonical form, so they must never be squeezed through a lossy class.
 */
data class ChainEvent(
    val type: String,
    val timestamp: Long,
    val signedBy: String,
    val signature: String,
    val prev: String?,
    val seq: Int?,
    /** "control" (keys, devices, trust, commitments) or "content" (claims). */
    val track: String,
    val raw: JsonObject,
)

fun JsonObject.toChainEvent(): ChainEvent {
    fun text(key: String) = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
    fun num(key: String) = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()
    val type = text("type") ?: "?"
    return ChainEvent(
        type = type,
        timestamp = num("timestamp") ?: 0L,
        signedBy = text("signed_by") ?: "",
        signature = text("signature") ?: "",
        prev = text("prev"),
        seq = num("seq")?.toInt(),
        track = if (type == "add_claim" || type == "set_claim_order") "content" else "control",
        raw = this,
    )
}

/**
 * Identity information from server.
 */
@Serializable
data class IdentityInfo(
    @SerialName("identity_hash") val identityHash: String,
    val name: String?,
    val pubkey: String,
    @SerialName("encryption_pubkey") val encryptionPubkey: String?,
    @SerialName("identity_type") val identityType: String,
    @SerialName("distribution_points") val distributionPoints: List<String> = emptyList(),
    @SerialName("created_at") val createdAt: Long,
    @SerialName("event_count") val eventCount: Int = 0
)

/**
 * Device info from sigchain.
 */
@Serializable
data class DeviceInfo(
    val pubkey: String,
    val label: String?,
    val capabilities: List<String>,
    val addedAt: Long
)

/**
 * Public message.
 */
@Serializable
data class Message(
    @SerialName("message_hash") val messageHash: String? = null,
    val sender: String,
    val content: MessageContent,
    @SerialName("created_at") val createdAt: Long,
    val signature: String,
    @SerialName("message_type") val messageType: String = "public"
)

@Serializable
data class MessageContent(
    val type: String = "text/plain",
    val body: String
)

/**
 * Discovered relay on local network.
 */
data class DiscoveredRelay(
    val name: String,
    val host: String,
    val port: Int,
    val properties: Map<String, String> = emptyMap(),
    val scheme: String = "http",
    /** Identity hashes the node says it serves (unauthenticated: anybody on the network can claim any). */
    val ids: List<String> = emptyList()
) {
    val url: String get() = "$scheme://$host:$port"
}

/**
 * Relay status response.
 */
@Serializable
data class RelayStatus(
    val running: Boolean = false,
    val suspended: Boolean = false,
    @SerialName("poll_interval") val pollInterval: Int = 300,
    @SerialName("identities_count") val identitiesCount: Int = 0
)
