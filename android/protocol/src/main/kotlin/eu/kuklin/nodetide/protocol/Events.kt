package eu.kuklin.nodetide.protocol

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Builders for the events an app creates itself. They produce exactly the field set the Python reference's
 * `to_dict()` produces (fields that are None there are absent, others are present even when null), because the identity
 * hash and every signature are over that exact form. Timestamps are passed in so tests can pin them.
 */
object Events {
    /** What a control event signed now must carry, or null while there is no content (see sigchain-v2.md). */
    fun commitment(contentHashes: List<String>): JsonObject? =
        if (contentHashes.isEmpty()) null
        else JsonObject(mapOf("count" to JsonPrimitive(contentHashes.size), "root" to JsonPrimitive(Merkle.root(contentHashes))))

    private fun signed(body: Map<String, JsonElement>, signer: Signer): JsonObject {
        val signature = Hex.encode(signer.sign(Canonical.bytes(JsonObject(body))))
        return JsonObject(body + ("signature" to JsonPrimitive(signature)))
    }

    private fun base(type: String, timestamp: Long, prev: String?, signer: Signer): MutableMap<String, JsonElement> = mutableMapOf(
        "version" to JsonPrimitive(1),
        "type" to JsonPrimitive(type),
        "alg" to JsonPrimitive("ed25519"),
        "hash_alg" to JsonPrimitive("sha256"),
        "timestamp" to JsonPrimitive(timestamp),
        "prev" to (prev?.let { JsonPrimitive(it) } ?: JsonNull),
        "signed_by" to JsonPrimitive(signer.publicKeyHex),
    )

    private fun strings(list: List<String>) = JsonArray(list.map { JsonPrimitive(it) })

    /** A personal identity's first event, self-signed by the master key. The identity is the hash of this event. */
    fun genesis(
        master: Signer, encryptionPubkey: String, timestamp: Long, name: String? = null,
        distributionPoints: List<String>? = null, identityType: String = "personal",
    ): JsonObject {
        val body = base("genesis", timestamp, null, master)
        body["pubkey"] = JsonPrimitive(master.publicKeyHex)
        body["encryption_pubkey"] = JsonPrimitive(encryptionPubkey)
        body["identity_type"] = JsonPrimitive(identityType)
        body["name"] = name?.let { JsonPrimitive(it) } ?: JsonNull
        body["ephemeral"] = JsonPrimitive(false)
        body["ownership_proof"] = JsonNull
        body["distribution_points"] = distributionPoints?.let(::strings) ?: JsonNull
        return signed(body, master)
    }

    fun identityHash(genesis: JsonObject): String = sha256Hex(Canonical.bytes(genesis))

    fun eventHash(event: JsonObject): String = sha256Hex(Canonical.bytes(event))

    /** Authorize a device key. [commitment] is the current content commitment (null while there is no content). */
    fun addDevice(
        master: Signer, prev: String, timestamp: Long, devicePubkey: String, deviceEncryptionPubkey: String, label: String,
        capabilities: List<String> = DEVICE_CAPABILITIES, expires: Long? = null, commitment: JsonObject? = null,
    ): JsonObject {
        val body = base("add_device", timestamp, prev, master)
        body["device_pubkey"] = JsonPrimitive(devicePubkey)
        body["device_encryption_pubkey"] = JsonPrimitive(deviceEncryptionPubkey)
        body["label"] = JsonPrimitive(label)
        body["capabilities"] = strings(capabilities)
        body["expires"] = expires?.let { JsonPrimitive(it) } ?: JsonNull
        commitment?.let { body["content"] = it }
        return signed(body, master)
    }

    fun revokeDevice(
        master: Signer, prev: String, timestamp: Long, devicePubkey: String, reason: String? = null,
        untrustedSince: Long? = null, commitment: JsonObject? = null,
    ): JsonObject {
        val body = base("revoke_device", timestamp, prev, master)
        body["device_pubkey"] = JsonPrimitive(devicePubkey)
        body["reason"] = reason?.let { JsonPrimitive(it) } ?: JsonNull
        untrustedSince?.let { body["untrusted_since"] = JsonPrimitive(it) }
        commitment?.let { body["content"] = it }
        return signed(body, master)
    }

    /** A control event whose only job is to commit to the content so far, so a light verifier can rely on it. */
    fun checkpoint(signer: Signer, prev: String, timestamp: Long, commitment: JsonObject): JsonObject {
        val body = base("checkpoint", timestamp, prev, signer)
        body["content"] = commitment
        return signed(body, signer)
    }

    /** Withdraw a claim. A control event: whether a claim still stands is a trust fact every verifier must see. */
    fun revokeClaim(
        signer: Signer, prev: String, timestamp: Long, claimId: String, reason: String? = null, commitment: JsonObject? = null,
    ): JsonObject {
        val body = base("revoke_claim", timestamp, prev, signer)
        body["claim_id"] = JsonPrimitive(claimId)
        body["reason"] = reason?.let { JsonPrimitive(it) } ?: JsonNull
        commitment?.let { body["content"] = it }
        return signed(body, signer)
    }

    /**
     * A CONTENT event. [prevContent] is the previous content event's hash (null for the first), [seq] its position and
     * [controlRef] the latest control event (the chain head) it is signed under.
     */
    private fun contentEvent(type: String, signer: Signer, prevContent: String?, seq: Int, controlRef: String, timestamp: Long) =
        base(type, timestamp, prevContent, signer).also {
            it["seq"] = JsonPrimitive(seq)
            it["control_ref"] = JsonPrimitive(controlRef)
        }

    fun addClaim(
        signer: Signer, prevContent: String?, seq: Int, controlRef: String, timestamp: Long,
        claimId: String, claimType: String, commitment: String, expires: Long? = null,
    ): JsonObject {
        val body = contentEvent("add_claim", signer, prevContent, seq, controlRef, timestamp)
        body["claim_id"] = JsonPrimitive(claimId)
        body["claim_type"] = JsonPrimitive(claimType)
        body["commitment"] = JsonPrimitive(commitment)
        body["expires"] = expires?.let { JsonPrimitive(it) } ?: JsonNull
        return signed(body, signer)
    }

    fun setClaimOrder(
        signer: Signer, prevContent: String?, seq: Int, controlRef: String, timestamp: Long, claimType: String, order: List<String>,
    ): JsonObject {
        val body = contentEvent("set_claim_order", signer, prevContent, seq, controlRef, timestamp)
        body["claim_type"] = JsonPrimitive(claimType)
        body["order"] = strings(order)
        return signed(body, signer)
    }

    /** What a device may do. Matches DeviceCapability in the Python reference. */
    val DEVICE_CAPABILITIES = listOf("sign_messages", "encrypt", "authenticate", "manage_claims")
}
