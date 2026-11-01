package eu.kuklin.nodetide.protocol

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Sigchain v2 verification (see sigchain-v2.md): a port of python/src/nodetide/core/identity.py and golang/auth, held to the
 * same verdicts by protocol-vectors/chain-v2.json.
 *
 * An identity has two tracks. The CONTROL chain (genesis, devices, rotation, recovery, owners, revoke_claim, checkpoint) is
 * linked by prev and small. The CONTENT track (add_claim, set_claim_order) is bulk; control events commit to it with
 * {count, root} (a Merkle root), so a verifier can check keys and trust from the control chain alone and prove single content
 * events with a path.
 */
class ChainError(message: String, val malformed: Boolean = false) : Exception(message)

class Options(
    val verifier: Ed25519Verifier,
    /** The verified chain of another identity (an owner, a trustee), or null. */
    val resolve: ((String) -> Sigchain?)? = null,
    /** Also require the newest event's approvals and recovery signatures to use the signers' CURRENT keys. */
    val checkCurrent: Boolean = false,
)

data class Device(val pubkey: String, val label: String, val capabilities: List<String>, val addedAt: Long, val expires: Long?)

data class DeviceStatus(
    val known: Boolean = false,
    val capabilities: List<String> = emptyList(),
    val revoked: Boolean = false,
    val untrustedSince: Long? = null,
)

class Sigchain private constructor(private val verifier: Ed25519Verifier) {
    val events = mutableListOf<JsonObject>()          // control chain
    val hashes = mutableListOf<String>()
    val content = mutableListOf<JsonObject>()         // content track (all of it, none, or what was proven)
    private val contentHashes = mutableListOf<String>()
    private val sparse = sortedMapOf<Int, JsonObject>()

    var master: String = ""
        private set
    private val commitments = mutableListOf<Pair<Int, String>>()
    private val states = mutableListOf<AuthState>()
    private val status = mutableMapOf<String, DeviceStatus>()
    private var owners: List<Owner>? = null
    private val claims = mutableMapOf<String, ClaimInfo>()
    private val revokedIds = mutableSetOf<String>()

    private class DeviceState(val caps: List<String>, val expires: Long, val label: String, val addedAt: Long)

    private class AuthState(val master: String, val devices: Map<String, DeviceState>, val revoked: Set<String>) {
        fun mayManageClaims(signer: String, at: Long): Boolean {
            if (signer == master) return true
            val d = devices[signer] ?: return false
            return signer !in revoked && "manage_claims" in d.caps && !(d.expires != 0L && d.expires < at)
        }
    }

    private class Owner(val identity: String, val weight: Long)

    private class ClaimInfo(val seq: Int, val type: String)

    private class RecoveryConfig(val trustees: List<String>, val threshold: Long)

    val identityHash: String get() = hashes.first()
    val headHash: String get() = hashes.last()
    val controlLength: Int get() = events.size
    val contentLength: Int get() = content.size
    val isPartial: Boolean get() = content.size < lastCommitted()

    fun hasEvent(hash: String) = hash in hashes

    fun deviceStatus(pubkey: String): DeviceStatus = status[pubkey] ?: DeviceStatus()

    /** (type, revoked) of a claim this object knows: all of them on a full chain, the proven ones on a light chain. */
    fun claim(id: String): Pair<String, Boolean>? = claims[id]?.let { it.type to (id in revokedIds) }

    fun claimIds(): List<String> = claims.keys.sorted()

    private fun lastCommitted() = commitments.lastOrNull()?.first ?: 0

    // ---------------------------------------------------------------------------------------------------------------

    companion object {
        private val CONTENT_TYPES = setOf("add_claim", "set_claim_order")
        private val DEFAULT_CAPABILITIES = listOf("sign_messages", "sign_files", "sign_identity", "encrypt", "authenticate", "manage_claims")
        private val HEX64 = Regex("^[0-9a-f]{64}$")
        const val GOVERNED = "owners"

        /** Parse and verify a list of events (control and content, in any order). Throws [ChainError]. */
        fun parse(raw: List<JsonElement>, options: Options): Sigchain {
            if (raw.isEmpty()) throw ChainError("empty sigchain", true)
            val control = mutableListOf<JsonObject>()
            val content = mutableListOf<JsonObject>()
            raw.forEachIndexed { i, item ->
                val ev = item.asObject() ?: throw ChainError("event $i: not an object", true)
                val type = ev.string("type") ?: throw ChainError("event $i: missing type", true)
                if (type in CONTENT_TYPES) content += ev else control += ev
            }
            if (control.isEmpty()) throw ChainError("no control events", true)
            val chain = Sigchain(options.verifier)
            chain.verifyControl(control, options)
            chain.verifyContent(content)
            return chain
        }

        internal fun capabilitiesOf(ev: JsonObject): List<String> {
            if (!ev.containsKey("capabilities")) return DEFAULT_CAPABILITIES
            val list = ev.list("capabilities") ?: return emptyList()
            return list.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
        }
    }

    private fun verifyHex(pubHex: String, message: ByteArray, sigHex: String): Boolean {
        val pub = Hex.decode(pubHex) ?: return false
        val sig = Hex.decode(sigHex) ?: return false
        if (pub.size != 32 || sig.size != 64) return false
        return verifier.verify(pub, message, sig)
    }

    private fun hashOf(ev: JsonObject) = sha256Hex(Canonical.bytes(ev))

    private fun checkEnvelope(ev: JsonObject, label: String, checkSignature: Boolean) {
        val signedBy = ev.string("signed_by") ?: throw ChainError("$label: missing signed_by", true)
        val sig = ev.string("signature") ?: throw ChainError("$label: missing signature", true)
        ev.string("alg")?.let { if (it != "ed25519") throw ChainError("$label: unsupported alg", true) }
        ev.string("hash_alg")?.let { if (it != "sha256") throw ChainError("$label: unsupported hash_alg", true) }
        if (!checkSignature) return
        // owner approvals are collected after the event is signed, so they are not part of what is signed
        val msg = Canonical.bytes(ev.without("signature", "approvals"))
        if (!verifyHex(signedBy, msg, sig)) throw ChainError("$label: signature invalid")
    }

    private fun revokedBy(ev: JsonObject, type: String, known: Collection<String>): Map<String, Long?> {
        val since = ev.long("untrusted_since")
        val out = mutableMapOf<String, Long?>()
        when (type) {
            "revoke_device" -> ev.string("device_pubkey")?.let { out[it] = since }
            "rotate_master" -> when (val rd = ev["revoke_devices"]) {
                is JsonPrimitive -> if (rd.isString && rd.content == "all") known.forEach { out[it] = since }
                is JsonArray -> rd.forEach { k -> (k as? JsonPrimitive)?.takeIf { it.isString }?.content?.let { out[it] = since } }
                else -> {}
            }
        }
        return out
    }

    private fun revocationFieldsProblem(ev: JsonObject, type: String): String? {
        if (!ev.absent("untrusted_since")) {
            val v = ev.long("untrusted_since")
            if (v == null || v < 0) return "untrusted_since is a time"
            if (v > (ev.long("timestamp") ?: 0)) return "untrusted_since cannot be in the future"
        }
        if (type == "rotate_master") {
            if (ev.absent("revoke_devices")) return if (!ev.absent("untrusted_since")) "untrusted_since without devices to revoke" else null
            val bad = "revoke_devices is \"all\" or a list of device keys"
            when (val rd = ev["revoke_devices"]) {
                is JsonPrimitive -> if (!(rd.isString && rd.content == "all")) return bad
                is JsonArray -> {
                    if (rd.size > 64) return bad
                    for (k in rd) {
                        val s = (k as? JsonPrimitive)?.takeIf { it.isString }?.content
                        if (s == null || !HEX64.matches(s)) return bad
                    }
                }
                else -> return bad
            }
        }
        return null
    }

    // --- the control chain ---------------------------------------------------------------------------------------

    private fun verifyControl(control: List<JsonObject>, options: Options) {
        var master = ""
        val devices = mutableMapOf<String, DeviceState>()
        val revoked = mutableSetOf<String>()
        var recovery: RecoveryConfig? = null
        var managed = false
        var prevHash = ""

        control.forEachIndexed { i, ev ->
            val label = "event $i"
            val type = ev.string("type") ?: ""
            val governed = ev.string("signed_by") == GOVERNED
            checkEnvelope(ev, label, i == 0 || !governed)
            val hash = hashOf(ev)
            val signedBy = ev.string("signed_by") ?: ""

            fun snapshot() = AuthState(master, devices.toMap(), revoked.toSet())

            if (i == 0) {
                if (type != "genesis") throw ChainError("first event must be genesis")
                val pub = ev.string("pubkey") ?: throw ChainError("genesis: missing pubkey", true)
                if (pub != signedBy) throw ChainError("genesis must be self-signed")
                if (!ev.absent("prev")) throw ChainError("genesis must not have prev")
                if (!ev.absent("content")) throw ChainError("Genesis cannot commit to content")
                master = pub
                this.master = pub
                status[pub] = DeviceStatus(known = true, capabilities = listOf("sign", "encrypt"))
                events += ev
                hashes += hash
                if (!ev.absent("owners")) {
                    if (ev.string("identity_type") != "organization") throw ChainError("Only an organization identity has owners")
                    if (!ev.absent("governance")) {
                        val g = ev.string("governance")
                        if (g != "self" && g != "managed") throw ChainError("Genesis: governance is self or managed")
                        managed = g == "managed"
                    }
                    val list = parseOwners(ev["owners"], options, "Genesis")
                    val (approved, total) = approvalScore(ev, list, options, options.checkCurrent && control.size == 1, "Genesis")
                    if (approved != total) throw ChainError("Genesis: every founding owner must approve")
                    owners = list
                } else {
                    if ((ev.list("approvals")?.size ?: 0) > 0) throw ChainError("Genesis: approvals without owners")
                    if (!ev.absent("governance")) throw ChainError("Genesis: governance without owners")
                }
                states += snapshot()
                prevHash = hash
                return@forEachIndexed
            }

            if (ev.string("prev") != prevHash) throw ChainError("$label: prev hash mismatch")
            if (!ev.absent("seq")) throw ChainError("$label: a content event does not belong in the control chain")
            val last = i == control.size - 1
            val genesisPub = events[0].string("pubkey") ?: ""

            fun applyRevocations() {
                val known = devices.keys + genesisPub
                for ((pub, since) in revokedBy(ev, type, known)) {
                    revoked += pub
                    val old = status[pub]
                    status[pub] = (old ?: DeviceStatus()).copy(revoked = true, untrustedSince = since)
                }
            }

            fun addDevice() {
                val pub = ev.string("device_pubkey") ?: return
                val caps = capabilitiesOf(ev)
                devices[pub] = DeviceState(caps, ev.long("expires") ?: 0L, ev.string("label") ?: "", ev.long("timestamp") ?: 0L)
                status[pub] = DeviceStatus(known = true, capabilities = caps)
            }

            if (governed) {
                val current = owners ?: throw ChainError("$label: only an organization is governed by owners")
                val allowed = type == "rotate_master" || type == "set_owners" || (managed && (type == "add_device" || type == "revoke_device"))
                if (!allowed) throw ChainError("$label: $type cannot be decided by owners")
                if ((ev.string("signature") ?: "").isNotEmpty()) throw ChainError("$label: a governed event has no signature of its own")
                val (approved, total) = approvalScore(ev, current, options, options.checkCurrent && last, label)
                if (2 * approved <= total) throw ChainError("$label: owners approve $approved of $total, which is not over half")
                when (type) {
                    "add_device" -> addDevice()
                    "revoke_device" -> {
                        revocationFieldsProblem(ev, type)?.let { throw ChainError("$label: $it") }
                        applyRevocations()
                    }
                    "rotate_master" -> {
                        revocationFieldsProblem(ev, type)?.let { throw ChainError("$label: $it") }
                        applyRevocations()
                        master = ev.string("new_pubkey") ?: throw ChainError("$label: missing new_pubkey", true)
                        this.master = master
                    }
                    "set_owners" -> owners = parseOwners(ev["owners"], options, label)
                }
            } else {
                if ((ev.list("approvals")?.size ?: 0) > 0) throw ChainError("$label: approvals belong on governed events only")
                if (owners != null && (type == "set_owners" || type == "set_recovery" || type == "social_recovery" ||
                        (managed && (type == "rotate_master" || type == "add_device" || type == "revoke_device")))
                ) throw ChainError("$label: an organization's $type is decided by its owners")
                if (type == "set_owners") throw ChainError("$label: only an organization has owners")
                when (type) {
                    "add_device", "revoke_device", "set_recovery", "resolve_fork", "set_distribution" -> {
                        if (signedBy != master) throw ChainError("$label: must be signed by master key")
                        when (type) {
                            "add_device" -> addDevice()
                            "revoke_device" -> {
                                revocationFieldsProblem(ev, type)?.let { throw ChainError("$label: $it") }
                                applyRevocations()
                            }
                            "set_recovery" -> recovery = parseRecoveryConfig(ev, hashes[0], label)
                        }
                    }
                    "revoke_claim", "checkpoint" -> {
                        val mayManage = AuthState(master, devices, revoked).mayManageClaims(signedBy, ev.long("timestamp") ?: 0L)
                        if (!mayManage) throw ChainError("$label: signer may not manage claims")
                        if (type == "revoke_claim") {
                            val id = ev.string("claim_id") ?: throw ChainError("$label: missing claim_id", true)
                            if (id in revokedIds) throw ChainError("$label: claim already revoked")
                            revokedIds += id
                        }
                    }
                    "rotate_master" -> {
                        if (signedBy != master) throw ChainError("$label: rotation must be signed by old master")
                        val np = ev.string("new_pubkey") ?: throw ChainError("$label: missing new_pubkey", true)
                        revocationFieldsProblem(ev, type)?.let { throw ChainError("$label: $it") }
                        applyRevocations()
                        master = np
                        this.master = np
                    }
                    "social_recovery" -> {
                        checkRecoveryEvent(ev, hashes[0], recovery, options, options.checkCurrent && last, label)
                        master = ev.string("new_pubkey") ?: ""
                        this.master = master
                    }
                    "genesis" -> throw ChainError("$label: unexpected genesis", true)
                    else -> throw ChainError("$label: unknown event type \"$type\"", true)
                }
            }
            events += ev
            hashes += hash
            states += snapshot()
            prevHash = hash
        }
        computeCommitments()
    }

    private fun computeCommitments() {
        var prev = 0 to Merkle.EMPTY_ROOT
        events.forEachIndexed { i, ev ->
            if (!ev.absent("content")) {
                val c = ev.obj("content")
                val count = c?.long("count")
                val root = c?.string("root")
                if (c == null || c.size != 2 || count == null || root == null) throw ChainError("event $i: malformed content commitment")
                if (count < prev.first) throw ChainError("event $i: content commitment goes backwards")
                prev = count.toInt() to root
            }
            commitments += prev
        }
    }

    // --- the content track ---------------------------------------------------------------------------------------

    private fun verifyContent(unordered: List<JsonObject>) {
        val content = unordered.sortedBy { it.long("seq") ?: 0L }
        val hashes = content.map(::hashOf)
        commitments.forEachIndexed { i, (count, root) ->
            if (count <= hashes.size && Merkle.root(hashes.subList(0, count)) != root) {
                throw ChainError("event $i: content commitment does not match the content")
            }
        }
        val partial = content.size < lastCommitted()
        if (partial && content.isEmpty()) return // light: the control chain checks out; the content it commits to is not here

        val indexOf = this.hashes.withIndex().associate { it.value to it.index }
        val lastControl = events.size - 1
        val committedByRef = IntArray(events.size)
        var prevHash: String? = null
        var prevK = 0
        val seen = mutableMapOf<String, ClaimInfo>()

        content.forEachIndexed { i, ev ->
            val tag = "Content event $i"
            val type = ev.string("type")
            if (type !in CONTENT_TYPES || ev.long("seq") == null) throw ChainError("$tag: not a content event")
            checkEnvelope(ev, tag, false)
            if (ev.long("seq")!!.toInt() != i || ev.string("prev") != prevHash) throw ChainError("$tag: seq or prev does not continue the content track")
            val k = indexOf[ev.string("control_ref")] ?: throw ChainError("$tag: behind: it names a control event this chain does not have")
            if (k < prevK) throw ChainError("$tag: control_ref goes backwards")
            if (i < commitments[k].first) throw ChainError("$tag: already committed before the control event it names")
            if (k < lastControl && i >= commitments[k + 1].first) throw ChainError("$tag: not committed by the control event that follows its control_ref")
            val signedBy = ev.string("signed_by") ?: ""
            if (!states[k].mayManageClaims(signedBy, ev.long("timestamp") ?: 0L)) throw ChainError("$tag: signer may not manage claims")
            if (!verifyHex(signedBy, Canonical.bytes(ev.without("signature")), ev.string("signature") ?: "")) throw ChainError("$tag: signature invalid")
            committedByRef[k]++

            when (type) {
                "add_claim" -> {
                    val id = ev.string("claim_id") ?: throw ChainError("$tag: missing claim_id", true)
                    if (id in seen) throw ChainError("$tag: duplicate claim_id")
                    seen[id] = ClaimInfo(i, ev.string("claim_type") ?: "")
                    claims[id] = seen.getValue(id)
                }
                "set_claim_order" -> {
                    val claimType = ev.string("claim_type")
                    val order = ev.list("order")
                    if (order == null || order.isEmpty() || order.size > 32) throw ChainError("$tag: a claim order lists between 1 and 32 claims")
                    val revokedByK = (0..k).filter { events[it].string("type") == "revoke_claim" }.mapNotNull { events[it].string("claim_id") }.toSet()
                    val listed = mutableSetOf<String>()
                    for (item in order) {
                        val id = (item as? JsonPrimitive)?.takeIf { it.isString }?.content
                        if (id == null || !listed.add(id)) throw ChainError("$tag: a claim is listed twice")
                        val c = seen[id] ?: throw ChainError("$tag: orders an unknown claim")
                        if (id in revokedByK) throw ChainError("$tag: orders a revoked claim")
                        if (c.type != claimType) throw ChainError("$tag: orders a claim of another type")
                    }
                }
            }
            prevHash = hashes[i]
            prevK = k
        }

        this.content += content
        contentHashes += hashes
        if (partial) return // still being filled: what is here has been checked

        // each control event commits exactly the content signed under the control events before it
        var running = 0
        for (k in events.indices) {
            if (k > 0 && commitments[k].first != running) throw ChainError("event $k: content exists that this control event does not commit to, or it commits more than exists")
            running += committedByRef[k]
        }
        // a revoked claim must exist, and have been committed no later than the revocation
        events.forEachIndexed { j, ev ->
            if (ev.string("type") == "revoke_claim") {
                val id = ev.string("claim_id") ?: ""
                val c = seen[id] ?: throw ChainError("event $j: revokes an unknown claim")
                if (c.seq >= commitments[j].first) throw ChainError("event $j: revokes a claim its commitment does not cover")
            }
        }
    }

    /**
     * Accept one content event on a light chain, given its Merkle path to the control event that commits it. Returns why
     * not, or null. A reason starting "behind:" means the chain lacks the control event the content names.
     */
    fun attachContent(ev: JsonObject, proof: List<String>): String? {
        val type = ev.string("type")
        val seq = ev.long("seq")
        if (type !in CONTENT_TYPES || seq == null) return "not a content event"
        val k = hashes.indexOf(ev.string("control_ref") ?: "")
        if (k < 0) return "behind: the content event names a control event this chain does not have"
        if (k + 1 >= events.size) return "not committed yet: no control event after the one it names"
        val before = commitments[k]
        val after = commitments[k + 1]
        if (seq < before.first || seq >= after.first) return "the content event is not in the interval the control chain commits"
        if (!Merkle.verify(hashOf(ev), seq.toInt(), after.first, proof, after.second)) return "the Merkle proof does not match the control chain's commitment"
        if (!states[k].mayManageClaims(ev.string("signed_by") ?: "", ev.long("timestamp") ?: 0L)) return "signer may not manage claims"
        try {
            checkEnvelope(ev, "content event", true)
        } catch (e: ChainError) {
            return e.message
        }
        sparse[seq.toInt()] = ev
        if (type == "add_claim") ev.string("claim_id")?.let { claims[it] = ClaimInfo(seq.toInt(), ev.string("claim_type") ?: "") }
        return null
    }

    /** Active devices at [now]: added, not revoked, not expired. The genesis key is listed as "Primary". */
    fun activeDevices(now: Long): List<Device> {
        val devices = linkedMapOf<String, Device>()
        val revoked = mutableSetOf<String>()
        for (ev in events) {
            val type = ev.string("type")
            val ts = ev.long("timestamp") ?: 0L
            when (type) {
                "genesis" -> ev.string("pubkey")?.let { devices[it] = Device(it, "Primary", listOf("sign", "encrypt"), ts, null) }
                "add_device" -> {
                    val pub = ev.string("device_pubkey") ?: continue
                    val expires = ev.long("expires")?.takeIf { it != 0L }
                    if (expires != null && expires < now) continue
                    devices[pub] = Device(pub, ev.string("label") ?: "", capabilitiesOf(ev), ts, expires)
                }
                "revoke_device", "rotate_master" -> revoked += revokedBy(ev, type!!, devices.keys).keys
            }
        }
        return devices.values.filter { it.pubkey !in revoked && !(it.expires != null && it.expires < now) }
    }

    // --- organizations with owners, and social recovery (the keys of OTHER identities, as of a named state) --------

    internal fun masterAt(state: String): String? {
        var key: String? = null
        events.forEachIndexed { i, ev ->
            when (ev.string("type")) {
                "genesis" -> key = ev.string("pubkey")
                "rotate_master", "social_recovery" -> key = ev.string("new_pubkey")
            }
            if (hashes[i] == state) return key
        }
        return null
    }

    private fun parseOwners(raw: JsonElement?, options: Options, label: String): List<Owner> {
        val list = (raw as? JsonArray)?.toList()
        if (list == null || list.isEmpty() || list.size > 16) throw ChainError("$label: an organization has between 1 and 16 owners")
        val seen = mutableSetOf<String>()
        return list.map { item ->
            val m = item.asObject()
            if (m == null || m.size != 2) throw ChainError("$label: an owner is {identity, weight}")
            val identity = m.string("identity")?.takeIf { it.isNotEmpty() } ?: throw ChainError("$label: an owner needs an identity hash")
            val weight = m.long("weight")
            if (weight == null || weight < 1 || weight > 1_000_000) throw ChainError("$label: an owner's weight is a whole number from 1 to 1000000")
            if (!seen.add(identity)) throw ChainError("$label: an owner is listed twice")
            val resolve = options.resolve ?: throw ChainError("$label: owner identities are needed to check an organization")
            val chain = resolve(identity) ?: throw ChainError("$label: unknown owner identity ${identity.take(12)}")
            if (chain.events[0].string("identity_type") != "personal" || chain.owners != null) {
                throw ChainError("$label: an owner must be a personal identity")
            }
            Owner(identity, weight)
        }
    }

    private fun approvalScore(ev: JsonObject, owners: List<Owner>, options: Options, fresh: Boolean, label: String): Pair<Long, Long> {
        val weights = owners.associate { it.identity to it.weight }
        val total = owners.sumOf { it.weight }
        val resolve = options.resolve ?: throw ChainError("$label: owner identities are needed to check an organization")
        val done = mutableSetOf<String>()
        var approved = 0L
        for (item in ev.list("approvals") ?: emptyList()) {
            val a = item.asObject() ?: throw ChainError("$label: approval from someone who is not an owner")
            val identity = a.string("identity") ?: ""
            val weight = weights[identity] ?: throw ChainError("$label: approval from someone who is not an owner")
            if (!done.add(identity)) throw ChainError("$label: an owner approved twice")
            val chain = resolve(identity) ?: throw ChainError("$label: unknown owner identity ${identity.take(12)}")
            val state = a.string("state") ?: ""
            val key = chain.masterAt(state) ?: throw ChainError("$label: approval names a chain state the owner does not have")
            if (a.string("key") != key) throw ChainError("$label: approval key is not the owner's key at that state")
            if (fresh && key != chain.master) throw ChainError("$label: approval uses a key the owner has since replaced")
            val message = Canonical.bytes(JsonObject(mapOf(
                "purpose" to JsonPrimitive("nodetide-owner-approval-v1"),
                "owner" to JsonPrimitive(identity),
                "state" to JsonPrimitive(state),
                "event" to ev.without("signature", "approvals"),
            )))
            if (!verifyHex(key, message, a.string("signature") ?: "")) throw ChainError("$label: owner approval signature invalid")
            approved += weight
        }
        return approved to total
    }

    private fun parseRecoveryConfig(ev: JsonObject, identity: String, label: String): RecoveryConfig {
        val list = ev.list("primary_trustees") ?: throw ChainError("$label: trustees are distinct identity hashes")
        val trustees = list.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: throw ChainError("$label: trustees are distinct identity hashes") }
        if (trustees.toSet().size != trustees.size) throw ChainError("$label: trustees are distinct identity hashes")
        if (identity in trustees) throw ChainError("$label: you cannot be your own trustee")
        val threshold = ev.long("primary_threshold")
        if (threshold == null || threshold < 1 || threshold > trustees.size) throw ChainError("$label: the threshold is between 1 and the number of trustees")
        return RecoveryConfig(trustees, threshold)
    }

    private fun checkRecoveryEvent(ev: JsonObject, identity: String, config: RecoveryConfig?, options: Options, fresh: Boolean, label: String) {
        if (config == null) throw ChainError("$label: no recovery was set up")
        val newPub = ev.string("new_pubkey") ?: ""
        if (ev.string("signed_by") != newPub) throw ChainError("$label: a recovery is signed by the new key")
        val done = mutableSetOf<String>()
        for (item in ev.list("recovery_signatures") ?: emptyList()) {
            val rec = item.asObject()
            val trustee = rec?.string("trustee_identity") ?: throw ChainError("$label: a recovery signature names its trustee")
            val resolve = options.resolve ?: throw ChainError("$label: trustee identities are needed to check a recovery")
            val chain = resolve(trustee) ?: throw ChainError("$label: unknown trustee ${trustee.take(12)}")
            val state = rec.string("state") ?: ""
            val key = chain.masterAt(state) ?: throw ChainError("$label: recovery signature names a chain state the trustee does not have")
            if (rec.string("key") != key) throw ChainError("$label: recovery signature key is not the trustee's key at that state")
            if (fresh && key != chain.master) throw ChainError("$label: recovery signature uses a key the trustee has since replaced")
            val message = Canonical.bytes(JsonObject(mapOf(
                "purpose" to JsonPrimitive("nodetide-social-recovery-v1"),
                "identity" to JsonPrimitive(identity),
                "prev" to JsonPrimitive(ev.string("prev") ?: ""),
                "new_pubkey" to JsonPrimitive(newPub),
                "new_encryption_pubkey" to JsonPrimitive(ev.string("new_encryption_pubkey") ?: ""),
                "trustee" to JsonPrimitive(trustee),
                "state" to JsonPrimitive(state),
            )))
            if (!verifyHex(key, message, rec.string("signature") ?: "")) throw ChainError("$label: trustee recovery signature invalid")
            if (trustee !in config.trustees) throw ChainError("$label: recovery signature from someone who is not a trustee")
            if (!done.add(trustee)) throw ChainError("$label: a trustee signed twice")
        }
        if (done.size < maxOf(1L, config.threshold)) throw ChainError("$label: ${done.size} of ${config.threshold} trustees signed")
    }
}
