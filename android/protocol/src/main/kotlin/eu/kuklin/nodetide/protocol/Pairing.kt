package eu.kuklin.nodetide.protocol

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject

/** What a pairing QR code says: where (the node), which identity, and the secret code that names the rendezvous slot. */
data class Invite(val code: String, val node: String, val identity: String)

/**
 * Adding a device by QR (the web wallet, which holds the master key, shows it; the phone scans it). The same node
 * rendezvous the hosted wallet uses: a slot named by the hash of the code, in which the new device leaves its PUBLIC keys.
 * See web/js/app.js (Wallet.pairing*) and python/src/nodetide/api/pairing.py.
 */
object Pairing {
    const val ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"      // no 0 O 1 I L
    const val CODE_LENGTH = 10
    private val HASH = Regex("^[0-9a-f]{64}$")

    /** The code as typed or shown ("abcde-23456", spaces): upper-cased, letters and digits only; null unless it is a code. */
    fun normalizeCode(text: String): String? {
        val code = text.uppercase().filter { it.isLetterOrDigit() }
        return code.takeIf { it.length == CODE_LENGTH && it.all { c -> c in ALPHABET } }
    }

    fun slotName(code: String): String = sha256Hex("nodetide-pairing:$code".toByteArray(Charsets.UTF_8))

    /** What both devices show so the owner can see they mean the same key: 12 hex digits of the key's hash, in groups of four. */
    fun fingerprint(pubkeyHex: String): String =
        sha256Hex(Hex.decode(pubkeyHex) ?: throw IllegalArgumentException("not a hex key")).take(12).chunked(4).joinToString("-")

    fun buildInvite(code: String, node: String, identity: String): String {
        fun enc(v: String) = URLEncoder.encode(v, "UTF-8")
        return "nodetide://pair?c=${enc(code)}&n=${enc(node)}&i=${enc(identity)}"
    }

    /**
     * An invite, or null for anything else or anything doubtful: wrong scheme, a code that is not a code, an identity that is not a
     * hash, or a node address that is not https (or plain http on the local network, never anywhere else).
     */
    fun parseInvite(text: String): Invite? {
        val uri = try { URI(text.trim()) } catch (e: Exception) { return null }
        if (uri.scheme?.lowercase() != "nodetide" || uri.host?.lowercase() != "pair" || uri.userInfo != null) return null
        val query = (uri.rawQuery ?: return null).split('&').mapNotNull {
            val i = it.indexOf('=')
            if (i <= 0) null else URLDecoder.decode(it.substring(0, i), "UTF-8") to URLDecoder.decode(it.substring(i + 1), "UTF-8")
        }.toMap()
        val code = normalizeCode(query["c"] ?: return null) ?: return null
        val identity = query["i"]?.takeIf { HASH.matches(it) } ?: return null
        val node = (query["n"] ?: return null).trim().trimEnd('/')
        if (!Lan.cleartextAllowed(node) || URI(node).rawPath.orEmpty().isNotEmpty() || URI(node).rawQuery != null) return null
        return Invite(code, node, identity)
    }
}

/** A shared identity (watch only): the web client's "Share Identity" QR (JSON), or the older `nodetide:identity:<hash>:<pubkey>`. */
data class SharedIdentity(val identity: String, val publicKey: String?, val distributionPoints: List<String>)

object Share {
    private val HASH = Regex("^[0-9a-f]{64}$")

    fun build(identity: String, publicKey: String?, distributionPoints: List<String>): String =
        JsonObject(buildMap {
            put("v", JsonPrimitive(1))
            put("id", JsonPrimitive(identity))
            if (distributionPoints.isNotEmpty()) put("dp", JsonArray(distributionPoints.map { JsonPrimitive(it) }))
            if (publicKey != null) put("pk", JsonPrimitive(publicKey))
        }).toString()

    fun parse(text: String): SharedIdentity? {
        val t = text.trim()
        if (t.startsWith("{")) {
            val obj = try { Json.parseToJsonElement(t).jsonObject } catch (e: Exception) { return null }
            if ((obj["v"] as? JsonPrimitive)?.intOrNull != 1) return null
            val id = (obj["id"] as? JsonPrimitive)?.contentOrNull?.takeIf { HASH.matches(it) } ?: return null
            val pk = (obj["pk"] as? JsonPrimitive)?.contentOrNull?.takeIf { HASH.matches(it) }
            val points = (obj["dp"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
                ?.filter { it.length <= 300 }?.take(16).orEmpty()
            return SharedIdentity(id, pk, points)
        }
        val parts = t.split(":")
        if (parts.size == 4 && parts[0] == "nodetide" && parts[1] == "identity" && HASH.matches(parts[2]) && HASH.matches(parts[3])) {
            return SharedIdentity(parts[2], parts[3], emptyList())
        }
        return null
    }
}
