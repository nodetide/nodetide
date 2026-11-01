package eu.kuklin.nodetide.protocol

import java.net.URI

/** A node found on the local network by its mDNS announcement (`_nodetide._tcp`, see lan-discovery.md). */
data class LanNode(
    val name: String,
    val host: String,
    val port: Int,
    val scheme: String,
    /** Identity hashes the operator chose to advertise: how a client finds *its* node. Unauthenticated. */
    val ids: List<String>,
    val properties: Map<String, String>,
) {
    val baseUrl: String get() = "$scheme://$host:$port"
}

/**
 * What the app is willing to do with an address that came from the local network. Multicast is unauthenticated, so an
 * announcement must not aim the app at arbitrary hosts, and cleartext http must never leave the LAN.
 */
object Lan {
    const val MAX_IDS = 3
    private val HASH = Regex("^[0-9a-f]{64}$")

    /** The four octets of a plain dotted IPv4 address (no leading zeros, which some parsers read as octal), else null. */
    private fun ipv4(host: String): IntArray? {
        val parts = host.split('.')
        if (parts.size != 4) return null
        val out = IntArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' } || (p.length > 1 && p[0] == '0')) return null
            out[i] = p.toInt()
            if (out[i] > 255) return null
        }
        return out
    }

    /** A private, loopback or link-local IPv4 address (not the cloud metadata one), or a `.local` / `localhost` name. */
    fun isLanHost(host: String): Boolean {
        val h = host.lowercase()
        if (h == "localhost" || (h.endsWith(".local") && h.length > ".local".length)) return true
        val a = ipv4(h) ?: return false
        return when {
            a[0] == 10 -> true
            a[0] == 127 -> true
            a[0] == 172 && a[1] in 16..31 -> true
            a[0] == 192 && a[1] == 168 -> true
            a[0] == 169 && a[1] == 254 -> !(a[2] == 169 && a[3] == 254)
            else -> false
        }
    }

    /** https to anywhere, http only to the local network. */
    fun cleartextAllowed(url: String): Boolean {
        val uri = try { URI(url.trim()) } catch (e: Exception) { return false }
        val host = uri.host ?: return false
        if (uri.userInfo != null) return false
        return when (uri.scheme?.lowercase()) {
            "https" -> true
            "http" -> isLanHost(host)
            else -> false
        }
    }

    fun parseIds(raw: String?): List<String> =
        (raw ?: "").split(',').map { it.trim() }.filter { HASH.matches(it) }.distinct().take(MAX_IDS)

    /**
     * A node from a resolved announcement, or null if it is not one we may use: wrong version, bad port, or a host that is
     * not a plain IPv4 address on a local range.
     */
    fun fromAnnouncement(name: String, host: String, port: Int, attributes: Map<String, String>): LanNode? {
        if (attributes["version"] != "1" || port !in 1..65535) return null
        if (ipv4(host) == null || !isLanHost(host)) return null
        val scheme = if (attributes["scheme"] == "https") "https" else "http"
        return LanNode(name, host, port, scheme, parseIds(attributes["ids"]), attributes)
    }

    /** The discovered nodes that advertise this identity. Several matches mean somebody else claims it too: the user chooses. */
    fun matching(nodes: List<LanNode>, identityHash: String): List<LanNode> =
        nodes.filter { identityHash in it.ids }
}
