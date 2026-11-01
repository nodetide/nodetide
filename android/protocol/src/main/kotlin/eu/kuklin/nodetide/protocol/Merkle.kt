package eu.kuklin.nodetide.protocol

/**
 * The Merkle tree control events use to commit to the content track (RFC 6962 style; see sigchain-v2.md): a leaf is
 * sha256(0x00 || event hash), an inner node sha256(0x01 || left || right), a tree over n leaves splits at the largest
 * power of two below n.
 */
object Merkle {
    val EMPTY_ROOT: String = sha256Hex(ByteArray(0))

    private fun leaf(h: ByteArray) = sha256(byteArrayOf(0) + h)

    private fun node(l: ByteArray, r: ByteArray) = sha256(byteArrayOf(1) + l + r)

    private fun split(n: Int): Int {
        var k = 1
        while (k * 2 < n) k *= 2
        return k
    }

    private fun tree(leaves: List<ByteArray>): ByteArray {
        if (leaves.size == 1) return leaves[0]
        val k = split(leaves.size)
        return node(tree(leaves.subList(0, k)), tree(leaves.subList(k, leaves.size)))
    }

    /** Root (hex) over event hashes (hex). */
    fun root(hashes: List<String>): String {
        if (hashes.isEmpty()) return EMPTY_ROOT
        return Hex.encode(tree(hashes.map { leaf(requireNotNull(Hex.decode(it)) { "not a hex hash" }) }))
    }

    private fun path(leaves: List<ByteArray>, index: Int): List<ByteArray> {
        if (leaves.size == 1) return emptyList()
        val k = split(leaves.size)
        return if (index < k) path(leaves.subList(0, k), index) + tree(leaves.subList(k, leaves.size))
        else path(leaves.subList(k, leaves.size), index - k) + tree(leaves.subList(0, k))
    }

    /** Audit path (hex siblings, leaf upwards) for the leaf at [index]. */
    fun proof(hashes: List<String>, index: Int): List<String> {
        require(index in hashes.indices) { "no such leaf" }
        val leaves = hashes.map { leaf(requireNotNull(Hex.decode(it))) }
        return path(leaves, index).map(Hex::encode)
    }

    /** Is [leafHash] at [index] of a tree of [count] leaves with this [root]? (The size is bound by the signed commitment.) */
    fun verify(leafHash: String, index: Int, count: Int, path: List<String>, root: String): Boolean {
        if (index !in 0 until count) return false
        val leafBytes = Hex.decode(leafHash) ?: return false
        val siblings = path.map { Hex.decode(it) ?: return false }

        fun climb(index: Int, count: Int, siblings: List<ByteArray>): ByteArray? {
            if (count == 1) return if (siblings.isEmpty()) leaf(leafBytes) else null
            if (siblings.isEmpty()) return null
            val k = split(count)
            val rest = siblings.subList(0, siblings.size - 1)
            val top = siblings.last()
            return if (index < k) climb(index, k, rest)?.let { node(it, top) }
            else climb(index - k, count - k, rest)?.let { node(top, it) }
        }
        return climb(index, count, siblings)?.let { Hex.encode(it) == root } ?: false
    }
}
