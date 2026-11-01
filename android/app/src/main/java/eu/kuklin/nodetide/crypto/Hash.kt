package eu.kuklin.nodetide.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid

/**
 * Cryptographic hashing utilities using BLAKE2b (compatible with nodetide).
 */
object Hash {
    private val sodium = SodiumAndroid()
    private val lazySodium = LazySodiumAndroid(sodium)

    /**
     * Compute BLAKE2b-256 hash.
     */
    fun blake2b256(data: ByteArray): ByteArray {
        val hash = ByteArray(32)
        lazySodium.cryptoGenericHash(hash, 32, data, data.size.toLong(), null, 0)
        return hash
    }

    /**
     * Alias for blake2b256 for convenience.
     */
    fun blake2b(data: ByteArray): ByteArray = blake2b256(data)

    /**
     * Compute BLAKE2b-256 hash and return as hex string.
     */
    fun blake2b256Hex(data: ByteArray): String = blake2b256(data).toHex()

    fun blake2b256Hex(data: String): String = blake2b256Hex(data.toByteArray(Charsets.UTF_8))

    // (The identity hash is sha256 of the whole SIGNED genesis event in canonical JSON: see protocol Events.identityHash.)
}
