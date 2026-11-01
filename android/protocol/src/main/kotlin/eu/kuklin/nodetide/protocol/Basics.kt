package eu.kuklin.nodetide.protocol

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest

/** Ed25519 verification, supplied by the platform (lazysodium on Android, java.security on a JVM). */
fun interface Ed25519Verifier {
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
}

/** Something that signs with one Ed25519 key. */
interface Signer {
    val publicKeyHex: String
    fun sign(message: ByteArray): ByteArray
}

object Hex {
    private const val DIGITS = "0123456789abcdef"

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            out.append(DIGITS[(b.toInt() shr 4) and 0xf]).append(DIGITS[b.toInt() and 0xf])
        }
        return out.toString()
    }

    fun decode(text: String): ByteArray? {
        if (text.length % 2 != 0) return null
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            val hi = DIGITS.indexOf(text[2 * i].lowercaseChar())
            val lo = DIGITS.indexOf(text[2 * i + 1].lowercaseChar())
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}

fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

fun sha256Hex(bytes: ByteArray): String = Hex.encode(sha256(bytes))

// --- small helpers over kotlinx.serialization's JSON tree ---------------------------------------------------------

internal fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

internal fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()

/** True when the key is absent or null (the Python reference leaves such keys out). */
internal fun JsonObject.absent(key: String): Boolean = this[key] == null || this[key] is JsonNull

internal fun JsonObject.list(key: String): List<JsonElement>? = (this[key] as? JsonArray)?.toList()

internal fun JsonObject.obj(key: String): JsonObject? = this[key] as? JsonObject

internal fun JsonObject.without(vararg drop: String): JsonObject = JsonObject(filterKeys { it !in drop })

internal fun JsonElement.asObject(): JsonObject? = this as? JsonObject
