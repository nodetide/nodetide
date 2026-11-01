package eu.kuklin.nodetide.protocol

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Canonical JSON: byte-identical to Python's json.dumps(v, sort_keys=True, separators=(",", ":")) with the default
 * ensure_ascii=True. Signatures and event hashes are computed over this form.
 *
 * Only what the protocol uses is supported: null, booleans, integers, strings, arrays and objects.
 */
object Canonical {
    fun encode(value: JsonElement): String = StringBuilder().also { write(it, value) }.toString()

    fun bytes(value: JsonElement): ByteArray = encode(value).toByteArray(Charsets.UTF_8)

    private fun write(out: StringBuilder, value: JsonElement) {
        when (value) {
            is JsonNull -> out.append("null")
            is JsonPrimitive -> when {
                value.isString -> string(out, value.content)
                value.content == "true" || value.content == "false" -> out.append(value.content)
                else -> {
                    require(value.content.none { it == '.' || it == 'e' || it == 'E' }) { "non-integer number: ${value.content}" }
                    out.append(value.content)
                }
            }
            is JsonArray -> {
                out.append('[')
                value.forEachIndexed { i, e ->
                    if (i > 0) out.append(',')
                    write(out, e)
                }
                out.append(']')
            }
            is JsonObject -> {
                out.append('{')
                // Python sorts keys by Unicode code point; String.compareTo orders UTF-16 units, which differs for
                // characters outside the BMP, so compare code points.
                value.keys.sortedWith(::compareCodePoints).forEachIndexed { i, k ->
                    if (i > 0) out.append(',')
                    string(out, k)
                    out.append(':')
                    write(out, value.getValue(k))
                }
                out.append('}')
            }
        }
    }

    private fun compareCodePoints(a: String, b: String): Int {
        var i = 0
        var j = 0
        while (i < a.length && j < b.length) {
            val x = a.codePointAt(i)
            val y = b.codePointAt(j)
            if (x != y) return x.compareTo(y)
            i += Character.charCount(x)
            j += Character.charCount(y)
        }
        return (a.length - i).compareTo(b.length - j)
    }

    private const val HEX = "0123456789abcdef"

    private fun unicode(out: StringBuilder, unit: Int) {
        out.append("\\u")
        out.append(HEX[(unit shr 12) and 0xf]).append(HEX[(unit shr 8) and 0xf]).append(HEX[(unit shr 4) and 0xf]).append(HEX[unit and 0xf])
    }

    /** ensure_ascii: everything outside space..~ is escaped (non-BMP characters as surrogate pairs). */
    private fun string(out: StringBuilder, s: String) {
        out.append('"')
        for (ch in s) { // UTF-16 units: a surrogate pair is already two units, as Python's escape writes it
            when {
                ch == '"' -> out.append("\\\"")
                ch == '\\' -> out.append("\\\\")
                ch == '\n' -> out.append("\\n")
                ch == '\r' -> out.append("\\r")
                ch == '\t' -> out.append("\\t")
                ch == '\b' -> out.append("\\b")
                ch == '\u000c' -> out.append("\\f")
                ch.code in 0x20..0x7e -> out.append(ch)
                else -> unicode(out, ch.code)
            }
        }
        out.append('"')
    }
}
