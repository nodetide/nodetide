package eu.kuklin.nodetide.data

import java.util.Base64

/** What reading the stored accounts gave. */
sealed interface Loaded {
    data class Ok(val book: AccountBook) : Loaded

    /**
     * There is stored data but it cannot be opened (the Keystore key is gone, or the data was altered). It must NOT be treated
     * as "no accounts": the next save would overwrite it for good. Callers refuse to write until the user decides.
     */
    data class Unreadable(val reason: String) : Loaded
}

/** The account book as it is kept on disk: JSON, sealed with a [SecretBox], as one base64 string. */
object SealedBook {
    /** Authenticated context: a blob sealed for something else will not open here. */
    val AAD: ByteArray = "nodetide.accounts.v3".toByteArray()

    fun seal(book: AccountBook, box: SecretBox): String =
        Base64.getEncoder().encodeToString(box.seal(book.encode().toByteArray(Charsets.UTF_8), AAD))

    fun open(stored: String?, box: SecretBox): Loaded {
        if (stored.isNullOrBlank()) return Loaded.Ok(AccountBook())
        return try {
            val plain = box.open(Base64.getDecoder().decode(stored), AAD)
            val text = String(plain, Charsets.UTF_8)
            // a successful decryption of something that is not our JSON is also "unreadable", never "empty"
            val book = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }.decodeFromString(AccountBook.serializer(), text)
            Loaded.Ok(book)
        } catch (e: Exception) {
            Loaded.Unreadable(e.message ?: e.javaClass.simpleName)
        }
    }
}
