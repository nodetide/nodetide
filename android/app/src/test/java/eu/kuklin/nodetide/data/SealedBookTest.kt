package eu.kuklin.nodetide.data

import java.security.GeneralSecurityException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

/** The sealing logic runs on the JVM; on a phone the same code gets its key from the Android Keystore. */
class SealedBookTest {
    private fun newKey(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    private val key = newKey()
    private val box = AesGcmBox { key }
    private val aad = "context".toByteArray()

    private fun book() = AccountBook().with(
        Account(
            LocalIdentity(
                identityHash = "abc123", name = "Alice", signingSecretKey = "TOPSECRETMASTERKEY", signingPublicKey = "pub",
                encryptionSecretKey = "TOPSECRETENCRYPTIONKEY", encryptionPublicKey = "encpub",
                deviceSigningSecretKey = "TOPSECRETDEVICEKEY",
            ),
            listOf(JsonObject(mapOf("type" to JsonPrimitive("genesis")))),
        )
    )

    @Test
    fun aSealedSecretOpensToTheSameBytes() {
        val plain = "hello keys".toByteArray()
        assertArrayEquals(plain, box.open(box.seal(plain, aad), aad))
    }

    @Test
    fun everySealingUsesAFreshIvSoTheSamePlaintextNeverRepeats() {
        val a = box.seal("same".toByteArray(), aad)
        val b = box.seal("same".toByteArray(), aad)
        assertNotEquals(Base64.getEncoder().encodeToString(a), Base64.getEncoder().encodeToString(b))
        assertEquals(1, a[0].toInt())                      // format version
        assertEquals(1 + 12 + 4 + 16, a.size)              // version + IV + plaintext + tag
    }

    @Test
    fun alteredDataIsRefused() {
        val sealed = box.seal("secret".toByteArray(), aad)
        for (index in listOf(0, 1, 12, 13, sealed.size - 1)) {
            val tampered = sealed.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
            try {
                box.open(tampered, aad)
                fail("tampering at byte $index went unnoticed")
            } catch (expected: GeneralSecurityException) {
            }
        }
    }

    @Test
    fun theWrongKeyOrTheWrongContextCannotOpenIt() {
        val sealed = box.seal("secret".toByteArray(), aad)
        try {
            AesGcmBox { newKey() }.open(sealed, aad)
            fail("another key opened it")
        } catch (expected: GeneralSecurityException) {
        }
        try {
            box.open(sealed, "other".toByteArray())
            fail("another context opened it")
        } catch (expected: GeneralSecurityException) {
        }
    }

    @Test
    fun theBookRoundTripsAndNeverAppearsInClear() {
        val stored = SealedBook.seal(book(), box)
        for (secret in listOf("TOPSECRETMASTERKEY", "TOPSECRETENCRYPTIONKEY", "TOPSECRETDEVICEKEY", "Alice", "abc123", "genesis")) {
            assertFalse("$secret is visible in what is stored", stored.contains(secret))
            assertFalse("$secret is visible once decoded", String(Base64.getDecoder().decode(stored), Charsets.ISO_8859_1).contains(secret))
        }
        val opened = SealedBook.open(stored, box) as Loaded.Ok
        assertEquals(book(), opened.book)
        assertEquals("TOPSECRETMASTERKEY", opened.book.current!!.identity.signingSecretKey)
    }

    @Test
    fun nothingStoredIsAnEmptyBookNotAProblem() {
        assertEquals(Loaded.Ok(AccountBook()), SealedBook.open(null, box))
        assertEquals(Loaded.Ok(AccountBook()), SealedBook.open("", box))
    }

    @Test
    fun dataThatCannotBeOpenedIsAProblemNeverAnEmptyBook() {
        val stored = SealedBook.seal(book(), box)
        // the key is gone (a restored phone): the data must not be mistaken for "no accounts", or the next save would erase it
        assertTrue(SealedBook.open(stored, AesGcmBox { newKey() }) is Loaded.Unreadable)
        assertTrue(SealedBook.open("not base64 !!!", box) is Loaded.Unreadable)
        assertTrue(SealedBook.open(Base64.getEncoder().encodeToString(ByteArray(3)), box) is Loaded.Unreadable)
        // decrypts fine but is not our JSON
        val foreign = Base64.getEncoder().encodeToString(box.seal("not json".toByteArray(), SealedBook.AAD))
        assertTrue(SealedBook.open(foreign, box) is Loaded.Unreadable)
        // a blob sealed for another purpose does not open as accounts
        val other = Base64.getEncoder().encodeToString(box.seal(book().encode().toByteArray(), "something else".toByteArray()))
        assertTrue(SealedBook.open(other, box) is Loaded.Unreadable)
    }
}
