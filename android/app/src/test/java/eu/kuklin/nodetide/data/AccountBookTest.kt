package eu.kuklin.nodetide.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AccountBookTest {
    private fun identity(hash: String, name: String? = hash, secret: String = "secret-$hash") = LocalIdentity(
        identityHash = hash, name = name, signingSecretKey = secret, signingPublicKey = "pub-$hash",
        encryptionSecretKey = null, encryptionPublicKey = null,
    )

    private fun account(hash: String, vararg chain: String) =
        Account(identity(hash), chain.map { JsonObject(mapOf("type" to JsonPrimitive(it))) })

    @Test
    fun anEmptyBookHasNoCurrentAccount() {
        assertNull(AccountBook().current)
        assertNull(AccountBook.decode(null).current)
        assertNull(AccountBook.decode("not json at all").current)       // damaged storage starts clean, never crashes
    }

    @Test
    fun addingAnAccountMakesItActiveAndKeepsTheOthers() {
        val book = AccountBook().with(account("a")).with(account("b"))
        assertEquals(listOf("a", "b"), book.accounts.map { it.hash })
        assertEquals("b", book.current?.hash)
        assertEquals("a", book.with(account("c"), makeActive = false).activate("a").current?.hash)
    }

    @Test
    fun oneAccountPerIdentity() {
        val book = AccountBook().with(account("a", "genesis", "add_device")).with(account("b"))
        val again = book.with(Account(identity("a", name = "renamed")), makeActive = true)   // same identity, no chain given
        assertEquals(2, again.accounts.size)
        assertEquals("renamed", again.accounts.first { it.hash == "a" }.identity.name)
        assertEquals(2, again.accounts.first { it.hash == "a" }.chain.size)                  // the chain it had is kept
        assertEquals("a", again.current?.hash)
    }

    @Test
    fun anUnknownAccountCannotBeActivated() {
        val book = AccountBook().with(account("a"))
        assertEquals("a", book.activate("nobody").current?.hash)
    }

    @Test
    fun removingTheActiveAccountMakesAnotherActive() {
        val book = AccountBook().with(account("a")).with(account("b")).with(account("c")).activate("b")
        val without = book.without("b")
        assertEquals(listOf("a", "c"), without.accounts.map { it.hash })
        assertEquals("c", without.current?.hash)                                               // the next one takes over
        assertEquals("a", AccountBook().with(account("a")).with(account("b")).without("b").current?.hash)
        assertEquals("c", book.without("a").activate("c").current?.hash)
        assertEquals("b", book.without("a").current?.hash)                                     // removing another keeps the active one
        assertNull(book.without("a").without("b").without("c").current)
        assertEquals(book, book.without("never-there"))
    }

    @Test
    fun theChainOfOneAccountIsUpdatedAlone() {
        val book = AccountBook().with(account("a", "genesis")).with(account("b", "genesis"))
        val updated = book.withChain("a", listOf(JsonObject(mapOf("type" to JsonPrimitive("x"))), JsonObject(mapOf("type" to JsonPrimitive("y")))))
        assertEquals(2, updated.accounts.first { it.hash == "a" }.chain.size)
        assertEquals(1, updated.accounts.first { it.hash == "b" }.chain.size)
    }

    @Test
    fun theBookSurvivesStorageWithItsKeysAndChains() {
        val book = AccountBook().with(account("a", "genesis", "add_device")).with(Account(identity("w", secret = "")))
        val back = AccountBook.decode(book.encode())
        assertEquals(book, back)
        assertEquals("secret-a", back.accounts.first().identity.signingSecretKey)
        assertFalse(back.accounts.first().watchOnly)
        assertTrue(back.accounts.last().watchOnly)                                             // no secret key: followed, not held
        assertEquals("w", back.current?.hash)
    }

    @Test
    fun aPairedDeviceHoldsKeysSoItIsNotWatchOnly() {
        // no master key here, but a device key the master authorized: the account acts, it does not just follow
        val device = Account(identity("d", secret = "").copy(isDevice = true, deviceSigningSecretKey = "device-secret", deviceSigningPublicKey = "device-pub"))
        assertFalse(device.watchOnly)
        assertTrue(device.deviceOnly)
        val master = account("m", "genesis")
        assertFalse(master.watchOnly)
        assertFalse(master.deviceOnly)
        val watched = Account(identity("w", secret = ""))
        assertTrue(watched.watchOnly)
        assertFalse(watched.deviceOnly)
    }

    @Test
    fun unknownFieldsFromALaterVersionAreIgnored() {
        val text = Json.encodeToString(AccountBook.serializer(), AccountBook().with(account("a"))).replace("\"accounts\"", "\"future\":1,\"accounts\"")
        assertEquals("a", AccountBook.decode(text).current?.hash)
    }
}
