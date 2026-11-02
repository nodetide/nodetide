package eu.kuklin.nodetide.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class PairingTest {
    private val id = "ab".repeat(32)
    private val node = "https://nt-node.test.nodetide-project.net"

    @Test
    fun theSlotAndTheFingerprintAreWhatPythonAndTheWebComputeForTheSameInput() {
        // computed with python/src: hashlib.sha256(b"nodetide-pairing:" + code), and the wallet's fingerprint()
        assertEquals("0486b30737cff250cb9289172986f09bcdcbeae260c5d25d52fa13c625e412b4", Pairing.slotName("ABCDE23456"))
        assertEquals("9a2d-b2e2-3f15", Pairing.fingerprint("ab".repeat(32)))
    }

    @Test
    fun codesAreForgivingAboutCaseAndSeparatorsButNothingElse() {
        assertEquals("ABCDE23456", Pairing.normalizeCode("abcde-23456"))
        assertEquals("ABCDE23456", Pairing.normalizeCode(" ABCDE 23456 "))
        for (bad in listOf("", "ABCDE2345", "ABCDE234567", "ABCDE0O1IL", "abcde-2345!", "ÄBCDE23456")) assertNull(Pairing.normalizeCode(bad), bad)
    }

    @Test
    fun anInviteRoundTripsAndKeepsTheNodeAddressIntact() {
        val text = Pairing.buildInvite("ABCDE23456", node, id)
        assertEquals(Invite("ABCDE23456", node, id), Pairing.parseInvite(text))
        // what the web client builds with URLSearchParams
        assertEquals(Invite("ABCDE23456", "http://192.168.1.5:4557", id),
            Pairing.parseInvite("nodetide://pair?c=ABCDE23456&n=http%3A%2F%2F192.168.1.5%3A4557&i=$id"))
        assertEquals(Invite("ABCDE23456", node, id), Pairing.parseInvite("  $text \n"))
        assertEquals(Invite("ABCDE23456", node, id), Pairing.parseInvite(Pairing.buildInvite("abcde-23456", "$node/", id)))
    }

    @Test
    fun anythingDoubtfulIsNotAnInvite() {
        val ok = "c=ABCDE23456&n=${java.net.URLEncoder.encode(node, "UTF-8")}&i=$id"
        assertNotNull(Pairing.parseInvite("nodetide://pair?$ok"))
        val bad = listOf(
            "https://pair?$ok", "nodetide://other?$ok", "nodetide://pair", "nodetide://pair?c=ABCDE23456",
            "nodetide://pair?c=SHORT&n=${java.net.URLEncoder.encode(node, "UTF-8")}&i=$id",
            "nodetide://pair?c=ABCDE23456&n=${java.net.URLEncoder.encode(node, "UTF-8")}&i=nothash",
            "nodetide://pair?c=ABCDE23456&n=http%3A%2F%2Fevil.example.org&i=$id",              // cleartext away from the local network
            "nodetide://pair?c=ABCDE23456&n=http%3A%2F%2F8.8.8.8&i=$id",
            "nodetide://pair?c=ABCDE23456&n=ftp%3A%2F%2F192.168.1.5&i=$id",
            "nodetide://pair?c=ABCDE23456&n=https%3A%2F%2Fuser%3Apw%40node.example.org&i=$id",  // credentials in the address
            "nodetide://pair?c=ABCDE23456&n=https%3A%2F%2Fnode.example.org%2Fpath%3Fx%3D1&i=$id", // not just an origin
            "nodetide://u@pair?$ok", "", "not a uri at all", "nodetide://pair?c=ABCDE23456&n=%ZZ&i=$id",
        )
        for (b in bad) assertNull(Pairing.parseInvite(b), b)
    }

    @Test
    fun theWebShareQrAndTheOlderFormatBothParse() {
        val pk = "cd".repeat(32)
        val web = """{"v":1,"id":"$id","dp":["https://relay.example.org","dns:example.org"],"pk":"$pk"}"""
        assertEquals(SharedIdentity(id, pk, listOf("https://relay.example.org", "dns:example.org")), Share.parse(web))
        assertEquals(SharedIdentity(id, null, emptyList()), Share.parse("""{"v":1,"id":"$id"}"""))
        assertEquals(SharedIdentity(id, pk, emptyList()), Share.parse("nodetide:identity:$id:$pk"))
        assertEquals(SharedIdentity(id, pk, listOf("https://a.example")), Share.parse(Share.build(id, pk, listOf("https://a.example"))))
        for (bad in listOf("", "{}", """{"v":2,"id":"$id"}""", """{"v":1,"id":"short"}""", "{broken", "nodetide:identity:$id", "nodetide:identity:zz:$pk", "hello")) {
            assertNull(Share.parse(bad), bad)
        }
    }
}
