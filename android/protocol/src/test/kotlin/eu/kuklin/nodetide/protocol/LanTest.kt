package eu.kuklin.nodetide.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LanTest {
    private val h1 = "a1".repeat(32)
    private val h2 = "b2".repeat(32)
    private val h3 = "c3".repeat(32)
    private val h4 = "d4".repeat(32)

    @Test
    fun onlyLocalAddressesAreLan() {
        for (ok in listOf("192.168.1.5", "10.0.2.2", "172.16.0.1", "172.31.255.255", "127.0.0.1", "169.254.10.20", "localhost", "nas.local", "NAS.LOCAL")) {
            assertTrue(Lan.isLanHost(ok), ok)
        }
        for (no in listOf("8.8.8.8", "172.32.0.1", "172.15.0.1", "192.169.1.1", "169.254.169.254", "example.org", ".local", "local",
            "192.168.1", "192.168.1.256", "192.168.001.5", "010.0.0.1", "192.168.1.5.6", "::1", "fe80::1", "", "192.168.1.5:80", "0x7f.0.0.1")) {
            assertFalse(Lan.isLanHost(no), no)
        }
    }

    @Test
    fun cleartextNeverLeavesTheLan() {
        assertTrue(Lan.cleartextAllowed("http://192.168.1.5:4557"))
        assertTrue(Lan.cleartextAllowed("http://nas.local:4557/api"))
        assertTrue(Lan.cleartextAllowed("https://node.example.org"))
        assertFalse(Lan.cleartextAllowed("http://node.example.org"))
        assertFalse(Lan.cleartextAllowed("http://8.8.8.8:4557"))
        assertFalse(Lan.cleartextAllowed("http://169.254.169.254/latest"))
        assertFalse(Lan.cleartextAllowed("http://user:pw@192.168.1.5"))
        assertFalse(Lan.cleartextAllowed("http://192.168.1.5@evil.example"))
        assertFalse(Lan.cleartextAllowed("ftp://192.168.1.5"))
        assertFalse(Lan.cleartextAllowed("javascript:alert(1)"))
        assertFalse(Lan.cleartextAllowed("not a url"))
        assertFalse(Lan.cleartextAllowed(""))
    }

    @Test
    fun anAnnouncementIsAcceptedOnlyWhenWellFormedAndLocal() {
        val ok = Lan.fromAnnouncement("home", "192.168.1.20", 4557, mapOf("version" to "1", "path" to "/api", "ids" to "$h1,$h2"))
        assertNotNull(ok)
        assertEquals("http://192.168.1.20:4557", ok.baseUrl)
        assertEquals(listOf(h1, h2), ok.ids)
        assertEquals("https://192.168.1.20:4557", Lan.fromAnnouncement("n", "192.168.1.20", 4557, mapOf("version" to "1", "scheme" to "https"))?.baseUrl)
        assertEquals("http", Lan.fromAnnouncement("n", "192.168.1.20", 4557, mapOf("version" to "1", "scheme" to "gopher"))?.scheme)

        assertNull(Lan.fromAnnouncement("n", "192.168.1.20", 4557, mapOf("version" to "2")))
        assertNull(Lan.fromAnnouncement("n", "192.168.1.20", 4557, emptyMap()))
        assertNull(Lan.fromAnnouncement("n", "192.168.1.20", 0, mapOf("version" to "1")))
        assertNull(Lan.fromAnnouncement("n", "192.168.1.20", 70000, mapOf("version" to "1")))
        assertNull(Lan.fromAnnouncement("n", "8.8.8.8", 4557, mapOf("version" to "1")))
        assertNull(Lan.fromAnnouncement("n", "169.254.169.254", 80, mapOf("version" to "1")))
        assertNull(Lan.fromAnnouncement("n", "nas.local", 4557, mapOf("version" to "1")))     // announcements are resolved to numbers
        assertNull(Lan.fromAnnouncement("n", "fe80::1", 4557, mapOf("version" to "1")))
    }

    @Test
    fun advertisedIdsAreValidatedAndFew() {
        assertEquals(listOf(h1, h2, h3), Lan.parseIds("$h1,$h2,$h3,$h4"))
        assertEquals(listOf(h1), Lan.parseIds("$h1,$h1, nonsense ,${h1.uppercase()},${h1.take(63)}"))
        assertEquals(emptyList(), Lan.parseIds(null))
        assertEquals(emptyList(), Lan.parseIds(""))
    }

    @Test
    fun findingMyNodeByMyHash() {
        val mine = LanNode("mine", "192.168.1.20", 4557, "http", listOf(h1), emptyMap())
        val other = LanNode("other", "192.168.1.21", 4557, "http", listOf(h2), emptyMap())
        val anonymous = LanNode("anon", "192.168.1.22", 4557, "http", emptyList(), emptyMap())
        assertEquals(listOf(mine), Lan.matching(listOf(other, mine, anonymous), h1))
        assertEquals(emptyList(), Lan.matching(listOf(other, anonymous), h1))
        val twoClaims = Lan.matching(listOf(mine, mine.copy(name = "impostor", host = "192.168.1.99")), h1)
        assertEquals(2, twoClaims.size)       // the caller must not pick one silently
    }
}
