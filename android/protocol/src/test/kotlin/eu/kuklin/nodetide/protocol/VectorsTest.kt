package eu.kuklin.nodetide.protocol

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.DynamicTest.dynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The cross-language vectors (protocol-vectors/chain-v2.json), made by the Python reference. Kotlin must reach the same
 * verdict on every chain, report the same facts about the valid ones, and build the same events from the same inputs.
 */
class VectorsTest {
    private val doc: JsonObject = Json.parseToJsonElement(File("../../protocol-vectors/chain-v2.json").readText()).jsonObject
    private val now = doc.getValue("now").jsonPrimitive.content.toLong()

    private fun resolver(related: JsonObject): (String) -> Sigchain? {
        val cache = mutableMapOf<String, Sigchain?>()
        val busy = mutableSetOf<String>()
        lateinit var resolve: (String) -> Sigchain?
        resolve = { id ->
            if (id in cache) cache[id]
            else {
                val list = related[id]?.let { (it as? JsonArray)?.toList() }
                if (list == null || !busy.add(id)) null
                else try {
                    val chain = try { Sigchain.parse(list, Options(BcEd25519, resolve)) } catch (e: ChainError) { null }
                    cache[id] = chain?.takeIf { it.identityHash == id }
                    cache[id]
                } finally { busy.remove(id) }
            }
        }
        return resolve
    }

    @TestFactory
    fun chainsAgreeWithThePythonReference(): List<DynamicTest> = doc.getValue("cases").jsonArray.map { c ->
        val case = c.jsonObject
        dynamicTest(case.getValue("name").jsonPrimitive.content) {
            val expect = case.getValue("expect").jsonObject
            val related = case.getValue("related").jsonObject
            val checkCurrent = case.getValue("check_current").jsonPrimitive.boolean
            val chain = try {
                Sigchain.parse(case.getValue("chain").jsonArray.toList(), Options(BcEd25519, resolver(related), checkCurrent))
            } catch (e: ChainError) {
                if (expect.getValue("valid").jsonPrimitive.boolean) fail("Kotlin rejects a chain the reference accepts: ${e.message}")
                return@dynamicTest
            }
            if (!expect.getValue("valid").jsonPrimitive.boolean) {
                fail("Kotlin accepts a chain the reference rejects (${expect["reference_error"]})")
            }
            assertEquals(expect.getValue("identity").jsonPrimitive.content, chain.identityHash)
            assertEquals(expect.getValue("head").jsonPrimitive.content, chain.headHash)
            assertEquals(expect.getValue("master").jsonPrimitive.content, chain.master)
            assertEquals(expect.getValue("partial").jsonPrimitive.boolean, chain.isPartial)
            assertEquals(expect.getValue("control_length").jsonPrimitive.content.toInt(), chain.controlLength)
            assertEquals(expect.getValue("content_length").jsonPrimitive.content.toInt(), chain.contentLength)
            assertEquals(
                expect.getValue("active_devices").jsonArray.map { it.jsonPrimitive.content },
                chain.activeDevices(now).map { it.pubkey }.sorted(),
            )
            val claims = chain.claimIds().map { id -> chain.claim(id)!!.let { "$id/${it.first}/${if (it.second) "revoked" else "active"}" } }
            val wanted = expect.getValue("claims").jsonArray.map {
                val m = it.jsonObject
                "${m.getValue("id").jsonPrimitive.content}/${m.getValue("type").jsonPrimitive.content}/" +
                    if (m.getValue("revoked").jsonPrimitive.boolean) "revoked" else "active"
            }
            assertEquals(wanted.sorted(), claims.sorted())
            expect["device_status"]?.jsonObject?.forEach { (pub, v) ->
                val want = v.jsonObject
                val got = chain.deviceStatus(pub)
                assertEquals(want.getValue("known").jsonPrimitive.boolean, got.known, "known $pub")
                assertEquals(want.getValue("revoked").jsonPrimitive.boolean, got.revoked, "revoked $pub")
                assertEquals(want["untrusted_since"]?.jsonPrimitive?.content?.toLongOrNull(), got.untrustedSince, "untrusted_since $pub")
            }
            case["attach"]?.jsonArray?.forEachIndexed { i, a ->
                val item = a.jsonObject
                val problem = chain.attachContent(item.getValue("event").jsonObject, item.getValue("proof").jsonArray.map { it.jsonPrimitive.content })
                assertEquals(item.getValue("ok").jsonPrimitive.boolean, problem == null, "attach $i: $problem")
            }
        }
    }

    @Test
    fun eventsBuiltHereAreByteIdenticalToThePythonOnes() {
        val b = doc.getValue("builders").jsonObject
        val master = SeedSigner(b.getValue("master_seed").jsonPrimitive.content)
        val device = SeedSigner(b.getValue("device_seed").jsonPrimitive.content)
        val base = b.getValue("base_timestamp").jsonPrimitive.content.toLong()
        fun ts(step: Int) = base + 10L * step
        val caps = listOf("sign_messages", "encrypt", "authenticate", "manage_claims")

        val genesis = Events.genesis(master, b.getValue("master_encryption_pubkey").jsonPrimitive.content, ts(1), b.getValue("name").jsonPrimitive.content)
        val h0 = Events.identityHash(genesis)
        val addDevice = Events.addDevice(master, h0, ts(2), device.publicKeyHex, b.getValue("device_encryption_pubkey").jsonPrimitive.content, "phone", caps)
        val hAdd = Events.eventHash(addDevice)
        val c1 = Events.addClaim(master, null, 0, hAdd, ts(3), "claim-id-0000000001", "email", "11".repeat(32))
        val c2 = Events.addClaim(device, Events.eventHash(c1), 1, hAdd, ts(4), "claim-id-0000000002", "phone", "22".repeat(32))
        val two = listOf(c1, c2).map(Events::eventHash)
        val checkpoint = Events.checkpoint(master, hAdd, ts(5), Events.commitment(two)!!)
        val hCp = Events.eventHash(checkpoint)
        val c3 = Events.addClaim(master, Events.eventHash(c2), 2, hCp, ts(6), "claim-id-0000000003", "email", "33".repeat(32))
        val order = Events.setClaimOrder(master, Events.eventHash(c3), 3, hCp, ts(7), "email", listOf("claim-id-0000000003", "claim-id-0000000001"))
        val four = listOf(c1, c2, c3, order).map(Events::eventHash)
        val revokeClaim = Events.revokeClaim(master, hCp, ts(8), "claim-id-0000000002", "gone", Events.commitment(four))
        val revokeDevice = Events.revokeDevice(master, Events.eventHash(revokeClaim), ts(9), device.publicKeyHex, "lost", commitment = Events.commitment(four))

        val built = listOf(genesis, addDevice, checkpoint, revokeClaim, revokeDevice, c1, c2, c3, order)
        val expected = b.getValue("events").jsonArray.map { it.jsonObject }
        assertEquals(expected.map(Canonical::encode), built.map(Canonical::encode))

        // and what it builds is a chain the verifier accepts
        val chain = Sigchain.parse(built, Options(BcEd25519))
        assertEquals(h0, chain.identityHash)
        assertEquals(4, chain.contentLength)
        assertTrue(chain.activeDevices(now).none { it.pubkey == device.publicKeyHex })
        assertNotNull(chain.claim("claim-id-0000000002"))
    }

    @Test
    fun canonicalJsonEscapesLikePython() {
        val value = JsonObject(mapOf("b" to JsonPrimitive("a\"b\\c\n\u007f\u0001é😀"), "a" to JsonPrimitive(1)))
        assertEquals("{\"a\":1,\"b\":\"a\\\"b\\\\c\\n\\u007f\\u0001\\u00e9\\ud83d\\ude00\"}", Canonical.encode(value))
    }
}
