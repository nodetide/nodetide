package eu.kuklin.nodetide.data

import android.os.Build
import eu.kuklin.nodetide.NodetideApp
import eu.kuklin.nodetide.crypto.EncryptionKeyPair
import eu.kuklin.nodetide.crypto.SigningKeyPair
import eu.kuklin.nodetide.crypto.SodiumVerifier
import eu.kuklin.nodetide.network.ApiClient
import eu.kuklin.nodetide.protocol.Invite
import eu.kuklin.nodetide.protocol.Options
import eu.kuklin.nodetide.protocol.Pairing
import eu.kuklin.nodetide.protocol.Sigchain
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

sealed interface PairingPhase {
    /** The invite was read; nothing has been sent yet. The user checks where this phone is about to be added. */
    data object Confirm : PairingPhase
    data object Opening : PairingPhase
    /** This phone's public keys are on the node; the owner has to confirm on the other device. */
    data object Waiting : PairingPhase
    data class Done(val name: String?) : PairingPhase
    data class Failed(val message: String) : PairingPhase
}

/**
 * Becoming a device of an identity by scanning the QR code the owner's wallet shows (web/js/app.js, Wallet.pairing*).
 *
 * The phone makes its own keys and leaves only the PUBLIC halves in a slot on the node, named by the hash of the code from the QR.
 * The owner compares the fingerprint, and the wallet that holds the master key authorizes the phone on the identity's chain. The phone
 * does not trust any message for that: it fetches the chain, verifies it, and becomes a device only when the chain itself lists its key
 * with the right to authenticate. The keys live in this object (not in the screen), so turning the phone does not lose them.
 */
class PairingSession(val invite: Invite) {
    val device: SigningKeyPair = SigningKeyPair.generate()
    val encryption: EncryptionKeyPair = EncryptionKeyPair.generate()
    val label: String = Build.MODEL.orEmpty().filter { it.code in 0x20..0x7e }.trim().take(60).ifEmpty { "Android phone" }
    val fingerprint: String = Pairing.fingerprint(device.publicKeyHex)

    private val _phase = MutableStateFlow<PairingPhase>(PairingPhase.Confirm)
    val phase: StateFlow<PairingPhase> = _phase

    private var job: Job? = null

    @Synchronized
    fun start(scope: CoroutineScope) {
        if (job != null) return
        _phase.value = PairingPhase.Opening
        job = scope.launch { run() }
    }

    @Synchronized
    fun cancel() {
        job?.cancel()
        job = null
        if (_phase.value !is PairingPhase.Done) _phase.value = PairingPhase.Failed("Cancelled.")
    }

    private fun fail(message: String) { _phase.value = PairingPhase.Failed(message) }

    private suspend fun run() {
        val api = ApiClient(invite.node)
        val slot = Pairing.slotName(invite.code)
        val expires = api.openPairing(slot, device.publicKeyHex, encryption.publicKeyHex, label).getOrElse {
            fail("Could not reach ${invite.node}: ${it.message}")
            return
        }
        _phase.value = PairingPhase.Waiting
        while (currentCoroutineContext().isActive) {
            if (System.currentTimeMillis() / 1000 > expires + 30) {
                fail("The code expired before the other device confirmed. Show a new code there and scan it again.")
                return
            }
            val download = api.getSigchain(invite.identity)
            val chainResult = download.getOrNull()
            if (chainResult == null) {
                if (download.exceptionOrNull()?.message?.startsWith("HTTP 404") == true) {
                    fail("This node does not know that identity.")
                    return
                }                                                         // otherwise a hiccup: try again
            } else if (!chainResult.verified) {
                fail("The identity's chain on that node does not verify (${chainResult.problem ?: "unknown reason"}). Nothing was added.")
                return
            } else {
                val chain = Sigchain.parse(chainResult.events, Options(SodiumVerifier))
                val mine = chain.activeDevices(System.currentTimeMillis() / 1000).firstOrNull { it.pubkey == device.publicKeyHex }
                if (mine != null && "authenticate" in mine.capabilities) {
                    finish(api, chainResult.events)
                    return
                }
            }
            delay(2000)
        }
    }

    private suspend fun finish(api: ApiClient, events: List<JsonObject>) {
        val info = api.getIdentity(invite.identity).getOrNull()
        val points = events.mapNotNull { it["distribution_points"] as? JsonArray }.lastOrNull()
            ?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.orEmpty()
        val app = NodetideApp.instance
        app.identityStore.addPairedDevice(
            identityHash = invite.identity,
            name = info?.name,
            masterPublicKey = info?.masterPubkey.orEmpty(),
            distributionPoints = points,
            chain = events,
            device = device,
            deviceEncryption = encryption,
        )
        if (app.settingsStore.getRelayUrl() == null) app.settingsStore.setRelayUrl(invite.node, "Paired node")
        _phase.value = PairingPhase.Done(info?.name)
    }
}
