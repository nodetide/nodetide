package eu.kuklin.nodetide.ui.screens

import androidx.navigation.NavController
import eu.kuklin.nodetide.NodetideApp
import eu.kuklin.nodetide.data.LocalIdentity
import eu.kuklin.nodetide.data.PairingSession
import eu.kuklin.nodetide.protocol.Pairing
import eu.kuklin.nodetide.protocol.Share
import eu.kuklin.nodetide.ui.Screen

/**
 * What to do with text that came from a QR code (or was pasted): a pairing invite starts adding this phone as a device; a shared
 * identity (the web client's Share QR, or the older format) is saved watch-only. Returns a message when it is neither.
 */
suspend fun handleScanned(text: String, navController: NavController): String? {
    val app = NodetideApp.instance

    Pairing.parseInvite(text)?.let { invite ->
        app.pairing = PairingSession(invite)
        navController.navigate(Screen.PairDevice.route) { popUpTo(Screen.Home.route) }
        return null
    }

    val shared = Share.parse(text) ?: return "That is not a Nodetide code. Use the QR shown by \"Add a device\" in the web client, or an identity's Share QR."
    // A watched identity: no secret key here, only what is public
    val identity = LocalIdentity(
        identityHash = shared.identity,
        name = null,
        signingPublicKey = shared.publicKey.orEmpty(),
        signingSecretKey = "",
        encryptionSecretKey = null,
        encryptionPublicKey = null,
        distributionPoints = shared.distributionPoints,
    )
    val name = app.getApiClient()?.getIdentity(shared.identity)?.getOrNull()?.name
    app.identityStore.saveIdentity(identity.copy(name = name))
    navController.navigate(Screen.Identity.route) { popUpTo(Screen.Home.route) }
    return null
}
