package eu.kuklin.nodetide.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import eu.kuklin.nodetide.NodetideApp
import eu.kuklin.nodetide.data.PairingPhase
import eu.kuklin.nodetide.ui.Screen

/** Becoming a device of an identity by scanning the owner's pairing QR: see [eu.kuklin.nodetide.data.PairingSession]. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairDeviceScreen(navController: NavController) {
    val app = NodetideApp.instance
    val session = remember { app.pairing }

    if (session == null) {
        LaunchedEffect(Unit) { navController.popBackStack() }
        return
    }
    val phase by session.phase.collectAsState()
    val uri = androidx.compose.ui.platform.LocalUriHandler.current

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Add this phone to an identity", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Identity", style = MaterialTheme.typography.labelMedium)
                Text(session.invite.identity.take(16) + "…", fontFamily = FontFamily.Monospace)
                Text("Node", style = MaterialTheme.typography.labelMedium)
                Text(session.invite.node, fontFamily = FontFamily.Monospace)
                Text("This phone", style = MaterialTheme.typography.labelMedium)
                Text(session.label)
                Text("Key fingerprint", style = MaterialTheme.typography.labelMedium)
                Text(session.fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleLarge)
            }
        }

        when (val p = phase) {
            is PairingPhase.Confirm -> {
                Text(
                    "The device that showed the code will ask you to confirm this same fingerprint. Continue only if you started this yourself. " +
                        "This phone gets its own keys; it never sees the identity's master key.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { session.start(app.appScope) }) { Text("Add this phone") }
                    OutlinedButton(onClick = { app.pairing = null; navController.popBackStack() }) { Text("Cancel") }
                }
            }
            is PairingPhase.Opening -> {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                    Text("Contacting the node…")
                }
            }
            is PairingPhase.Waiting -> {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                    Text("Waiting for you to confirm on the other device. Check that it shows ${session.fingerprint}.")
                }
                OutlinedButton(onClick = { session.cancel(); app.pairing = null; navController.popBackStack() }) { Text("Cancel") }
            }
            is PairingPhase.Done -> {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text("This phone is now a device of ${p.name ?: "the identity"}.", fontWeight = FontWeight.SemiBold)
                }
                Text("The chain was fetched from the node and checked: it lists this phone's key. The node address was saved as this phone's relay.", style = MaterialTheme.typography.bodyMedium)
                Button(onClick = {
                    app.pairing = null
                    navController.navigate(Screen.Identity.route) { popUpTo(Screen.Home.route) }
                }) { Text("Open the identity") }
            }
            is PairingPhase.Failed -> {
                Text(p.message, color = MaterialTheme.colorScheme.error)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { app.pairing = null; navController.popBackStack() }) { Text("Close") }
                }
            }
        }
    }
}
