package eu.kuklin.nodetide.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import eu.kuklin.nodetide.NodetideApp
import eu.kuklin.nodetide.ui.Screen
import kotlinx.coroutines.launch

@Composable
fun HomeScreen(navController: NavController) {
    val scope = rememberCoroutineScope()
    val identityStore = remember { NodetideApp.instance.identityStore }
    val settingsStore = remember { NodetideApp.instance.settingsStore }

    val identity by identityStore.currentIdentity.collectAsState(initial = null)
    val relayUrl by settingsStore.relayUrl.collectAsState(initial = null)

    var relayStatus by remember { mutableStateOf<String?>(null) }
    var isCheckingRelay by remember { mutableStateOf(false) }

    LaunchedEffect(relayUrl) {
        if (relayUrl != null) {
            isCheckingRelay = true
            try {
                val client = NodetideApp.instance.getApiClient()
                if (client != null) {
                    val result = client.healthCheck()
                    relayStatus = if (result.isSuccess && result.getOrNull() == true) "Connected" else "Unreachable"
                } else {
                    relayStatus = null
                }
            } catch (e: Exception) {
                relayStatus = "Error"
            }
            isCheckingRelay = false
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text(
                text = "Welcome to Nodetide",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Identity Status",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    if (identity != null) {
                        Text(
                            text = "✓ Identity configured",
                            color = MaterialTheme.colorScheme.secondary
                        )
                        identity?.name?.let { name ->
                            Text(
                                text = "Name: $name",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                        Text(
                            text = "Hash: ${identity?.identityHash?.take(16)}...",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        TextButton(onClick = { navController.navigate(Screen.Accounts.route) }) {
                            Text("Accounts (switch or add)")
                        }
                    } else {
                        Text(
                            text = "No identity configured",
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { navController.navigate(Screen.CreateIdentity.route) }
                            ) {
                                Text("Create New")
                            }
                            OutlinedButton(
                                onClick = { navController.navigate(Screen.AttachDevice.route) }
                            ) {
                                Text("Attach Device")
                            }
                        }
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Relay Status",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    if (relayUrl != null) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            if (isCheckingRelay) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    strokeWidth = 2.dp
                                )
                            }
                            Text(
                                text = when (relayStatus) {
                                    "Connected" -> "✓ Connected"
                                    "Unreachable" -> "✗ Unreachable"
                                    else -> "Checking..."
                                },
                                color = when (relayStatus) {
                                    "Connected" -> MaterialTheme.colorScheme.secondary
                                    "Unreachable" -> MaterialTheme.colorScheme.error
                                    else -> MaterialTheme.colorScheme.onSurface
                                }
                            )
                        }
                        Text(
                            text = relayUrl ?: "",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        Text(
                            text = "No relay configured",
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = { navController.navigate(Screen.Relays.route) }
                        ) {
                            Text("Find Relays")
                        }
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Quick Actions",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = { navController.navigate(Screen.Messages.route) },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Messages")
                        }
                        OutlinedButton(
                            onClick = { navController.navigate(Screen.Identity.route) },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Identity")
                        }
                    }
                }
            }
        }
    }
}
