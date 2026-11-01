package eu.kuklin.nodetide.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import eu.kuklin.nodetide.NodetideApp
import eu.kuklin.nodetide.data.Account
import eu.kuklin.nodetide.ui.Screen
import kotlinx.coroutines.launch

/** Every identity on this phone: switch between them, add another, remove one. */
@Composable
fun AccountsScreen(navController: NavController) {
    val scope = rememberCoroutineScope()
    val store = remember { NodetideApp.instance.identityStore }
    val book by store.book.collectAsState(initial = eu.kuklin.nodetide.data.AccountBook())
    val problem by store.problem.collectAsState(initial = null)
    var removing by remember { mutableStateOf<Account?>(null) }
    var discarding by remember { mutableStateOf(false) }

    if (discarding) {
        AlertDialog(
            onDismissRequest = { discarding = false },
            icon = { Icon(Icons.Default.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("Discard the unreadable accounts?") },
            text = { Text("They are stored encrypted with a key this phone no longer has, so they cannot be opened here and nothing in them can be recovered on this phone. Discard them only if you have a backup or another device that holds these identities.") },
            confirmButton = {
                Button(
                    onClick = { scope.launch { store.discardUnreadable() }; discarding = false },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                ) { Text("Discard") }
            },
            dismissButton = { TextButton(onClick = { discarding = false }) { Text("Cancel") } },
        )
    }

    removing?.let { account ->
        AlertDialog(
            onDismissRequest = { removing = null },
            icon = { Icon(Icons.Default.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("Remove ${account.identity.name ?: "this account"}?") },
            text = {
                Text(
                    if (account.watchOnly) "This stops following the identity on this phone."
                    else "This deletes the account and its private keys from this phone. Without a backup or another device holding the keys, the identity cannot be used again. This cannot be undone."
                )
            },
            confirmButton = {
                Button(
                    onClick = { scope.launch { store.removeAccount(account.hash) }; removing = null },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                ) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("Cancel") } },
        )
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text("Accounts", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(
                "Each account is its own identity with its own keys. The active one is used everywhere in the app.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (problem != null) {
            item {
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer), modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Your accounts cannot be opened", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(
                            "They are encrypted with a key kept in this phone's secure hardware, and that key is gone or the data was changed. " +
                                "This can happen after restoring the phone from a backup or changing its security. Nothing was deleted: the app will not " +
                                "write over them. Restore from a backup, or discard them to start again.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = { discarding = true }) { Text("Discard unreadable accounts") }
                    }
                }
            }
        }

        if (book.accounts.isEmpty() && problem == null) {
            item { Text("No accounts yet.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }

        items(book.accounts, key = { it.hash }) { account ->
            val active = account.hash == book.current?.hash
            Card(
                modifier = Modifier.fillMaxWidth().clickable { scope.launch { store.setActive(account.hash) } },
                colors = CardDefaults.cardColors(
                    containerColor = if (active) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
                ),
            ) {
                Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = active, onClick = { scope.launch { store.setActive(account.hash) } })
                    Column(modifier = Modifier.weight(1f).padding(start = 8.dp)) {
                        Text(account.identity.name ?: "(unnamed)", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(
                            account.hash.take(24) + "...",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        val kind = when {
                            account.watchOnly -> "watch-only"
                            account.identity.isDevice -> "device"
                            else -> "your identity"
                        }
                        Text(
                            kind + if (active) " · active" else "",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.secondary,
                        )
                    }
                    IconButton(onClick = { removing = account }) {
                        Icon(Icons.Default.Delete, contentDescription = "Remove account", tint = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(onClick = { navController.navigate(Screen.CreateIdentity.route) }) {
                    Icon(Icons.Default.Add, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("New account")
                }
                OutlinedButton(onClick = { navController.navigate(Screen.AttachDevice.route) }) { Text("Attach device") }
                OutlinedButton(onClick = { navController.navigate(Screen.ScanQR.route) }) { Text("Watch") }
            }
        }
    }
}
