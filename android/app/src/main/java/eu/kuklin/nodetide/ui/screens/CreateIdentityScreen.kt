package eu.kuklin.nodetide.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateIdentityScreen(navController: NavController) {
    val scope = rememberCoroutineScope()
    val identityStore = remember { NodetideApp.instance.identityStore }

    var name by remember { mutableStateOf("") }
    var isCreating by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun createIdentity() {
        if (name.isBlank()) {
            error = "Please enter a name"
            return
        }

        scope.launch {
            isCreating = true
            error = null

            try {
                // Keys, genesis and the first device are made by the protocol module; the screen only publishes them.
                val identity = identityStore.createIdentity(name.trim())
                val client = NodetideApp.instance.getApiClient()
                if (client != null) {
                    val chain = identityStore.getSigchain()
                    var refused: Throwable? = client.createIdentity(chain.first()).exceptionOrNull()
                    for (event in chain.drop(1)) {
                        if (refused != null) break
                        refused = client.submitEvent(identity.identityHash, event).exceptionOrNull()
                    }
                    if (refused != null) {
                        identityStore.clearIdentity() // nothing half-made is kept when the node says no
                        error = "The node did not accept the identity: ${refused.message}"
                        isCreating = false
                        return@launch
                    }
                }

                // Navigate back
                navController.navigate(Screen.Identity.route) {
                    popUpTo(Screen.Home.route)
                }
            } catch (e: Exception) {
                error = e.message ?: "Unknown error"
            }

            isCreating = false
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Create Identity") },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "Create a new identity",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )

            Text(
                text = "This will generate a new cryptographic keypair and create your identity on the connected relay.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Display Name") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                enabled = !isCreating
            )

            error?.let { err ->
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Text(
                        text = err,
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            Button(
                onClick = { createIdentity() },
                modifier = Modifier.fillMaxWidth(),
                enabled = !isCreating && name.isNotBlank()
            ) {
                if (isCreating) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(if (isCreating) "Creating..." else "Create Identity")
            }
        }
    }
}
