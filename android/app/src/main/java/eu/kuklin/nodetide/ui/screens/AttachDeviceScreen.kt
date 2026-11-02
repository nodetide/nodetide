package eu.kuklin.nodetide.ui.screens

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import eu.kuklin.nodetide.NodetideApp
import eu.kuklin.nodetide.protocol.Share
import eu.kuklin.nodetide.crypto.SigningKeyPair
import eu.kuklin.nodetide.ui.Screen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AttachDeviceScreen(navController: NavController) {
    val scope = rememberCoroutineScope()
    var selectedTab by remember { mutableStateOf(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Attach Device") },
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
        ) {
            TabRow(selectedTabIndex = selectedTab) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Scan QR") }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Show QR") }
                )
            }

            when (selectedTab) {
                0 -> ScanQRTab(navController)
                1 -> ShowQRTab(navController)
            }
        }
    }
}

@Composable
private fun ScanQRTab(navController: NavController) {
    val scope = rememberCoroutineScope()
    var pasted by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "Add this phone as a device",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "On the web client open My Identity > Devices & recovery > Add a device, unlock the wallet and press \"Show a pairing QR code\". " +
                "Scan that QR here. This phone gets its own keys; you confirm on the other screen that the fingerprints match.\n\n" +
                "An identity's Share QR can be scanned too: it adds the identity to watch, without any keys.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = { navController.navigate(Screen.ScanQR.route) }
        ) {
            Icon(Icons.Default.QrCodeScanner, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("Open Scanner")
        }

        Spacer(modifier = Modifier.height(24.dp))

        OutlinedTextField(
            value = pasted,
            onValueChange = { pasted = it; problem = null },
            label = { Text("Or paste the invite") },
            placeholder = { Text("nodetide://pair?...") },
            isError = problem != null,
            supportingText = problem?.let { { Text(it) } },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedButton(
            enabled = pasted.isNotBlank(),
            onClick = { scope.launch { problem = handleScanned(pasted, navController) } }
        ) {
            Text("Use this invite")
        }
    }
}

@Composable
private fun ShowQRTab(navController: NavController) {
    val scope = rememberCoroutineScope()
    val identityStore = remember { NodetideApp.instance.identityStore }
    val identity by identityStore.currentIdentity.collectAsState(initial = null)

    var qrBitmap by remember { mutableStateOf<Bitmap?>(null) }
    var isGenerating by remember { mutableStateOf(false) }

    LaunchedEffect(identity) {
        if (identity != null) {
            isGenerating = true
            withContext(Dispatchers.Default) {
                try {
                    // Generate QR code with identity data for device attachment
                    // Format: nodetide:attach:identityHash:pubkey:encryptedSecretKey
                    // Note: In production, this should use secure key exchange
                    val qrData = Share.build(identity!!.identityHash, identity!!.signingPublicKey.ifBlank { null }, identity!!.distributionPoints)
                    qrBitmap = generateQRCode(qrData, 256)
                } catch (e: Exception) {
                    // Handle error
                }
            }
            isGenerating = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if (identity == null) {
            Spacer(modifier = Modifier.weight(1f))
            Text(
                text = "No identity to share",
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = "Create an identity first to share it with other devices.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = { navController.navigate(Screen.CreateIdentity.route) }) {
                Text("Create Identity")
            }
            Spacer(modifier = Modifier.weight(1f))
        } else {
            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Show this QR to another device",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "The other device can scan this to view your identity. For security, secret key sharing requires additional verification.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(24.dp))

            Card(
                modifier = Modifier.size(280.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            ) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    if (isGenerating) {
                        CircularProgressIndicator()
                    } else if (qrBitmap != null) {
                        Image(
                            bitmap = qrBitmap!!.asImageBitmap(),
                            contentDescription = "QR Code",
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(16.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = identity?.name ?: "(unnamed)",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = identity?.identityHash?.take(24) + "...",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun generateQRCode(content: String, size: Int): Bitmap {
    val writer = QRCodeWriter()
    val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size)

    val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
    for (x in 0 until size) {
        for (y in 0 until size) {
            bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
        }
    }
    return bitmap
}
