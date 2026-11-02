package eu.kuklin.nodetide

import android.app.Application
import eu.kuklin.nodetide.data.IdentityStore
import eu.kuklin.nodetide.data.SettingsStore
import eu.kuklin.nodetide.discovery.RelayDiscoveryService
import eu.kuklin.nodetide.network.ApiClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class NodetideApp : Application() {
    lateinit var identityStore: IdentityStore
        private set

    lateinit var settingsStore: SettingsStore
        private set

    lateinit var discoveryService: RelayDiscoveryService
        private set

    /** The pairing being done now (a QR was scanned or an invite pasted); the pairing screen shows it. */
    @Volatile var pairing: eu.kuklin.nodetide.data.PairingSession? = null
    /** Work that must outlive a screen (turning the phone must not cancel a pairing). */
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var apiClient: ApiClient? = null
    private var lastRelayUrl: String? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        identityStore = IdentityStore(this)
        // seal anything an earlier build left in clear
        CoroutineScope(Dispatchers.IO).launch { runCatching { identityStore.migrate() } }
        settingsStore = SettingsStore(this)
        discoveryService = RelayDiscoveryService(this)
    }

    fun getApiClient(): ApiClient? {
        val currentUrl = runBlocking { settingsStore.relayUrl.first() }
        if (currentUrl == null) {
            apiClient = null
            lastRelayUrl = null
            return null
        }
        if (currentUrl != lastRelayUrl) {
            apiClient = ApiClient(currentUrl)
            lastRelayUrl = currentUrl
        }
        return apiClient
    }

    companion object {
        lateinit var instance: NodetideApp
            private set
    }
}
