package eu.kuklin.nodetide.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.util.Log
import eu.kuklin.nodetide.data.DiscoveredRelay
import eu.kuklin.nodetide.protocol.Lan
import eu.kuklin.nodetide.protocol.LanNode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.net.Inet4Address

/**
 * Finds Nodetide nodes on the local network (mDNS / DNS-SD, `_nodetide._tcp`, see lan-discovery.md).
 *
 * Android's NsdManager resolves one service at a time (a second concurrent resolve fails with FAILURE_ALREADY_ACTIVE), so
 * resolves are queued. Everything found goes through [Lan.fromAnnouncement]: only plain IPv4 addresses on local ranges,
 * only announcements of the right version. The result says what a node *claims*; nothing here proves it is the user's node.
 */
class RelayDiscoveryService(private val context: Context) {

    companion object {
        private const val TAG = "RelayDiscovery"
        private const val SERVICE_TYPE = "_nodetide._tcp."
        private const val RESOLVE_TIMEOUT_MS = 4000L
    }

    private val nsdManager: NsdManager by lazy { context.getSystemService(Context.NSD_SERVICE) as NsdManager }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val resolving = Mutex()

    private var listener: NsdManager.DiscoveryListener? = null
    private var starts = 0
    private val found = mutableMapOf<String, LanNode>()
    private val _nodes = MutableStateFlow<List<LanNode>>(emptyList())

    /** The nodes currently on the network (empty until [start]). */
    val nodes: StateFlow<List<LanNode>> = _nodes.asStateFlow()

    /** Start browsing; nested calls are counted, so a screen and a banner can both ask. */
    @Synchronized
    fun start() {
        if (starts++ > 0) return
        val l = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) { Log.d(TAG, "discovery started") }

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                scope.launch { resolve(serviceInfo) }
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                synchronized(found) { found.remove(serviceInfo.serviceName) }
                publish()
            }

            override fun onDiscoveryStopped(serviceType: String) { Log.d(TAG, "discovery stopped") }
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) { Log.e(TAG, "start failed: $errorCode") }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) { Log.e(TAG, "stop failed: $errorCode") }
        }
        listener = l
        try {
            nsdManager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, l)
        } catch (e: Exception) {
            Log.e(TAG, "could not start discovery", e)
            listener = null
            starts = 0
        }
    }

    @Synchronized
    fun stop() {
        if (starts == 0 || --starts > 0) return
        listener?.let { runCatching { nsdManager.stopServiceDiscovery(it) } }
        listener = null
        synchronized(found) { found.clear() }
        publish()
    }

    /** Browse for a while and return what was found (the manual "Discover" button). */
    suspend fun discoverRelaysForDuration(durationMs: Long): List<DiscoveredRelay> {
        start()
        try {
            delay(durationMs)
            return nodes.value.map { it.toRelay() }
        } finally {
            stop()
        }
    }

    private fun publish() {
        _nodes.update { synchronized(found) { found.values.sortedBy { it.name } } }
    }

    @Suppress("DEPRECATION") // resolveService is deprecated from API 34 but still the call that works down to minSdk 26
    private suspend fun resolve(info: NsdServiceInfo) = resolving.withLock {
        val done = CompletableDeferred<NsdServiceInfo?>()
        try {
            nsdManager.resolveService(info, object : NsdManager.ResolveListener {
                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) { done.complete(null) }
                override fun onServiceResolved(serviceInfo: NsdServiceInfo) { done.complete(serviceInfo) }
            })
        } catch (e: Exception) {
            done.complete(null)
        }
        val resolved = withTimeoutOrNull(RESOLVE_TIMEOUT_MS) { done.await() } ?: return@withLock
        val host = (resolved.host as? Inet4Address)?.hostAddress ?: return@withLock    // numeric IPv4 only
        val attributes = resolved.attributes.orEmpty().mapValues { (_, v) -> v?.toString(Charsets.UTF_8) ?: "" }
        val node = Lan.fromAnnouncement(resolved.serviceName, host, resolved.port, attributes)
        if (node == null) {
            Log.d(TAG, "ignoring an announcement that is not a usable local node")
            return@withLock
        }
        synchronized(found) { found[resolved.serviceName] = node }
        publish()
    }
}

fun LanNode.toRelay() = DiscoveredRelay(name = name, host = host, port = port, properties = properties, scheme = scheme, ids = ids)
