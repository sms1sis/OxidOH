package io.github.sms1sis.oxidoh

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.Executors

class ProxyService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var heartbeatJob: Job? = null
    private var forwardJob: Job? = null
    // Cached pool: grows under burst load, idles back down after 60s.
    // Rust handles query parallelism; Kotlin just needs to dispatch quickly.
    private val dnsExecutor = Executors.newCachedThreadPool()
    
    
    // Active configuration tracking
    private var runningPort: Int = 0
    private var runningUrl: String = ""
    private var runningBootstrap: String = ""
    private var runningCacheTtl: Long = 0
    private var runningTcpLimit: Int = 0
    private var runningPollInterval: Long = 0
    private var runningHttp3: Boolean = false
    private var runningHeartbeatDomain: String = ""
    private var runningExcludedApps: Set<String> = emptySet()

    companion object {
        const val CHANNEL_ID = "ProxyServiceChannel"
        const val NOTIFICATION_ID = 1
        private const val TAG = "OxidOH"

        @Volatile
        var isProxyRunning = false
            private set

        @JvmStatic
        external fun getLatency(): Int
        @JvmStatic
        external fun getLogs(): Array<String>
        @JvmStatic
        external fun getStats(): IntArray
        @JvmStatic
        external fun clearStats()
        @JvmStatic
        external fun clearCache()
        @JvmStatic
        external fun clearLogs()

        @JvmStatic
        fun nativeLog(level: String, tag: String, message: String) {
            when (level) {
                "ERROR" -> Log.e(tag, message)
                "WARN" -> Log.w(tag, message)
                "INFO" -> if (BuildConfig.DEBUG) Log.i(tag, message)
                else -> if (BuildConfig.DEBUG) Log.d(tag, message)
            }
        }

        init {
            System.loadLibrary("oxidoh")
        }
    }

    private external fun initLogger(context: Context)
    private external fun startProxy(
        listenAddr: String,
        listenPort: Int,
        resolverUrl: String,
        bootstrapDns: String,
        allowIpv6: Boolean,
        cacheTtl: Long,
        tcpLimit: Int,
        pollInterval: Long,
        useHttp3: Boolean,
        excludeDomain: String
    ): Int
    private external fun stopProxy()

    private var connectivityManager: android.net.ConnectivityManager? = null
    private var lastNetwork: android.net.Network? = null
    private var networkRestartJob: Job? = null
    @Volatile private var proxyReady = false  // set true once waitForProxyReady succeeds

    private val networkCallback = object : android.net.ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: android.net.Network) {
            super.onAvailable(network)
            // registerDefaultNetworkCallback always fires onAvailable immediately with the
            // current network on registration — ignore that first call by comparing network IDs.
            if (lastNetwork == null) {
                lastNetwork = network
                if (BuildConfig.DEBUG) Log.d(TAG, "Network callback: initial network registered, ignoring")
                return
            }
            if (network == lastNetwork) return  // same network, not a change
            lastNetwork = network
            if (!isProxyRunning || !proxyReady) {
                if (BuildConfig.DEBUG) Log.d(TAG, "Network change seen but proxy not ready yet — skipping restart")
                return
            }
            // Debounce: cancel any pending restart before scheduling a new one
            networkRestartJob?.cancel()
            networkRestartJob = serviceScope.launch(Dispatchers.IO) {
                Log.i(TAG, "Network changed to $network — restarting proxy for fresh bootstrap")
                delay(1500)
                if (!isProxyRunning) return@launch
                proxyReady = false
                stopProxy()
                delay(500)
                startProxy(
                    "127.0.0.1", runningPort, runningUrl, runningBootstrap,
                    runningCacheTtl > 0, runningCacheTtl, runningTcpLimit,
                    runningPollInterval, runningHttp3, runningHeartbeatDomain
                )
                val bound = waitForProxyReady(runningPort, timeoutMs = 30_000)
                proxyReady = bound
                if (!bound) Log.e(TAG, "Proxy did not rebind after network change")
                else Log.i(TAG, "Proxy ready after network change")
            }
        }

        override fun onLost(network: android.net.Network) {
            super.onLost(network)
            if (network == lastNetwork) lastNetwork = null
        }
    }

    override fun onCreate() {
        super.onCreate()
        initLogger(this)
        createNotificationChannel()
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        connectivityManager?.registerDefaultNetworkCallback(networkCallback)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            handleStop()
            return START_NOT_STICKY
        }

        // Start foreground immediately to prevent ANR/Crash
        isProxyRunning = true
        startForegroundServiceNotification()

        val prefs = getSharedPreferences("settings", Context.MODE_PRIVATE)
        val listenPort = intent?.getIntExtra("listenPort", -1).takeIf { it != null && it != -1 }
            ?: prefs.getString("listen_port", "5053")?.toIntOrNull() ?: 5053
        
        val resolverUrl = intent?.getStringExtra("resolverUrl") 
            ?: prefs.getString("resolver_url", "https://odoh.cloudflare-dns.com/dns-query") ?: "https://odoh.cloudflare-dns.com/dns-query"

        val bootstrapDns = intent?.getStringExtra("bootstrapDns")
            ?: prefs.getString("bootstrap_dns", "1.1.1.1") ?: "1.1.1.1"

        val allowIpv6 = intent?.getBooleanExtra("allowIpv6", prefs.getBoolean("allow_ipv6", false))
            ?: prefs.getBoolean("allow_ipv6", false)
        
        val cacheTtl = intent?.getLongExtra("cacheTtl", -1L).takeIf { it != null && it != -1L }
            ?: prefs.getString("cache_ttl", "300")?.toLongOrNull() ?: 300L

        val tcpLimit = intent?.getIntExtra("tcpLimit", 20) ?: 20
        val pollInterval = intent?.getLongExtra("pollInterval", 120L) ?: 120L
        val useHttp3 = intent?.getBooleanExtra("useHttp3", false) ?: false
        
        val heartbeatEnabled = intent?.getBooleanExtra("heartbeatEnabled", prefs.getBoolean("heartbeat_enabled", true)) 
            ?: prefs.getBoolean("heartbeat_enabled", true)
        
        val heartbeatDomain = intent?.getStringExtra("heartbeatDomain")
            ?: prefs.getString("heartbeat_domain", "google.com") ?: "google.com"
            
        val heartbeatInterval = intent?.getLongExtra("heartbeatInterval", -1L).takeIf { it != null && it != -1L }
            ?: prefs.getString("heartbeat_interval", "10")?.toLongOrNull() ?: 10L

        val excludedApps = prefs.getStringSet("excluded_apps", emptySet()) ?: emptySet()

        if (BuildConfig.DEBUG) Log.d(TAG, "onStartCommand: vpnReady=${vpnInterface != null}, url=$resolverUrl")

        if (vpnInterface != null) {
            val configChanged = runningPort != listenPort || runningUrl != resolverUrl || 
                               runningBootstrap != bootstrapDns || runningCacheTtl != cacheTtl ||
                               runningTcpLimit != tcpLimit || runningPollInterval != pollInterval ||
                               runningHttp3 != useHttp3 || runningHeartbeatDomain != heartbeatDomain ||
                               runningExcludedApps != excludedApps
            
            if (configChanged) {
                if (BuildConfig.DEBUG) Log.d(TAG, "Dynamic config change detected. Restarting backend...")
                stopProxy()
                
                runningPort = listenPort
                runningUrl = resolverUrl
                runningBootstrap = bootstrapDns
                runningCacheTtl = cacheTtl
                runningTcpLimit = tcpLimit
                runningPollInterval = pollInterval
                runningHttp3 = useHttp3
                runningHeartbeatDomain = heartbeatDomain
                runningExcludedApps = excludedApps
                
                serviceScope.launch(Dispatchers.IO) {
                    // Wait for the previous proxy instance to fully release the port
                    delay(1500)
                    if (BuildConfig.DEBUG) Log.d(TAG, "Re-initializing Rust proxy on 127.0.0.1:$listenPort")
                    val res = startProxy(
                        "127.0.0.1", listenPort, resolverUrl, bootstrapDns,
                        allowIpv6, cacheTtl, tcpLimit, pollInterval, useHttp3, heartbeatDomain
                    )
                    if (BuildConfig.DEBUG) Log.d(TAG, "Backend proxy re-initialized (result=$res)")
                    if (heartbeatEnabled && isProxyRunning) {
                        delay(1000)
                        startHeartbeat(resolverUrl, heartbeatInterval)
                    }
                }
            } else {
                if (BuildConfig.DEBUG) Log.d(TAG, "No config change, refreshing heartbeat only")
                if (heartbeatEnabled) {
                    startHeartbeat(resolverUrl, heartbeatInterval)
                } else {
                    stopHeartbeat()
                }
            }
            return START_STICKY
        }
        
        // Initial start
        runningPort = listenPort
        runningUrl = resolverUrl
        runningBootstrap = bootstrapDns
        runningCacheTtl = cacheTtl
        runningTcpLimit = tcpLimit
        runningPollInterval = pollInterval
        runningHttp3 = useHttp3
        runningHeartbeatDomain = heartbeatDomain
        runningExcludedApps = excludedApps

        try {
            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .addAddress("10.0.0.1", 32)
                .addDnsServer("10.0.0.2") // Virtual DNS IP
                .addRoute("10.0.0.2", 32) // Route only the virtual DNS IP
                .setMtu(1500)
                .setBlocking(true)

            if (allowIpv6) {
                builder.addAddress("fd00::1", 128)
                       .addDnsServer("fd00::2")
                       .addRoute("fd00::2", 128)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                builder.allowBypass()
                builder.addDisallowedApplication(packageName) // Always exclude ourselves
                excludedApps.forEach { pkg ->
                    try {
                        builder.addDisallowedApplication(pkg)
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to exclude app: $pkg")
                    }
                }
            }

            vpnInterface = builder.establish()
            if (BuildConfig.DEBUG) Log.d(TAG, "VPN Interface established (IPv6: $allowIpv6)")

            // Fire startProxy() — it spawns the Rust runtime task and returns
            // immediately (non-blocking JNI). The proxy does bootstrap DNS +
            // ODoH config fetch before binding its UDP socket, so we must wait
            // until the port is actually open before forwarding packets into it.
            serviceScope.launch(Dispatchers.IO) {
                if (BuildConfig.DEBUG) Log.d(TAG, "Starting Rust proxy on 127.0.0.1:$listenPort")
                startProxy(
                    "127.0.0.1", listenPort, resolverUrl, bootstrapDns,
                    allowIpv6, cacheTtl, tcpLimit, pollInterval, useHttp3, heartbeatDomain
                )
                if (BuildConfig.DEBUG) Log.d(TAG, "startProxy() returned, proxy task spawned")
            }

            // Poll until the Rust proxy UDP port is open, then start forwarding.
            // Timeout after 30 s to avoid spinning forever if startup fails.
            forwardJob = serviceScope.launch(Dispatchers.IO) {
                if (BuildConfig.DEBUG) Log.d(TAG, "Waiting for Rust proxy to bind on port $listenPort...")
                val bound = waitForProxyReady(listenPort, timeoutMs = 30_000)
                if (!bound) {
                    Log.e(TAG, "Rust proxy did not bind on port $listenPort within 30s — aborting")
                    handleStop()
                    return@launch
                }
                if (BuildConfig.DEBUG) Log.d(TAG, "Rust proxy ready — starting packet forwarding")
                proxyReady = true
                if (isActive && isProxyRunning) {
                    forwardPackets(listenPort)
                }
                proxyReady = false
            }

            if (heartbeatEnabled) {
                // Give the Rust proxy a moment to bind before the first heartbeat ping.
                // The heartbeat loop itself retries every interval so a single missed
                // ping is harmless; this just avoids a guaranteed first-ping timeout.
                serviceScope.launch {
                    delay(3000)
                    if (isProxyRunning) startHeartbeat(resolverUrl, heartbeatInterval)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN", e)
            handleStop()
        }

        return START_STICKY
    }

    /**
     * Polls 127.0.0.1:[port] with a minimal UDP probe every 200 ms until the
     * Rust proxy responds (any bytes back = bound) or [timeoutMs] elapses.
     * Returns true if the proxy is ready, false if it timed out.
     */
    private fun waitForProxyReady(port: Int, timeoutMs: Long): Boolean {
        val probe = byteArrayOf(
            // Minimal valid DNS query for "." (root) type A — 17 bytes
            0x00, 0x01,  // ID
            0x01, 0x00,  // flags: standard query
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counts
            0x00,        // root label
            0x00, 0x01,  // QTYPE A
            0x00, 0x01   // QCLASS IN
        )
        val deadline = System.currentTimeMillis() + timeoutMs
        val addr = java.net.InetAddress.getByName("127.0.0.1")
        while (System.currentTimeMillis() < deadline && isProxyRunning) {
            var sock: DatagramSocket? = null
            try {
                sock = DatagramSocket()
                sock.soTimeout = 200
                sock.send(DatagramPacket(probe, probe.size, addr, port))
                val buf = ByteArray(512)
                sock.receive(DatagramPacket(buf, buf.size))
                return true // got a response — proxy is up
            } catch (_: Exception) {
                // timeout or nothing yet — keep polling
            } finally {
                try { sock?.close() } catch (_: Exception) {}
            }
            Thread.sleep(200)
        }
        return false
    }

    private fun startHeartbeat(resolverUrl: String, interval: Long) {
        stopHeartbeat()
        heartbeatJob = serviceScope.launch(Dispatchers.IO) {
            // Use direct HTTPS HEAD to the DoH resolver URL instead of DNS wire packets.
            // This means:
            //  - heartbeat activity never appears in query logs or stats counters
            //  - no fake DNS traffic inflates UDP/cache-miss counters
            //  - latency reflects real ODoH round-trip time
            if (BuildConfig.DEBUG) Log.d(TAG, "Starting HTTPS heartbeat to $resolverUrl")
            while (isActive && isProxyRunning) {
                val start = System.currentTimeMillis()
                try {
                    val conn = URL(resolverUrl).openConnection() as HttpURLConnection
                    conn.requestMethod = "HEAD"
                    conn.connectTimeout = 5000
                    conn.readTimeout = 5000
                    conn.instanceFollowRedirects = false
                    conn.setRequestProperty("User-Agent", "OxidOH-Heartbeat/1.0")
                    conn.setRequestProperty("Connection", "close")
                    conn.connect()
                    val latencyMs = (System.currentTimeMillis() - start).toInt()
                    conn.disconnect()
                    if (BuildConfig.DEBUG) Log.d(TAG, "Heartbeat RTT: ${latencyMs}ms")
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    if (BuildConfig.DEBUG) Log.d(TAG, "Heartbeat failed: ${e.message}")
                }
                delay(interval * 1000L)
            }
            if (BuildConfig.DEBUG) Log.d(TAG, "Heartbeat loop stopped")
        }
    }

    private fun stopHeartbeat() {
        heartbeatJob?.cancel()
        heartbeatJob = null
    }

    private suspend fun forwardPackets(proxyPort: Int) {
        val fd = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(fd)
        val outputStream = FileOutputStream(fd)
        val packet = ByteBuffer.allocate(16384)
        val proxyAddr = InetAddress.getByName("127.0.0.1")
        try {
            withContext(Dispatchers.IO) {
                while (isActive && isProxyRunning) {
                    val length = inputStream.read(packet.array())
                    if (length > 0) {
                        val data = packet.array().copyOf(length)
                        val version = (data[0].toInt() and 0xF0)
                        
                        if (version == 0x40 && (data[9].toInt() and 0xFF) == 17) { // IPv4 UDP
                            val ihl = (data[0].toInt() and 0x0F) * 4
                            val dPort = ((data[ihl + 2].toInt() and 0xFF) shl 8) or (data[ihl + 3].toInt() and 0xFF)
                            
                            // Compare dest IP bytes directly (10.0.0.2 = 0x0A,0x00,0x00,0x02)
                        // Avoids InetAddress allocation + string comparison on every packet
                        val dstIsDns = dPort == 53 ||
                            (data[16] == 10.toByte() && data[17] == 0.toByte() &&
                             data[18] == 0.toByte() && data[19] == 2.toByte())
                        if (dstIsDns) {
                                dnsExecutor.execute {
                                    try {
                                        val dnsPayload = data.copyOfRange(ihl + 8, length)
                                        val response = handleDnsQuery(dnsPayload, proxyAddr, proxyPort)
                                        if (response != null) {
                                            synchronized(outputStream) {
                                                outputStream.write(constructIpv4Udp(data, response.data, response.length))
                                            }
                                        }
                                    } catch (e: Exception) {
                                        Log.e(TAG, "Parallel IPv4 DNS error", e)
                                    }
                                }
                            }
                        } else if (version == 0x60) { // IPv6
                            // Walk extension headers to find actual UDP payload offset
                            val udpOffset = findIpv6UdpOffset(data, length)
                            if (udpOffset > 0) {
                                val dPort = ((data[udpOffset].toInt() and 0xFF) shl 8) or (data[udpOffset + 1].toInt() and 0xFF)
                                if (dPort == 53) {
                                    dnsExecutor.execute {
                                        try {
                                            val dnsPayload = data.copyOfRange(udpOffset + 8, length)
                                            val response = handleDnsQuery(dnsPayload, proxyAddr, proxyPort)
                                            if (response != null) {
                                                synchronized(outputStream) {
                                                    outputStream.write(constructIpv6Udp(data, response.data, response.length))
                                                }
                                            }
                                        } catch (e: Exception) {
                                            Log.e(TAG, "Parallel IPv6 DNS error", e)
                                        }
                                    }
                                }
                            }
                        }
                        packet.clear()
                    }
                    yield() 
                }
            }
        } catch (e: Exception) {
            if (e !is CancellationException) {
                Log.e(TAG, "forwardPackets critical error", e)
            }
        }
    }

    // Thread-local socket pool: each thread in dnsExecutor owns its own socket.
    // This avoids the EBADF cascade that occurs when one thread closes a shared
    // socket while other threads are mid-send/receive on it.
    private val threadLocalSocket = object : ThreadLocal<DatagramSocket?>() {
        override fun initialValue(): DatagramSocket? = null
    }

    private fun getThreadSocket(): DatagramSocket {
        val existing = threadLocalSocket.get()
        if (existing != null && !existing.isClosed) return existing
        return DatagramSocket().also { s ->
            s.soTimeout = 4000
            threadLocalSocket.set(s)
        }
    }

    private fun handleDnsQuery(payload: ByteArray, proxyAddr: InetAddress, proxyPort: Int): DatagramPacket? {
        return try {
            val socket = getThreadSocket()
            socket.send(DatagramPacket(payload, payload.size, proxyAddr, proxyPort))
            val recvBuf = ByteArray(4096)
            val recvPacket = DatagramPacket(recvBuf, recvBuf.size)
            socket.receive(recvPacket)
            recvPacket
        } catch (e: Exception) {
            Log.e(TAG, "DNS lookup failed: ${e.message}")
            // Close and evict only this thread's socket — other threads are unaffected
            try { threadLocalSocket.get()?.close() } catch (_: Exception) {}
            threadLocalSocket.set(null)
            null
        }
    }

    /**
     * Walk the IPv6 fixed header (40 bytes) and any extension headers to find
     * the byte offset where the UDP header starts.  Returns -1 if the packet
     * does not contain a UDP segment or is too short to be valid.
     *
     * Extension header next-header values that can precede UDP (17):
     *   0  = Hop-by-Hop, 43 = Routing, 44 = Fragment, 60 = Destination Options
     */
    private fun findIpv6UdpOffset(data: ByteArray, length: Int): Int {
        if (length < 40) return -1
        val UDP = 17
        val extensionHeaders = setOf(0, 43, 44, 60, 135, 139, 140)
        var nextHeader = data[6].toInt() and 0xFF
        var offset = 40 // skip fixed IPv6 header
        while (offset < length) {
            if (nextHeader == UDP) return offset
            if (nextHeader !in extensionHeaders) return -1
            if (nextHeader == 44) {
                // Fragment header is exactly 8 bytes, no length field
                if (offset + 8 > length) return -1
                nextHeader = data[offset].toInt() and 0xFF
                offset += 8
            } else {
                if (offset + 2 > length) return -1
                nextHeader = data[offset].toInt() and 0xFF
                val extLen = (data[offset + 1].toInt() and 0xFF + 1) * 8
                offset += extLen
            }
        }
        return -1
    }

    private fun constructIpv6Udp(request: ByteArray, payload: ByteArray, payloadLen: Int): ByteArray {
        val response = ByteArray(40 + 8 + payloadLen)
        // Copy IPv6 header base
        System.arraycopy(request, 0, response, 0, 40)
        // Swap Source and Destination IPs (indices 8-23 and 24-39)
        System.arraycopy(request, 24, response, 8, 16)
        System.arraycopy(request, 8, response, 24, 16)
        // Payload length in IPv6 header (UDP header + DNS payload)
        val ipv6PayloadLen = 8 + payloadLen
        response[4] = (ipv6PayloadLen shr 8).toByte()
        response[5] = (ipv6PayloadLen and 0xFF).toByte()
        // Swap UDP ports
        response[40] = request[42]; response[41] = request[43]
        response[42] = request[40]; response[43] = request[41]
        // UDP length
        response[44] = (ipv6PayloadLen shr 8).toByte()
        response[45] = (ipv6PayloadLen and 0xFF).toByte()
        
        // Copy DNS payload
        System.arraycopy(payload, 0, response, 48, payloadLen)

        // UDP checksum (REQUIRED for IPv6)
        val checksum = calculateIpv6UdpChecksum(response)
        response[46] = (checksum shr 8).toByte()
        response[47] = (checksum and 0xFF).toByte()

        return response
    }

    private fun calculateIpv6UdpChecksum(packet: ByteArray): Int {
        var sum: Long = 0
        
        // Pseudo-header: Source Address
        for (i in 8..23 step 2) {
            sum += (((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)).toLong()
        }
        // Pseudo-header: Destination Address
        for (i in 24..39 step 2) {
            sum += (((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)).toLong()
        }
        // Pseudo-header: UDP Length
        sum += (((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)).toLong()
        // Pseudo-header: Next Header (17 for UDP)
        sum += 17

        // UDP Header + Payload
        for (i in 40 until packet.size step 2) {
            if (i == 46) continue // Skip checksum field itself
            if (i + 1 < packet.size) {
                sum += (((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)).toLong()
            } else {
                sum += ((packet[i].toInt() and 0xFF) shl 8).toLong()
            }
        }

        while ((sum shr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        
        var res = (sum.inv() and 0xFFFF).toInt()
        if (res == 0) res = 0xFFFF
        return res
    }

    private fun constructIpv4Udp(request: ByteArray, payload: ByteArray, payloadLen: Int): ByteArray {
        val ihl = (request[0].toInt() and 0x0F) * 4
        val totalLen = ihl + 8 + payloadLen
        val response = ByteArray(totalLen)
        System.arraycopy(request, 0, response, 0, ihl)
        // Swap Source and Destination IPs
        System.arraycopy(request, 16, response, 12, 4)
        System.arraycopy(request, 12, response, 16, 4)
        // Set a sensible TTL (64) — inherited value from request may be 0 after
        // header copy+modification which causes some kernels to silently drop the packet.
        response[8] = 64
        // Protocol stays UDP (17), already copied from request header
        // Swap UDP ports: response source = request dest, response dest = request source
        response[ihl]     = request[ihl + 2]; response[ihl + 1] = request[ihl + 3]
        response[ihl + 2] = request[ihl];     response[ihl + 3] = request[ihl + 1]
        val udpLen = 8 + payloadLen
        response[ihl + 4] = (udpLen shr 8).toByte(); response[ihl + 5] = (udpLen and 0xFF).toByte()
        // Zero UDP checksum (optional for IPv4; kernel will accept it)
        response[ihl + 6] = 0; response[ihl + 7] = 0
        System.arraycopy(payload, 0, response, ihl + 8, payloadLen)
        // Set total length and clear checksum field before recomputing
        response[2] = (totalLen shr 8).toByte(); response[3] = (totalLen and 0xFF).toByte()
        response[10] = 0; response[11] = 0
        var checksum: Long = 0
        for (i in 0 until ihl step 2) {
            checksum += (((response[i].toInt() and 0xFF) shl 8) or (response[i + 1].toInt() and 0xFF)).toLong()
        }
        while ((checksum shr 16) > 0) {
            checksum = (checksum and 0xFFFF) + (checksum shr 16)
        }
        val finalChecksum = (checksum.inv() and 0xFFFF).toInt()
        response[10] = (finalChecksum shr 8).toByte(); response[11] = (finalChecksum and 0xFF).toByte()
        return response
    }

    private fun startForegroundServiceNotification() {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_content))
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setLargeIcon(android.graphics.BitmapFactory.decodeResource(resources, R.drawable.ic_stat_shield))
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun handleStop() {
        isProxyRunning = false
        stopHeartbeat()
        stopProxy()
        serviceScope.cancel()
        dnsExecutor.shutdown()
        proxyReady = false
        // Thread-local sockets are closed when dnsExecutor threads terminate
        try { vpnInterface?.close(); vpnInterface = null } catch (e: Exception) {}
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
        else { @Suppress("DEPRECATION") stopForeground(true) }
        stopSelf()
    }

    override fun onRevoke() { handleStop(); super.onRevoke() }
    override fun onDestroy() {
        connectivityManager?.unregisterNetworkCallback(networkCallback)
        handleStop()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(NotificationChannel(CHANNEL_ID, getString(R.string.app_name), NotificationManager.IMPORTANCE_LOW))
        }
    }
}
