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
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.Executors

class ProxyService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var heartbeatJob: Job? = null
    private var forwardJob: Job? = null
    private val dnsExecutor = Executors.newFixedThreadPool(8)
    
    private var currentHeartbeatDomain: String? = null
    
    // Active configuration tracking
    private var runningPort: Int = 0
    private var runningUrl: String = ""
    private var runningBootstrap: String = ""
    private var runningCacheTtl: Long = 0
    private var runningTcpLimit: Int = 0
    private var runningPollInterval: Long = 0
    private var runningHttp3: Boolean = false
    private var runningHeartbeatDomain: String = ""

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
    private val networkCallback = object : android.net.ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: android.net.Network) {
            super.onAvailable(network)
            if (BuildConfig.DEBUG) Log.d(TAG, "Network available")
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

        if (BuildConfig.DEBUG) Log.d(TAG, "onStartCommand: vpnReady=${vpnInterface != null}, url=$resolverUrl")

        if (vpnInterface != null) {
            val configChanged = runningPort != listenPort || runningUrl != resolverUrl || 
                               runningBootstrap != bootstrapDns || runningCacheTtl != cacheTtl ||
                               runningTcpLimit != tcpLimit || runningPollInterval != pollInterval ||
                               runningHttp3 != useHttp3 || runningHeartbeatDomain != heartbeatDomain
            
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
                
                serviceScope.launch {
                    delay(1000)
                    if (BuildConfig.DEBUG) Log.d(TAG, "Initializing Rust proxy on 127.0.0.1:$listenPort")
                    val res = startProxy("127.0.0.1", listenPort, resolverUrl, bootstrapDns, allowIpv6, cacheTtl, tcpLimit, pollInterval, useHttp3, heartbeatDomain)
                    if (BuildConfig.DEBUG) Log.d(TAG, "Backend proxy initialized (result: $res)")
                    
                    if (heartbeatEnabled) {
                        if (BuildConfig.DEBUG) Log.d(TAG, "Triggering post-restart heartbeat")
                        startHeartbeat(heartbeatDomain, listenPort, heartbeatInterval)
                    }
                }
            } else {
                if (BuildConfig.DEBUG) Log.d(TAG, "No config change, refreshing heartbeat only")
                if (heartbeatEnabled) {
                    startHeartbeat(heartbeatDomain, listenPort, heartbeatInterval)
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

        serviceScope.launch {
            if (BuildConfig.DEBUG) Log.d(TAG, "Starting Rust proxy on 127.0.0.1:$listenPort")
            startProxy("127.0.0.1", listenPort, resolverUrl, bootstrapDns, allowIpv6, cacheTtl, tcpLimit, pollInterval, useHttp3, heartbeatDomain)
        }

        try {
            vpnInterface = Builder()
                .setSession(getString(R.string.app_name))
                .addAddress("10.0.0.1", 32)
                .addDnsServer("10.0.0.2") // Virtual DNS IP
                .addRoute("10.0.0.2", 32) // Route only the virtual DNS IP
                .apply {
                    if (allowIpv6) {
                        addAddress("fd00::1", 128)
                        addDnsServer("fd00::2")
                        addRoute("fd00::2", 128)
                    }
                }
                .setBlocking(true)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                        allowBypass()
                        addDisallowedApplication(packageName)
                    }
                }
                .establish()
            
            if (BuildConfig.DEBUG) Log.d(TAG, "VPN Interface established (IPv6: $allowIpv6)")
            forwardJob = serviceScope.launch { 
                delay(1000)
                if (BuildConfig.DEBUG) Log.d(TAG, "Starting packet forwarding loop on port $listenPort")
                forwardPackets(listenPort) 
            }
            
            if (heartbeatEnabled) {
                startHeartbeat(heartbeatDomain, listenPort, heartbeatInterval)
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN", e)
            handleStop()
        }

        return START_STICKY
    }

    private fun startHeartbeat(domain: String, port: Int, interval: Long) {
        stopHeartbeat()
        currentHeartbeatDomain = domain
        heartbeatJob = serviceScope.launch {
            val socket = DatagramSocket()
            val address = InetAddress.getByName("127.0.0.1")
            val query = constructDnsQuery(domain)
            if (BuildConfig.DEBUG) Log.d(TAG, "Starting heartbeat loop for $domain on port $port")
            try {
                while (isActive && isProxyRunning && currentHeartbeatDomain == domain) {
                    val packet = DatagramPacket(query, query.size, address, port)
                    socket.send(packet)
                    if (BuildConfig.DEBUG) Log.d(TAG, "Sent heartbeat ping to localhost:$port") 
                    delay(interval * 1000)
                }
            } catch (e: Exception) {
                if (e !is CancellationException) {
                    Log.e(TAG, "Heartbeat error", e)
                }
            } finally {
                socket.close()
                if (BuildConfig.DEBUG) Log.d(TAG, "Heartbeat loop stopped")
            }
        }
    }

    private fun stopHeartbeat() {
        currentHeartbeatDomain = null
        heartbeatJob?.cancel()
        heartbeatJob = null
    }

    private fun constructDnsQuery(domain: String): ByteArray {
        val header = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        val body = mutableListOf<Byte>()
        domain.split(".").forEach { part ->
            body.add(part.length.toByte())
            part.forEach { body.add(it.code.toByte()) }
        }
        body.add(0x00); body.add(0x00); body.add(0x01); body.add(0x00); body.add(0x01)
        return header + body.toByteArray()
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
                            
                            if (dPort == 53 || InetAddress.getByAddress(data.copyOfRange(16, 20)).hostAddress == "10.0.0.2") {
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
                            val nextHeader = data[6].toInt() and 0xFF
                            if (nextHeader == 17) { // UDP
                                val dPort = ((data[42].toInt() and 0xFF) shl 8) or (data[43].toInt() and 0xFF)
                                if (dPort == 53) {
                                    dnsExecutor.execute {
                                        try {
                                            val dnsPayload = data.copyOfRange(48, length)
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

    private fun handleDnsQuery(payload: ByteArray, proxyAddr: InetAddress, proxyPort: Int): DatagramPacket? {
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            socket.soTimeout = 4000
            socket.send(DatagramPacket(payload, payload.size, proxyAddr, proxyPort))
            val recvBuf = ByteArray(4096)
            val recvPacket = DatagramPacket(recvBuf, recvBuf.size)
            socket.receive(recvPacket)
            recvPacket
        } catch (e: Exception) {
            Log.e(TAG, "DNS lookup failed: ${e.message}")
            null
        } finally {
            socket?.close()
        }
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
        
        // Swap UDP ports: response source = request dest, response dest = request source
        response[ihl] = request[ihl + 2]; response[ihl + 1] = request[ihl + 3]
        response[ihl + 2] = request[ihl]; response[ihl + 3] = request[ihl + 1]
        val udpLen = 8 + payloadLen
        response[ihl + 4] = (udpLen shr 8).toByte(); response[ihl + 5] = (udpLen and 0xFF).toByte()
        System.arraycopy(payload, 0, response, ihl + 8, payloadLen)
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
