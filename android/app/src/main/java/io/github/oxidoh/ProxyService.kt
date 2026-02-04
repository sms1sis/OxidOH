package io.github.oxidoh

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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import kotlin.concurrent.thread

class ProxyService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var heartbeatThread: Thread? = null
    private var currentHeartbeatDomain: String? = null
    
    // Active configuration tracking
    private var runningPort: Int = 0
    private var runningUrl: String = ""
    private var runningBootstrap: String = ""
    private var runningCacheTtl: Long = 0

    companion object {
        const val CHANNEL_ID = "ProxyServiceChannel"
        const val NOTIFICATION_ID = 1
        private const val TAG = "ProxyService"

        @Volatile
        var isProxyRunning = false
            private set

        @JvmStatic
        external fun getLatency(): Int
        @JvmStatic
        external fun getLogs(): Array<String>
        @JvmStatic
        external fun clearCache()

        init {
            System.loadLibrary("oxidoh")
        }
    }

    private external fun initLogger(context: Context)
    private external fun startProxy(listenAddr: String, listenPort: Int, resolverUrl: String, bootstrapDns: String, allowIpv6: Boolean, cacheTtl: Long): Int
    private external fun stopProxy()

    private var connectivityManager: android.net.ConnectivityManager? = null
    private val networkCallback = object : android.net.ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: android.net.Network) {
            super.onAvailable(network)
            Log.d(TAG, "Network available")
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
            ?: prefs.getString("resolver_url", "https://cloudflare-dns.com/dns-query") ?: "https://cloudflare-dns.com/dns-query"
        
        val bootstrapDns = intent?.getStringExtra("bootstrapDns")
            ?: prefs.getString("bootstrap_dns", "1.1.1.1") ?: "1.1.1.1"

        val allowIpv6 = intent?.getBooleanExtra("allowIpv6", prefs.getBoolean("allow_ipv6", false))
            ?: prefs.getBoolean("allow_ipv6", false)
        
        val cacheTtl = intent?.getLongExtra("cacheTtl", -1L).takeIf { it != null && it != -1L }
            ?: prefs.getString("cache_ttl", "300")?.toLongOrNull() ?: 300L
        
        val heartbeatEnabled = intent?.getBooleanExtra("heartbeatEnabled", prefs.getBoolean("heartbeat_enabled", true)) 
            ?: prefs.getBoolean("heartbeat_enabled", true)
        
        val heartbeatDomain = intent?.getStringExtra("heartbeatDomain")
            ?: prefs.getString("heartbeat_domain", "google.com") ?: "google.com"
            
        val heartbeatInterval = intent?.getLongExtra("heartbeatInterval", -1L).takeIf { it != null && it != -1L }
            ?: prefs.getString("heartbeat_interval", "10")?.toLongOrNull() ?: 10L

        Log.d(TAG, "onStartCommand: vpnReady=${vpnInterface != null}, url=$resolverUrl, heartbeat=$heartbeatEnabled")

        if (vpnInterface != null) {
            val configChanged = runningPort != listenPort || runningUrl != resolverUrl || runningBootstrap != bootstrapDns || runningCacheTtl != cacheTtl
            
            if (configChanged) {
                Log.d(TAG, "Dynamic config change detected. Restarting backend...")
                stopProxy()
                
                runningPort = listenPort
                runningUrl = resolverUrl
                runningBootstrap = bootstrapDns
                runningCacheTtl = cacheTtl
                
                thread {
                    try { Thread.sleep(1000) } catch (e: InterruptedException) {}
                    Log.d(TAG, "Initializing Rust proxy on 127.0.0.1:$listenPort with TTL $cacheTtl")
                    val res = startProxy("127.0.0.1", listenPort, resolverUrl, bootstrapDns, allowIpv6, cacheTtl)
                    Log.d(TAG, "Backend proxy initialized (result: $res)")
                    
                    if (heartbeatEnabled) {
                        Log.d(TAG, "Triggering post-restart heartbeat")
                        startHeartbeat(heartbeatDomain, listenPort, heartbeatInterval)
                    }
                }
            } else {
                Log.d(TAG, "No config change, refreshing heartbeat only")
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

        thread {
            Log.d(TAG, "Starting Rust proxy on 127.0.0.1:$listenPort with TTL $cacheTtl")
            startProxy("127.0.0.1", listenPort, resolverUrl, bootstrapDns, allowIpv6, cacheTtl)
        }

        try {
            vpnInterface = Builder()
                .setSession("SafeDNS")
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
            
            Log.d(TAG, "VPN Interface established (IPv6: $allowIpv6)")
            thread { forwardPackets(listenPort) }
            
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
        heartbeatThread = thread {
            val socket = DatagramSocket()
            val address = InetAddress.getByName("127.0.0.1")
            val query = constructDnsQuery(domain)
            Log.d(TAG, "Starting heartbeat loop for $domain on port $port")
            try {
                while (isProxyRunning && currentHeartbeatDomain == domain && !Thread.currentThread().isInterrupted) {
                    val packet = DatagramPacket(query, query.size, address, port)
                    socket.send(packet)
                    Log.d(TAG, "Sent heartbeat ping to localhost:$port") 
                    try {
                        Thread.sleep(interval * 1000)
                    } catch (e: InterruptedException) {
                        break
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Heartbeat error", e)
            } finally {
                socket.close()
                Log.d(TAG, "Heartbeat loop stopped")
            }
        }
    }

    private fun stopHeartbeat() {
        currentHeartbeatDomain = null
        heartbeatThread?.interrupt()
        heartbeatThread = null
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

    private fun forwardPackets(proxyPort: Int) {
        val fd = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(fd)
        val outputStream = FileOutputStream(fd)
        val packet = ByteBuffer.allocate(16384)
        val udpSocket = DatagramSocket()
        val proxyAddr = InetAddress.getByName("127.0.0.1")
        try {
            while (isProxyRunning) {
                val length = inputStream.read(packet.array())
                if (length > 0) {
                    val data = packet.array()
                    val version = (data[0].toInt() and 0xF0)
                    
                    if (version == 0x40 && data[9].toInt() == 17) { // IPv4 UDP
                        val ihl = (data[0].toInt() and 0x0F) * 4
                        val dPort = ((data[ihl + 2].toInt() and 0xFF) shl 8) or (data[ihl + 3].toInt() and 0xFF)
                        if (dPort != 5053) { // Ignore local proxy traffic if it somehow leaks
                             // Log.d(TAG, "IPv4 UDP packet: dPort=$dPort")
                        }
                        if (dPort == 53) {
                            val dnsPayload = data.copyOfRange(ihl + 8, length)
                            udpSocket.send(DatagramPacket(dnsPayload, dnsPayload.size, proxyAddr, proxyPort))
                            val recvBuf = ByteArray(4096)
                            val recvPacket = DatagramPacket(recvBuf, recvBuf.size)
                            udpSocket.soTimeout = 4000 
                            try {
                                udpSocket.receive(recvPacket)
                                outputStream.write(constructIpv4Udp(data, recvPacket.data, recvPacket.length))
                            } catch (e: Exception) {
                                Log.e(TAG, "Proxy timeout (IPv4)", e)
                            }
                        }
                    } else if (version == 0x60) {
                        val nextHeader = data[6].toInt() and 0xFF
                        // Log.d(TAG, "IPv6 packet seen: nextHeader=$nextHeader")
                        if (nextHeader == 17) { // UDP
                            val dPort = ((data[42].toInt() and 0xFF) shl 8) or (data[43].toInt() and 0xFF)
                            if (dPort == 53) {
                                val dnsPayload = data.copyOfRange(48, length)
                                udpSocket.send(DatagramPacket(dnsPayload, dnsPayload.size, proxyAddr, proxyPort))
                                val recvBuf = ByteArray(4096)
                                val recvPacket = DatagramPacket(recvBuf, recvBuf.size)
                                udpSocket.soTimeout = 4000
                                                            try {
                                                                udpSocket.receive(recvPacket)
                                                                outputStream.write(constructIpv6Udp(data, recvPacket.data, recvPacket.length))
                                                            } catch (e: Exception) {
                                                                Log.e(TAG, "Proxy timeout (IPv6)", e)
                                                            }                            }
                        }
                    }
                    packet.clear()
                }
            }
        } catch (e: Exception) {}
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
        System.arraycopy(request, 16, response, 12, 4)
        System.arraycopy(request, 12, response, 16, 4)
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
            .setContentTitle("SafeDNS Active")
            .setContentText("Protecting DNS queries")
            .setSmallIcon(R.drawable.ic_stat_shield) // Custom monochrome shield icon
            .setLargeIcon(android.graphics.BitmapFactory.decodeResource(resources, R.mipmap.ic_launcher)) // App icon for drawer
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun handleStop() {
        isProxyRunning = false
        stopHeartbeat()
        stopProxy()
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
            manager?.createNotificationChannel(NotificationChannel(CHANNEL_ID, "SafeDNS", NotificationManager.IMPORTANCE_LOW))
        }
    }
}
