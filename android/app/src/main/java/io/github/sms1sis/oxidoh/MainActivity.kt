package io.github.sms1sis.oxidoh

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import io.github.sms1sis.oxidoh.ui.components.AboutDialog
import io.github.sms1sis.oxidoh.ui.components.DrawerContent
import io.github.sms1sis.oxidoh.ui.screens.DashboardScreen
import io.github.sms1sis.oxidoh.ui.screens.DnsProfile
import io.github.sms1sis.oxidoh.ui.screens.LogScreen
import io.github.sms1sis.oxidoh.ui.screens.StatsScreen
import io.github.sms1sis.oxidoh.ui.screens.AppSelectionScreen
import io.github.sms1sis.oxidoh.ui.theme.OxidOHTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val context = LocalContext.current
            val prefs = remember { context.getSharedPreferences("settings", MODE_PRIVATE) }
            var themeMode by remember { mutableStateOf(prefs.getString("theme", "System") ?: "System") }
            var notchMode by remember { mutableStateOf(prefs.getBoolean("notch_mode", true)) }
            
            val darkTheme = when (themeMode) {
                "Light" -> false
                "Dark" -> true
                "AMOLED" -> true
                else -> isSystemInDarkTheme()
            }
            
            val amoled = themeMode == "AMOLED"

            LaunchedEffect(notchMode) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    val window = (context as android.app.Activity).window
                    val params = window.attributes
                    params.layoutInDisplayCutoutMode = if (notchMode) {
                        WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
                    } else {
                        WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_DEFAULT
                    }
                    window.attributes = params
                }
            }

            DisposableEffect(darkTheme) {
                enableEdgeToEdge(
                    statusBarStyle = SystemBarStyle.auto(
                        android.graphics.Color.TRANSPARENT,
                        android.graphics.Color.TRANSPARENT,
                    ) { darkTheme },
                    navigationBarStyle = SystemBarStyle.auto(
                        android.graphics.Color.TRANSPARENT,
                        android.graphics.Color.TRANSPARENT,
                    ) { darkTheme }
                )
                onDispose {}
            }

            OxidOHTheme(darkTheme = darkTheme, amoled = amoled) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ProxyScreen(
                        themeMode = themeMode,
                        onThemeChange = { 
                            themeMode = it
                            prefs.edit().putString("theme", it).apply()
                        },
                        notchMode = notchMode,
                        onNotchModeChange = {
                            notchMode = it
                            prefs.edit().putBoolean("notch_mode", it).apply()
                        }
                    )
                }
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun ProxyScreen(themeMode: String, onThemeChange: (String) -> Unit, notchMode: Boolean, onNotchModeChange: (Boolean) -> Unit) {
        val context = LocalContext.current
        val prefs = remember { context.getSharedPreferences("settings", MODE_PRIVATE) }
        
        var isRunning by remember { mutableStateOf(ProxyService.isProxyRunning) }
        var currentTab by remember { mutableStateOf(0) }
        var latency by remember { mutableStateOf(0) }
        var logs by remember { mutableStateOf(emptyArray<String>()) }
        var stats by remember { mutableStateOf(intArrayOf(0, 0, 0)) }
        var showAppSelection by remember { mutableStateOf(false) }
        var excludedApps by remember { mutableStateOf(prefs.getStringSet("excluded_apps", emptySet()) ?: emptySet()) }
        
        var autoStart by remember { mutableStateOf(prefs.getBoolean("auto_start", false)) }
        var allowIpv6 by remember { mutableStateOf(prefs.getBoolean("allow_ipv6", false)) }
        var cacheTtl by remember { mutableStateOf(prefs.getString("cache_ttl", "300") ?: "300") }
        var tcpLimit by remember { mutableStateOf(prefs.getString("tcp_limit", "20") ?: "20") }
        var pollInterval by remember { mutableStateOf(prefs.getString("poll_interval", "120") ?: "120") }
        var useHttp3 by remember { mutableStateOf(prefs.getBoolean("use_http3", false)) }
        var heartbeatEnabled by remember { mutableStateOf(prefs.getBoolean("heartbeat_enabled", true)) }
        var heartbeatDomain by remember { mutableStateOf(prefs.getString("heartbeat_domain", "google.com") ?: "google.com") }
        var heartbeatInterval by remember { mutableStateOf(prefs.getString("heartbeat_interval", "10") ?: "10") }

        // Debounced heartbeat settings
        var pendingHeartbeatDomain by remember { mutableStateOf(heartbeatDomain) }
        var pendingHeartbeatInterval by remember { mutableStateOf(heartbeatInterval) }
        var pendingCacheTtl by remember { mutableStateOf(cacheTtl) }
        var pendingTcpLimit by remember { mutableStateOf(tcpLimit) }
        var pendingPollInterval by remember { mutableStateOf(pollInterval) }

                val profiles = listOf(
                    DnsProfile("Cloudflare via Fastly", "https://odoh.cloudflare-dns.com/dns-query https://odoh-relay.edgecompute.app/proxy", "151.101.1.51,1.1.1.1"),
                    DnsProfile("Cloudflare via Equinix", "https://odoh.cloudflare-dns.com/dns-query https://odoh-relay.equinix.com/proxy", "139.178.64.1,1.1.1.1"),
                    DnsProfile("Cloudflare via SURF", "https://odoh.cloudflare-dns.com/dns-query https://odoh-relay.surf.nl/proxy", "145.100.185.128,1.1.1.1"),
                    DnsProfile("Crypto.sx via Fastly", "https://odoh.crypto.sx/dns-query https://odoh-relay.edgecompute.app/proxy", "151.101.1.51,172.67.140.94"),
                    DnsProfile("Cloudflare Direct", "https://odoh.cloudflare-dns.com/dns-query", "1.1.1.1"),
                    DnsProfile("Tiarap JP Direct", "https://doh.tiar.app/odoh", "174.138.29.175"),
                    DnsProfile("Snowstorm Direct", "https://dope.snowstorm.love/dns-query", "1.1.1.1,8.8.8.8"),
                    DnsProfile("Custom ODoH", "https://odoh.cloudflare-dns.com/dns-query", "1.1.1.1")
                )
        
                var selectedProfileIndex by remember { mutableStateOf(prefs.getInt("selected_profile", 0)) }
                // Active settings (Source of truth for Service/Prefs)
        var resolverUrl by remember { mutableStateOf(prefs.getString("resolver_url", profiles[selectedProfileIndex].url) ?: profiles[selectedProfileIndex].url) }
        var bootstrapDns by remember { mutableStateOf(prefs.getString("bootstrap_dns", profiles[selectedProfileIndex].bootstrap) ?: profiles[selectedProfileIndex].bootstrap) }
        var listenPort by remember { mutableStateOf(prefs.getString("listen_port", "5053") ?: "5053") }

        // UI State (Pending user input)
        var pendingResolverUrl by remember { mutableStateOf(resolverUrl) }
        var pendingBootstrapDns by remember { mutableStateOf(bootstrapDns) }
        var pendingListenPort by remember { mutableStateOf(listenPort) }
        
        val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
        val scope = rememberCoroutineScope()
        var showAboutDialog by remember { mutableStateOf(false) }
        val uriHandler = LocalUriHandler.current

        val powerManager = remember { context.getSystemService(Context.POWER_SERVICE) as PowerManager }
        var isIgnoringBatteryOptimizations by remember {
            mutableStateOf(
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    powerManager.isIgnoringBatteryOptimizations(context.packageName)
                } else true
            )
        }

        val batteryOptimizationLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) {
            isIgnoringBatteryOptimizations = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                powerManager.isIgnoringBatteryOptimizations(context.packageName)
            } else true
        }

        fun requestBatteryOptimization() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                        data = android.net.Uri.parse("package:${context.packageName}")
                    }
                    batteryOptimizationLauncher.launch(intent)
                } catch (e: Exception) {
                    // Fallback to settings page if direct request fails
                    val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                    batteryOptimizationLauncher.launch(intent)
                }
            }
        }

        val permissionLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { isGranted ->
            if (!isGranted) {
                Log.w("OxidOH", "Notification permission denied")
            }
        }

        LaunchedEffect(Unit) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                    permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }

            // Inform the user about battery optimization via Toast on first run
            if (!isIgnoringBatteryOptimizations) {
                val hasPrompted = prefs.getBoolean("battery_prompted", false)
                if (!hasPrompted) {
                    val msg = context.getString(R.string.battery_prompt)
                    android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_LONG).show()
                    prefs.edit().putBoolean("battery_prompted", true).apply()
                }
            }
            
            while (true) {
                isRunning = ProxyService.isProxyRunning
                if (isRunning) {
                    val newLat = ProxyService.getLatency()
                    if (newLat > 0 && newLat != latency) {
                        if (BuildConfig.DEBUG) Log.d("OxidOH", "UI Latency update: $newLat ms")
                        latency = newLat
                    }
                    logs = ProxyService.getLogs()
                    stats = ProxyService.getStats()
                }
                delay(1000)
            }
        }

        // Debounce effect for all settings
        LaunchedEffect(pendingHeartbeatDomain, pendingHeartbeatInterval, pendingResolverUrl, pendingBootstrapDns, pendingListenPort, allowIpv6, pendingCacheTtl, pendingTcpLimit, pendingPollInterval, useHttp3, excludedApps) {
            delay(1500) // Wait for 1.5s after user stops typing
            
            var changed = false
            if (heartbeatDomain != pendingHeartbeatDomain) { heartbeatDomain = pendingHeartbeatDomain; changed = true }
            if (heartbeatInterval != pendingHeartbeatInterval) { heartbeatInterval = pendingHeartbeatInterval; changed = true }
            if (resolverUrl != pendingResolverUrl) { resolverUrl = pendingResolverUrl; changed = true }
            if (bootstrapDns != pendingBootstrapDns) { bootstrapDns = pendingBootstrapDns; changed = true }
            if (listenPort != pendingListenPort) { listenPort = pendingListenPort; changed = true }
            if (cacheTtl != pendingCacheTtl) { cacheTtl = pendingCacheTtl; changed = true }
            if (tcpLimit != pendingTcpLimit) { tcpLimit = pendingTcpLimit; changed = true }
            if (pollInterval != pendingPollInterval) { pollInterval = pendingPollInterval; changed = true }

            if (changed) {
                val finalResolverUrl = pendingResolverUrl
                val finalBootstrapDns = pendingBootstrapDns
                val finalListenPort = pendingListenPort
                val finalCacheTtl = pendingCacheTtl
                val finalTcpLimit = pendingTcpLimit
                val finalPollInterval = pendingPollInterval

                prefs.edit()
                    .putString("heartbeat_domain", heartbeatDomain)
                    .putString("heartbeat_interval", heartbeatInterval)
                    .putString("resolver_url", finalResolverUrl)
                    .putString("bootstrap_dns", finalBootstrapDns)
                    .putString("listen_port", finalListenPort)
                    .putBoolean("allow_ipv6", allowIpv6)
                    .putString("cache_ttl", finalCacheTtl)
                    .putString("tcp_limit", finalTcpLimit)
                    .putString("poll_interval", finalPollInterval)
                    .putBoolean("use_http3", useHttp3)
                    .putInt("selected_profile", selectedProfileIndex)
                    .apply()
                
                if (isRunning) {
                    startProxyService(finalResolverUrl, finalListenPort, finalBootstrapDns, allowIpv6, finalCacheTtl, finalTcpLimit, finalPollInterval, useHttp3, heartbeatEnabled, heartbeatDomain, heartbeatInterval)
                }
            }
        }

        val vpnPermissionLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == RESULT_OK) {
                startProxyService(resolverUrl, listenPort, bootstrapDns, allowIpv6, cacheTtl, tcpLimit, pollInterval, useHttp3, heartbeatEnabled, heartbeatDomain, heartbeatInterval)
                isRunning = true
            }
        }

        if (showAboutDialog) {
            AboutDialog(onDismiss = { showAboutDialog = false }, uriHandler = uriHandler)
        }

        if (showAppSelection) {
            AppSelectionScreen(
                excludedApps = excludedApps,
                onBack = { showAppSelection = false },
                onToggleApp = { pkg ->
                    val newSet = excludedApps.toMutableSet()
                    if (newSet.contains(pkg)) newSet.remove(pkg) else newSet.add(pkg)
                    excludedApps = newSet
                    prefs.edit().putStringSet("excluded_apps", newSet).apply()
                }
            )
            return
        }

        val onToggle = {
            if (isRunning) {
                val stopIntent = Intent(context, ProxyService::class.java).apply { action = "STOP" }
                context.startService(stopIntent)
                isRunning = false
            } else {
                val vpnIntent = VpnService.prepare(context)
                if (vpnIntent != null) vpnPermissionLauncher.launch(vpnIntent)
                else {
                    startProxyService(resolverUrl, listenPort, bootstrapDns, allowIpv6, cacheTtl, tcpLimit, pollInterval, useHttp3, heartbeatEnabled, heartbeatDomain, heartbeatInterval)
                    isRunning = true
                }
            }
        }

        ModalNavigationDrawer(
            drawerState = drawerState,
            drawerContent = {
                ModalDrawerSheet {
                    DrawerContent(
                        themeMode = themeMode,
                        autoStart = autoStart,
                        allowIpv6 = allowIpv6,
                        cacheTtl = pendingCacheTtl,
                        tcpLimit = pendingTcpLimit,
                        pollInterval = pendingPollInterval,
                        useHttp3 = useHttp3,
                        heartbeatEnabled = heartbeatEnabled,
                        heartbeatDomain = pendingHeartbeatDomain,
                        heartbeatInterval = pendingHeartbeatInterval,
                        onThemeChange = onThemeChange,
                        notchMode = notchMode,
                        onNotchModeChange = onNotchModeChange,
                        onAutoStartChange = { 
                            autoStart = it
                            prefs.edit().putBoolean("auto_start", it).apply()
                        },
                        onAllowIpv6Change = { enabled ->
                            allowIpv6 = enabled
                            prefs.edit().putBoolean("allow_ipv6", enabled).apply()
                            if (isRunning) {
                                startProxyService(resolverUrl, listenPort, bootstrapDns, enabled, cacheTtl, tcpLimit, pollInterval, useHttp3, heartbeatEnabled, heartbeatDomain, heartbeatInterval)
                            }
                        },
                        onCacheTtlChange = { pendingCacheTtl = it },
                        onTcpLimitChange = { pendingTcpLimit = it },
                        onPollIntervalChange = { pendingPollInterval = it },
                        onHttp3Change = { enabled ->
                            useHttp3 = enabled
                            prefs.edit().putBoolean("use_http3", enabled).apply()
                            if (isRunning) {
                                startProxyService(resolverUrl, listenPort, bootstrapDns, allowIpv6, cacheTtl, tcpLimit, pollInterval, enabled, heartbeatEnabled, heartbeatDomain, heartbeatInterval)
                            }
                        },
                        onHeartbeatChange = { enabled ->
                            heartbeatEnabled = enabled
                            prefs.edit().putBoolean("heartbeat_enabled", enabled).apply()
                            if (isRunning) {
                                startProxyService(resolverUrl, listenPort, bootstrapDns, allowIpv6, cacheTtl, tcpLimit, pollInterval, useHttp3, enabled, heartbeatDomain, heartbeatInterval)
                            }
                        },
                        onHeartbeatDomainChange = { pendingHeartbeatDomain = it },
                        onHeartbeatIntervalChange = { pendingHeartbeatInterval = it },
                        isIgnoringBatteryOptimizations = isIgnoringBatteryOptimizations,
                        onRequestBatteryOptimization = { requestBatteryOptimization() },
                        onAppExclusionClick = { showAppSelection = true },
                        onAboutClick = { showAboutDialog = true },
                        onClose = { scope.launch { drawerState.close() } }
                    )
                }
            }
        ) {
            Scaffold(
                topBar = {
                    CenterAlignedTopAppBar(
                        modifier = Modifier.clip(RoundedCornerShape(bottomStart = 24.dp, bottomEnd = 24.dp)),
                        title = { 
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Shield, null, modifier = Modifier.size(24.dp), tint = MaterialTheme.colorScheme.primary)
                                Spacer(Modifier.width(8.dp))
                                Text("OxidOH", fontWeight = FontWeight.Black, letterSpacing = (-0.5).sp)
                            }
                        },
                        navigationIcon = {
                            Surface(
                                onClick = { scope.launch { drawerState.open() } },
                                shape = RoundedCornerShape(12.dp),
                                color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f),
                                modifier = Modifier.padding(start = 12.dp).size(40.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(Icons.Filled.Menu, "Menu", modifier = Modifier.size(24.dp))
                                }
                            }
                        },
                        actions = {
                            if (isRunning) {
                                Surface(
                                    color = (if (latency < 150) Color(0xFF4CAF50) else Color(0xFFFFC107)).copy(alpha = 0.15f),
                                    shape = RoundedCornerShape(12.dp),
                                    modifier = Modifier.padding(end = 12.dp).height(40.dp),
                                    border = BorderStroke(1.dp, (if (latency < 150) Color(0xFF4CAF50) else Color(0xFFFFC107)).copy(alpha = 0.3f))
                                ) {
                                    Row(
                                        modifier = Modifier.padding(horizontal = 12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Box(Modifier.size(8.dp).background(if (latency < 150) Color(0xFF4CAF50) else Color(0xFFFFC107), CircleShape))
                                        Spacer(Modifier.width(8.dp))
                                        Text("${latency}ms", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                                    }
                                }
                            } else {
                                Spacer(Modifier.width(52.dp))
                            }
                        },
                        colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
                    )
                },
                bottomBar = {
                    Surface(
                        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.8f),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp)),
                        tonalElevation = 0.dp 
                    ) {
                        Row(
                            modifier = Modifier
                                .windowInsetsPadding(WindowInsets.navigationBars)
                                .height(64.dp)
                                .fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceEvenly,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            listOf(
                                Icons.Filled.Dashboard to stringResource(R.string.tab_app),
                                Icons.AutoMirrored.Filled.ListAlt to stringResource(R.string.tab_activity),
                                Icons.Filled.BarChart to stringResource(R.string.tab_stats)
                            ).forEachIndexed { index, pair ->
                                val selected = currentTab == index
                                val color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                                val bgColor = if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f) else Color.Transparent
                                
                                Column(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(16.dp))
                                        .clickable { currentTab = index }
                                        .background(bgColor)
                                        .padding(horizontal = 24.dp, vertical = 8.dp),
                                    horizontalAlignment = Alignment.CenterHorizontally,
                                    verticalArrangement = Arrangement.Center
                                ) {
                                    Icon(pair.first, null, tint = color, modifier = Modifier.size(24.dp))
                                }
                            }
                        }
                    }
                }
            ) { contentPadding ->
                Box(modifier = Modifier
                    .padding(contentPadding)
                    .consumeWindowInsets(contentPadding)
                    .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
                    .fillMaxSize()) {
                    if (isRunning) {
                        Box(Modifier.fillMaxSize().background(
                            Brush.radialGradient(
                                colors = listOf(MaterialTheme.colorScheme.primary.copy(alpha = 0.05f), Color.Transparent),
                                center = androidx.compose.ui.geometry.Offset(500f, 500f),
                                radius = 1000f
                            )
                        ))
                    }

                    when (currentTab) {
                        0 -> DashboardScreen(
                            isRunning = isRunning,
                            latency = latency,
                            resolverUrl = pendingResolverUrl,
                            bootstrapDns = pendingBootstrapDns,
                            listenPort = pendingListenPort,
                            profiles = profiles,
                            selectedProfileIndex = selectedProfileIndex,
                            onProfileSelect = { index ->
                                selectedProfileIndex = index
                                if (index < profiles.size - 1) {
                                    val profile = profiles[index]
                                    pendingResolverUrl = profile.url
                                    pendingBootstrapDns = profile.bootstrap
                                }
                            },
                            onUrlChange = { pendingResolverUrl = it },
                            onBootstrapChange = { pendingBootstrapDns = it },
                            onPortChange = { pendingListenPort = it },
                            onToggle = onToggle
                        )
                        1 -> LogScreen(logs)
                        2 -> StatsScreen(stats)
                    }
                }
            }
        }
    }

    private fun startProxyService(resolverUrl: String, listenPort: String, bootstrapDns: String, allowIpv6: Boolean, cacheTtl: String, tcpLimit: String, pollInterval: String, useHttp3: Boolean, heartbeatEnabled: Boolean, heartbeatDomain: String, heartbeatInterval: String) {
        val intent = Intent(this, ProxyService::class.java).apply {
            putExtra("resolverUrl", resolverUrl)
            putExtra("listenPort", listenPort.toIntOrNull() ?: 5053)
            putExtra("bootstrapDns", bootstrapDns)
            putExtra("allowIpv6", allowIpv6)
            putExtra("cacheTtl", cacheTtl.toLongOrNull() ?: 300L)
            putExtra("tcpLimit", tcpLimit.toIntOrNull() ?: 20)
            putExtra("pollInterval", pollInterval.toLongOrNull() ?: 120L)
            putExtra("useHttp3", useHttp3)
            putExtra("heartbeatEnabled", heartbeatEnabled)
            putExtra("heartbeatDomain", heartbeatDomain)
            putExtra("heartbeatInterval", heartbeatInterval.toLongOrNull() ?: 10L)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent)
        else startService(intent)
    }
}
