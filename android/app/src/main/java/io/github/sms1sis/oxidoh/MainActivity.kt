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
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.addOutline
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.ShaderBrush
import androidx.compose.ui.geometry.center
import android.graphics.Matrix
import android.graphics.SweepGradient
import androidx.compose.ui.graphics.toArgb
import androidx.core.content.ContextCompat
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
                    statusBarStyle = androidx.activity.SystemBarStyle.auto(
                        android.graphics.Color.TRANSPARENT,
                        android.graphics.Color.TRANSPARENT,
                    ) { darkTheme },
                    navigationBarStyle = androidx.activity.SystemBarStyle.auto(
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
        var autoStart by remember { mutableStateOf(prefs.getBoolean("auto_start", false)) }
        var allowIpv6 by remember { mutableStateOf(prefs.getBoolean("allow_ipv6", false)) }
        var cacheTtl by remember { mutableStateOf(prefs.getString("cache_ttl", "300") ?: "300") }
        var heartbeatEnabled by remember { mutableStateOf(prefs.getBoolean("heartbeat_enabled", true)) }
        var heartbeatDomain by remember { mutableStateOf(prefs.getString("heartbeat_domain", "google.com") ?: "google.com") }
        var heartbeatInterval by remember { mutableStateOf(prefs.getString("heartbeat_interval", "10") ?: "10") }

        // Debounced heartbeat settings
        var pendingHeartbeatDomain by remember { mutableStateOf(heartbeatDomain) }
        var pendingHeartbeatInterval by remember { mutableStateOf(heartbeatInterval) }
        var pendingCacheTtl by remember { mutableStateOf(cacheTtl) }

        val profiles = listOf(
            DnsProfile("Cloudflare via Fastly", "https://odoh.cloudflare-dns.com/dns-query https://odoh-relay.edgecompute.app/", "151.101.1.51,1.1.1.1"),
            DnsProfile("Cloudflare via Tiarap JP", "https://odoh.cloudflare-dns.com/dns-query https://odoh-jp.tiarap.org/proxy", "172.67.140.94,1.1.1.1"),
            DnsProfile("Tiarap Direct", "https://doh.tiar.app/odoh", "174.138.29.175"),
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
                    android.widget.Toast.makeText(context, "Disable battery optimization in Settings for better reliability", android.widget.Toast.LENGTH_LONG).show()
                    prefs.edit().putBoolean("battery_prompted", true).apply()
                }
            }
            
            while (true) {
                isRunning = ProxyService.isProxyRunning
                if (isRunning) {
                    val newLat = ProxyService.getLatency()
                    if (newLat > 0 && newLat != latency) {
                        Log.d("OxidOH", "UI Latency update: $newLat ms")
                        latency = newLat
                    }
                    logs = ProxyService.getLogs()
                }
                delay(1000)
            }
        }

        // Debounce effect for all settings
        LaunchedEffect(pendingHeartbeatDomain, pendingHeartbeatInterval, pendingResolverUrl, pendingBootstrapDns, pendingListenPort, allowIpv6, pendingCacheTtl) {
            delay(1500) // Wait for 1.5s after user stops typing
            
            var changed = false
            if (heartbeatDomain != pendingHeartbeatDomain) { heartbeatDomain = pendingHeartbeatDomain; changed = true }
            if (heartbeatInterval != pendingHeartbeatInterval) { heartbeatInterval = pendingHeartbeatInterval; changed = true }
            if (resolverUrl != pendingResolverUrl) { resolverUrl = pendingResolverUrl; changed = true }
            if (bootstrapDns != pendingBootstrapDns) { bootstrapDns = pendingBootstrapDns; changed = true }
            if (listenPort != pendingListenPort) { listenPort = pendingListenPort; changed = true }
            if (cacheTtl != pendingCacheTtl) { cacheTtl = pendingCacheTtl; changed = true }

            if (changed) {
                val finalResolverUrl = pendingResolverUrl
                val finalBootstrapDns = pendingBootstrapDns
                val finalListenPort = pendingListenPort
                val finalCacheTtl = pendingCacheTtl

                prefs.edit()
                    .putString("heartbeat_domain", heartbeatDomain)
                    .putString("heartbeat_interval", heartbeatInterval)
                    .putString("resolver_url", finalResolverUrl)
                    .putString("bootstrap_dns", finalBootstrapDns)
                    .putString("listen_port", finalListenPort)
                    .putBoolean("allow_ipv6", allowIpv6)
                    .putString("cache_ttl", finalCacheTtl)
                    .putInt("selected_profile", selectedProfileIndex)
                    .apply()
                
                if (isRunning) {
                    startProxyService(finalResolverUrl, finalListenPort, finalBootstrapDns, allowIpv6, finalCacheTtl, heartbeatEnabled, heartbeatDomain, heartbeatInterval)
                }
            }
        }

        val vpnPermissionLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == RESULT_OK) {
                startProxyService(resolverUrl, listenPort, bootstrapDns, allowIpv6, cacheTtl, heartbeatEnabled, heartbeatDomain, heartbeatInterval)
                isRunning = true
            }
        }

        if (showAboutDialog) {
            AboutDialog(onDismiss = { showAboutDialog = false }, uriHandler = uriHandler)
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
                    startProxyService(resolverUrl, listenPort, bootstrapDns, allowIpv6, cacheTtl, heartbeatEnabled, heartbeatDomain, heartbeatInterval)
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
                                startProxyService(resolverUrl, listenPort, bootstrapDns, enabled, cacheTtl, heartbeatEnabled, heartbeatDomain, heartbeatInterval)
                            }
                        },
                        onCacheTtlChange = { pendingCacheTtl = it },
                        onHeartbeatChange = { enabled ->
                            heartbeatEnabled = enabled
                            prefs.edit().putBoolean("heartbeat_enabled", enabled).apply()
                            if (isRunning) {
                                startProxyService(resolverUrl, listenPort, bootstrapDns, allowIpv6, cacheTtl, enabled, heartbeatDomain, heartbeatInterval)
                            }
                        },
                        onHeartbeatDomainChange = { pendingHeartbeatDomain = it },
                        onHeartbeatIntervalChange = { pendingHeartbeatInterval = it },
                        isIgnoringBatteryOptimizations = isIgnoringBatteryOptimizations,
                        onRequestBatteryOptimization = { requestBatteryOptimization() },
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
                                Icons.Filled.Dashboard to "App",
                                Icons.AutoMirrored.Filled.ListAlt to "Activity"
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

                    if (currentTab == 0) {
                        DashboardScreen(
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
                    } else {
                        LogScreen(logs)
                    }
                }
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun DashboardScreen(
        isRunning: Boolean,
        latency: Int,
        resolverUrl: String,
        bootstrapDns: String,
        listenPort: String,
        profiles: List<DnsProfile>,
        selectedProfileIndex: Int,
        onProfileSelect: (Int) -> Unit,
        onUrlChange: (String) -> Unit,
        onBootstrapChange: (String) -> Unit,
        onPortChange: (String) -> Unit,
        onToggle: () -> Unit
    ) {
        val infiniteTransition = rememberInfiniteTransition(label = "cardNeon")
        val rotation by infiniteTransition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(6000, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "rotation"
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .padding(horizontal = 24.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(32.dp, Alignment.CenterVertically)
        ) {
            StatusHero(isRunning, latency, onToggle)

            // Main Settings Card
            val cardShape = RoundedCornerShape(32.dp)
            val borderColor = MaterialTheme.colorScheme.primary

            ElevatedCard(
                modifier = Modifier
                    .fillMaxWidth()
                    .drawWithContent {
                        drawContent()
                        val outline = cardShape.createOutline(size, layoutDirection, this)
                        val path = Path().apply { addOutline(outline) }
                        
                        val strokeWidth = 2.dp.toPx()
                        
                        drawPath(
                            path = path,
                            color = borderColor.copy(alpha = 0.15f),
                            style = Stroke(width = strokeWidth)
                        )

                        val shader = SweepGradient(
                            size.center.x, size.center.y,
                            intArrayOf(
                                android.graphics.Color.TRANSPARENT,
                                borderColor.toArgb(),
                                android.graphics.Color.TRANSPARENT,
                                android.graphics.Color.TRANSPARENT,
                                borderColor.toArgb(),
                                android.graphics.Color.TRANSPARENT,
                                android.graphics.Color.TRANSPARENT
                            ),
                            floatArrayOf(0.0f, 0.1f, 0.2f, 0.5f, 0.6f, 0.7f, 1.0f)
                        )
                        val matrix = Matrix()
                        matrix.postRotate(rotation, size.center.x, size.center.y)
                        shader.setLocalMatrix(matrix)

                        drawPath(
                            path = path,
                            brush = ShaderBrush(shader),
                            style = Stroke(width = strokeWidth)
                        )
                    },
                shape = cardShape,
                colors = CardDefaults.elevatedCardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                ),
                elevation = CardDefaults.elevatedCardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Surface(
                                color = MaterialTheme.colorScheme.primaryContainer,
                                shape = CircleShape,
                                modifier = Modifier.size(32.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(Icons.Default.Tune, null, modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.onPrimaryContainer)
                                }
                            }
                            Spacer(Modifier.width(12.dp))
                            Text("Configuration", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        }
                        
                        var expanded by remember { mutableStateOf(false) }
                        Column {
                            Text("Service Provider", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                            Spacer(Modifier.height(4.dp))
                            OutlinedCard(
                                onClick = { expanded = true },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(16.dp)
                            ) {
                                Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                                    Text(profiles[selectedProfileIndex].name, modifier = Modifier.weight(1f), fontWeight = FontWeight.Medium)
                                    Icon(Icons.Default.KeyboardArrowDown, null)
                                }
                            }
                            DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                                profiles.forEachIndexed { index, profile ->
                                    DropdownMenuItem(
                                        text = { Text(profile.name) },
                                        onClick = { onProfileSelect(index); expanded = false }
                                    )
                                }
                            }
                        }

                        OutlinedTextField(
                            value = resolverUrl,
                            onValueChange = onUrlChange,
                            label = { Text("ODoH Target & Proxy URLs") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            singleLine = true,
                            enabled = selectedProfileIndex == profiles.size - 1
                        )
                        
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            OutlinedTextField(
                                value = bootstrapDns,
                                onValueChange = onBootstrapChange,
                                label = { Text("Bootstrap") },
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(16.dp),
                                singleLine = true,
                                enabled = selectedProfileIndex == profiles.size - 1
                            )
                            OutlinedTextField(
                                value = listenPort,
                                onValueChange = onPortChange,
                                label = { Text("Port") },
                                modifier = Modifier.weight(0.7f),
                                shape = RoundedCornerShape(16.dp),
                                singleLine = true
                            )
                        }
                }
            }
        }
    }

    @Composable
    fun LogScreen(logs: Array<String>) {
        val context = LocalContext.current
        val listState = androidx.compose.foundation.lazy.rememberLazyListState()
        
        LaunchedEffect(logs.size) {
            if (logs.isNotEmpty()) {
                listState.animateScrollToItem(logs.size - 1)
            }
        }

        Column(modifier = Modifier.fillMaxSize().padding(vertical = 24.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Network Activity", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Surface(
                    onClick = { saveLogsToFile(context, logs) },
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = CircleShape,
                    modifier = Modifier.size(40.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(Icons.Default.FileDownload, null, modifier = Modifier.size(20.dp))
                    }
                }
            }
            Spacer(Modifier.height(20.dp))
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(horizontal = 12.dp), 
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f))
            ) {
                if (logs.isEmpty()) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Default.CloudQueue, null, modifier = Modifier.size(48.dp), tint = MaterialTheme.colorScheme.outline)
                            Spacer(Modifier.height(12.dp))
                            Text("No activity detected", color = MaterialTheme.colorScheme.outline)
                        }
                    }
                } else {
                    androidx.compose.foundation.lazy.LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize().padding(16.dp),
                        contentPadding = PaddingValues(bottom = 16.dp)
                    ) {
                        items(logs.size) { index ->
                            Text(
                                text = logs[index],
                                style = androidx.compose.ui.text.TextStyle(
                                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                    fontSize = 12.sp
                                ),
                                modifier = Modifier.padding(vertical = 8.dp)
                            )
                            if (index < logs.size - 1) {
                                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                            }
                        }
                    }
                }
            }
        }
    }

    private fun saveLogsToFile(context: android.content.Context, logs: Array<String>) {
        if (logs.isEmpty()) return
        try {
            val fileName = "OxidOH_Logs_${System.currentTimeMillis()}.txt"
            val downloadsDir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
            val file = java.io.File(downloadsDir, fileName)
            java.io.FileOutputStream(file).use { out ->
                logs.forEach { line -> out.write((line + "\n").toByteArray()) }
            }
            android.media.MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), null, null)
            android.widget.Toast.makeText(context, "Saved to Downloads", android.widget.Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Log.e("OxidOH", "Failed to save logs", e)
        }
    }

    @Composable
    fun DrawerContent(
        themeMode: String,
        autoStart: Boolean,
        allowIpv6: Boolean,
        cacheTtl: String,
        heartbeatEnabled: Boolean,
        heartbeatDomain: String,
        heartbeatInterval: String,
        onThemeChange: (String) -> Unit,
        notchMode: Boolean,
        onNotchModeChange: (Boolean) -> Unit,
        onAutoStartChange: (Boolean) -> Unit,
        onAllowIpv6Change: (Boolean) -> Unit,
        onCacheTtlChange: (String) -> Unit,
        onHeartbeatChange: (Boolean) -> Unit,
        onHeartbeatDomainChange: (String) -> Unit,
        onHeartbeatIntervalChange: (String) -> Unit,
        isIgnoringBatteryOptimizations: Boolean,
        onRequestBatteryOptimization: () -> Unit,
        onAboutClick: () -> Unit,
        onClose: () -> Unit
    ) {
        val context = LocalContext.current
        Column(modifier = Modifier.padding(24.dp).verticalScroll(rememberScrollState())) {
            Text("Preferences", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Spacer(modifier = Modifier.height(32.dp))
            
            Text("Appearance", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(12.dp))
            listOf("Light", "Dark", "AMOLED", "System").forEach { mode ->
                NavigationDrawerItem(
                    label = { Text(mode) },
                    selected = themeMode == mode,
                    onClick = { onThemeChange(mode) },
                    shape = RoundedCornerShape(16.dp)
                )
            }
            
            Spacer(Modifier.height(16.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Notch Support", fontWeight = FontWeight.Bold)
                    Text("Edge-to-edge display", style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = notchMode, onCheckedChange = onNotchModeChange)
            }
            
            HorizontalDivider(modifier = Modifier.padding(vertical = 24.dp))
            
            Text("Service", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(16.dp))

            if (!isIgnoringBatteryOptimizations) {
                Surface(
                    onClick = onRequestBatteryOptimization,
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.BatteryAlert, null, tint = MaterialTheme.colorScheme.error)
                        Spacer(Modifier.width(16.dp))
                        Column {
                            Text("Battery Optimization", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onErrorContainer)
                            Text("Service might be killed in background. Tap to fix.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onErrorContainer)
                        }
                    }
                }
                Spacer(Modifier.height(16.dp))
            }
            
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Auto-start", fontWeight = FontWeight.Bold)
                    Text("Enable protection on boot", style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = autoStart, onCheckedChange = onAutoStartChange)
            }
            
            Spacer(Modifier.height(24.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("IPv6 Support", fontWeight = FontWeight.Bold)
                    Text("Enable IPv6 DNS interception", style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = allowIpv6, onCheckedChange = onAllowIpv6Change)
            }

            Spacer(Modifier.height(24.dp))

            Text("DNS Cache TTL (seconds)", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = cacheTtl,
                onValueChange = onCacheTtlChange,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                singleLine = true,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Number)
            )

            Spacer(Modifier.height(24.dp))
            
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Latency Pulse", fontWeight = FontWeight.Bold)
                    Text("Keep stats fresh in background", style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = heartbeatEnabled, onCheckedChange = onHeartbeatChange)
            }
            
            if (heartbeatEnabled) {
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = heartbeatDomain,
                    onValueChange = onHeartbeatDomainChange,
                    label = { Text("Ping Domain") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    singleLine = true
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = heartbeatInterval,
                    onValueChange = onHeartbeatIntervalChange,
                    label = { Text("Interval (sec)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    singleLine = true,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Number)
                )
            }
            
            Spacer(Modifier.height(16.dp))
            NavigationDrawerItem(
                label = { Text("Clear DNS Cache") },
                selected = false,
                icon = { Icon(Icons.Default.DeleteSweep, null) },
                onClick = { 
                    ProxyService.clearCache()
                    android.widget.Toast.makeText(context, "DNS Cache Cleared", android.widget.Toast.LENGTH_SHORT).show()
                    onClose() 
                },
                shape = RoundedCornerShape(16.dp)
            )

            Spacer(Modifier.height(40.dp))
            NavigationDrawerItem(
                label = { Text("About Application") },
                selected = false,
                icon = { Icon(Icons.Default.Info, null) },
                onClick = { onAboutClick(); onClose() },
                shape = RoundedCornerShape(16.dp)
            )
        }
    }

    @Composable
    fun StatusHero(isRunning: Boolean, latency: Int, onToggle: () -> Unit) {
        val haptic = LocalHapticFeedback.current
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Box(contentAlignment = Alignment.Center) {
                val color = if (isRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
                
                Box(Modifier.size(240.dp).clip(CircleShape).background(color.copy(alpha = if (isRunning) 0.03f else 0.1f)))
                
                if (isRunning) {
                    val infiniteTransition = rememberInfiniteTransition()
                    val rotation by infiniteTransition.animateFloat(
                        initialValue = 0f,
                        targetValue = 360f,
                        animationSpec = infiniteRepeatable(
                            animation = tween(4000, easing = LinearEasing),
                            repeatMode = RepeatMode.Restart
                        )
                    )
                    val pulseScale1 by infiniteTransition.animateFloat(
                        initialValue = 1f,
                        targetValue = 1.4f,
                        animationSpec = infiniteRepeatable(
                            animation = tween(2000, easing = FastOutSlowInEasing),
                            repeatMode = RepeatMode.Reverse
                        )
                    )
                    val pulseAlpha1 by infiniteTransition.animateFloat(
                        initialValue = 0.1f,
                        targetValue = 0.05f,
                        animationSpec = infiniteRepeatable(
                            animation = tween(2000, easing = FastOutSlowInEasing),
                            repeatMode = RepeatMode.Reverse
                        )
                    )

                    Box(
                        Modifier
                            .size(190.dp)
                            .rotate(rotation)
                            .border(
                                width = 3.dp,
                                brush = Brush.sweepGradient(
                                    colors = listOf(Color.Transparent, color, Color.Transparent)
                                ),
                                shape = CircleShape
                            )
                    )

                    Box(
                        Modifier
                            .size(160.dp)
                            .scale(pulseScale1)
                            .clip(CircleShape)
                            .background(color.copy(alpha = pulseAlpha1))
                    )
                }

                var isPressed by remember { mutableStateOf(false) }
                val scale by animateFloatAsState(
                    targetValue = if (isPressed) 0.92f else 1f,
                    animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy),
                    label = "clickScale"
                )

                Surface(
                    onClick = { 
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onToggle()
                    },
                    shape = CircleShape,
                    color = if (isRunning) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                    modifier = Modifier
                        .size(140.dp)
                        .scale(scale)
                        .shadow(if (isRunning) 12.dp else 0.dp, CircleShape)
                        .border(if (isRunning) 0.dp else 2.dp, color.copy(alpha = 0.5f), CircleShape)
                ) {
                    val innerTransition = rememberInfiniteTransition()
                    val scanPos by innerTransition.animateFloat(
                        initialValue = 0f,
                        targetValue = 1f,
                        animationSpec = infiniteRepeatable(
                            animation = tween(3000, easing = LinearEasing),
                            repeatMode = RepeatMode.Restart
                        )
                    )
                    val lockAlpha by innerTransition.animateFloat(
                        initialValue = 0.4f,
                        targetValue = 1f,
                        animationSpec = infiniteRepeatable(
                            animation = tween(1500, easing = FastOutSlowInEasing),
                            repeatMode = RepeatMode.Reverse
                        )
                    )

                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier.drawWithContent {
                            drawContent()
                            if (isRunning) {
                                val y = size.height * scanPos
                                drawLine(
                                    brush = Brush.verticalGradient(
                                        colors = listOf(Color.Transparent, color.copy(alpha = 0.5f), Color.Transparent),
                                        startY = y - 20,
                                        endY = y + 20
                                    ),
                                    start = Offset(0f, y),
                                    end = Offset(size.width, y),
                                    strokeWidth = 2.dp.toPx()
                                )
                            }
                        }
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            modifier = Modifier.size(82.dp).alpha(if (isRunning) 1f else 0.5f),
                            tint = if (isRunning) MaterialTheme.colorScheme.onPrimaryContainer else color
                        )
                        
                        if (isRunning) {
                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = null,
                                modifier = Modifier.size(32.dp).graphicsLayer(alpha = lockAlpha),
                                tint = MaterialTheme.colorScheme.primary
                            )
                            
                            val orbitRotation by innerTransition.animateFloat(
                                initialValue = 0f,
                                targetValue = 360f,
                                animationSpec = infiniteRepeatable(
                                    animation = tween(2500, easing = LinearEasing),
                                    repeatMode = RepeatMode.Restart
                                )
                            )
                            Box(
                                Modifier
                                    .size(60.dp)
                                    .rotate(orbitRotation)
                            ) {
                                Box(
                                    Modifier
                                        .size(6.dp)
                                        .align(Alignment.TopCenter)
                                        .background(color, CircleShape)
                                        .shadow(4.dp, CircleShape)
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                if (isRunning) "SYSTEM PROTECTED" else "UNPROTECTED", 
                style = MaterialTheme.typography.titleMedium, 
                fontWeight = FontWeight.ExtraBold,
                letterSpacing = 2.sp,
                color = if (isRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
            )

            Spacer(modifier = Modifier.height(12.dp))
            
            Text(
                if (isRunning) "TAP SHIELD TO DISCONNECT" else "TAP SHIELD TO CONNECT", 
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold, 
                color = if (isRunning) MaterialTheme.colorScheme.primary.copy(alpha = 0.7f) else Color(0xFFE91E63).copy(alpha = 0.7f),
                letterSpacing = 1.5.sp
            )
        }
    }

    @Composable
    fun AboutDialog(onDismiss: () -> Unit, uriHandler: androidx.compose.ui.platform.UriHandler) {
        val context = LocalContext.current
        val scope = rememberCoroutineScope()
        var checkingUpdate by remember { mutableStateOf(false) }

        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text("About OxidOH") },
            text = {
                Column {
                    Text("Version: v0.1.0", fontWeight = FontWeight.Bold)
                    Text("Developer: sms1sis")
                    Spacer(Modifier.height(16.dp))
                    
                    Button(
                        onClick = {
                            scope.launch {
                                checkingUpdate = true
                                checkForUpdates(context, uriHandler)
                                checkingUpdate = false
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !checkingUpdate,
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        if (checkingUpdate) {
                            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                            Spacer(Modifier.width(8.dp))
                            Text("Checking...")
                        } else {
                            Icon(Icons.Default.Update, null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Check for Updates")
                        }
                    }

                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = { uriHandler.openUri("https://github.com/sms1sis/OxidOH") }) {
                        Text("View on GitHub")
                    }
                }
            },
            confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } }
        )
    }

    private suspend fun checkForUpdates(context: android.content.Context, uriHandler: androidx.compose.ui.platform.UriHandler) {
        val repoUrl = "https://api.github.com/repos/sms1sis/OxidOH/releases/latest"
        val currentVersion = "v0.1.0"

        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                val connection = java.net.URL(repoUrl).openConnection() as java.net.HttpURLConnection
                connection.requestMethod = "GET"
                connection.setRequestProperty("Accept", "application/vnd.github.v3+json")
                connection.connectTimeout = 5000
                connection.readTimeout = 5000

                if (connection.responseCode == 200) {
                    val response = connection.inputStream.bufferedReader().use { it.readText() }
                    val tagName = response.substringAfter("\"tag_name\":\"").substringBefore("\"")
                    
                    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                        if (tagName != currentVersion && tagName.startsWith("v")) {
                            android.widget.Toast.makeText(context, "New version available: $tagName", android.widget.Toast.LENGTH_LONG).show()
                            uriHandler.openUri("https://github.com/sms1sis/OxidOH/releases/latest")
                        } else {
                            android.widget.Toast.makeText(context, "You are on the latest version", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            } catch (e: Exception) {
                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                    android.widget.Toast.makeText(context, "Failed to check for updates", android.widget.Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun startProxyService(resolverUrl: String, listenPort: String, bootstrapDns: String, allowIpv6: Boolean, cacheTtl: String, heartbeatEnabled: Boolean, heartbeatDomain: String, heartbeatInterval: String) {
        val intent = Intent(this, ProxyService::class.java).apply {
            putExtra("resolverUrl", resolverUrl)
            putExtra("listenPort", listenPort.toIntOrNull() ?: 5053)
            putExtra("bootstrapDns", bootstrapDns)
            putExtra("allowIpv6", allowIpv6)
            putExtra("cacheTtl", cacheTtl.toLongOrNull() ?: 300L)
            putExtra("heartbeatEnabled", heartbeatEnabled)
            putExtra("heartbeatDomain", heartbeatDomain)
            putExtra("heartbeatInterval", heartbeatInterval.toLongOrNull() ?: 10L)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent)
        else startService(intent)
    }
}

data class DnsProfile(val name: String, val url: String, val bootstrap: String)
