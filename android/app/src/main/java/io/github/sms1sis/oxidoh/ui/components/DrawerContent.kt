package io.github.sms1sis.oxidoh.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.sms1sis.oxidoh.ProxyService
import io.github.sms1sis.oxidoh.R
import io.github.sms1sis.oxidoh.ui.theme.*

@Composable
fun DrawerContent(
    themeMode: String,
    autoStart: Boolean,
    allowIpv6: Boolean,
    cacheTtl: String,
    tcpLimit: String,
    pollInterval: String,
    useHttp3: Boolean,
    heartbeatEnabled: Boolean,
    heartbeatDomain: String,
    heartbeatInterval: String,
    onThemeChange: (String) -> Unit,
    notchMode: Boolean,
    onNotchModeChange: (Boolean) -> Unit,
    onAutoStartChange: (Boolean) -> Unit,
    onAllowIpv6Change: (Boolean) -> Unit,
    onCacheTtlChange: (String) -> Unit,
    onTcpLimitChange: (String) -> Unit,
    onPollIntervalChange: (String) -> Unit,
    onHttp3Change: (Boolean) -> Unit,
    onHeartbeatChange: (Boolean) -> Unit,
    onHeartbeatDomainChange: (String) -> Unit,
    onHeartbeatIntervalChange: (String) -> Unit,
    isIgnoringBatteryOptimizations: Boolean,
    onRequestBatteryOptimization: () -> Unit,
    onAppExclusionClick: () -> Unit,
    onAboutClick: () -> Unit,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val focusManager = LocalFocusManager.current

    Column(modifier = Modifier
        .background(MaterialTheme.colorScheme.background)
        .fillMaxHeight()
        .verticalScroll(rememberScrollState())
        .padding(horizontal = 20.dp, vertical = 28.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp)
    ) {
        // ── Header ────────────────────────────────────────────────────────────
        Text("SYS_CONFIG", style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.primary, letterSpacing = 4.sp)
        Text("// OPERATOR PARAMETERS", style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 2.sp)
        Spacer(Modifier.height(24.dp))

        // ── Theme ─────────────────────────────────────────────────────────────
        DrawerSection("DISPLAY_MODE")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("Dark" to "DARK", "AMOLED" to "VOID", "Light" to "LITE", "System" to "AUTO")
                .forEach { (mode, label) ->
                    val selected = themeMode == mode
                    Surface(
                        onClick = { onThemeChange(mode) },
                        shape = RoundedCornerShape(2.dp),
                        color = if (selected) MaterialTheme.colorScheme.primary.copy(0.15f) else Color.Transparent,
                        modifier = Modifier
                            .weight(1f)
                            .border(1.dp,
                                if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                                RoundedCornerShape(2.dp))
                    ) {
                        Box(contentAlignment = Alignment.Center, modifier = Modifier.padding(8.dp)) {
                            Text(label, style = MaterialTheme.typography.labelSmall,
                                color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                letterSpacing = 1.sp, fontSize = 10.sp,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal)
                        }
                    }
                }
        }


        Spacer(Modifier.height(20.dp))

        // ── Toggles ───────────────────────────────────────────────────────────
        DrawerSection("SYSTEM_FLAGS")
        DrawerToggle("EDGE_TO_EDGE", "Notch / display cutout support", notchMode, onNotchModeChange)
        DrawerToggle("AUTO_START", "Activate on device boot", autoStart, onAutoStartChange)
        DrawerToggle("IPV6_STACK", "Enable IPv6 DNS interception", allowIpv6, onAllowIpv6Change)
        DrawerToggle("HTTP3_QUIC", "Use QUIC transport protocol", useHttp3, onHttp3Change)
        DrawerToggle("LATENCY_PULSE", "Background RTT monitoring", heartbeatEnabled, onHeartbeatChange)

        if (heartbeatEnabled) {
            Spacer(Modifier.height(8.dp))
            DrawerTextField("PULSE_TARGET", heartbeatDomain, onHeartbeatDomainChange,
                androidx.compose.ui.text.input.KeyboardType.Uri, focusManager)
            Spacer(Modifier.height(8.dp))
            DrawerTextField("PULSE_INTERVAL_SEC", heartbeatInterval, onHeartbeatIntervalChange,
                androidx.compose.ui.text.input.KeyboardType.Number, focusManager)
        }

        Spacer(Modifier.height(20.dp))

        // ── Advanced ──────────────────────────────────────────────────────────
        DrawerSection("ADVANCED_PARAMS")
        DrawerTextField("CACHE_TTL_SEC", cacheTtl, onCacheTtlChange,
            androidx.compose.ui.text.input.KeyboardType.Number, focusManager)
        Spacer(Modifier.height(8.dp))
        DrawerTextField("TCP_CONN_LIMIT", tcpLimit, onTcpLimitChange,
            androidx.compose.ui.text.input.KeyboardType.Number, focusManager)
        Spacer(Modifier.height(8.dp))
        DrawerTextField("BOOTSTRAP_REFRESH_SEC", pollInterval, onPollIntervalChange,
            androidx.compose.ui.text.input.KeyboardType.Number, focusManager)

        Spacer(Modifier.height(20.dp))

        // ── Actions ───────────────────────────────────────────────────────────
        DrawerSection("SYSTEM_ACTIONS")

        if (!isIgnoringBatteryOptimizations) {
            DrawerActionRow(Icons.Default.BatteryAlert, "BATTERY_DOZE",
                "Service may be killed — tap to whitelist", CrimsonThreat,
                onRequestBatteryOptimization)
            Spacer(Modifier.height(8.dp))
        }

        DrawerActionRow(Icons.Default.Apps, "APP_EXCLUSIONS",
            "Route specific apps outside proxy", CyanPrimary
        ) { onAppExclusionClick(); onClose() }

        Spacer(Modifier.height(8.dp))

        DrawerActionRow(Icons.Default.DeleteSweep, "FLUSH_DNS_CACHE",
            "Invalidate all cached responses", AmberAlert
        ) {
            ProxyService.clearCache()
            android.widget.Toast.makeText(context,
                context.getString(R.string.dns_cache_cleared), android.widget.Toast.LENGTH_SHORT).show()
            onClose()
        }

        Spacer(Modifier.height(8.dp))

        DrawerActionRow(Icons.Default.Info, "ABOUT_SYSTEM",
            "Version info and project links", GhostText
        ) { onAboutClick(); onClose() }

        Spacer(Modifier.height(32.dp))
    }
}

@Composable
private fun DrawerSection(label: String) {
    Row(verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(vertical = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Box(Modifier.width(2.dp).height(10.dp).background(MaterialTheme.colorScheme.primary))
        Text(label, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary, letterSpacing = 3.sp)
        Box(Modifier.weight(1f).height(0.5.dp).background(MaterialTheme.colorScheme.outlineVariant))
    }
}

@Composable
private fun DrawerToggle(label: String, desc: String, checked: Boolean, onChanged: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium,
                color = if (checked) MaterialTheme.colorScheme.onBackground else MaterialTheme.colorScheme.onSurfaceVariant,
                letterSpacing = 1.sp, fontWeight = FontWeight.Bold)
            Text(desc, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(0.6f), fontSize = 10.sp)
        }
        Switch(
            checked = checked, onCheckedChange = onChanged,
            colors = SwitchDefaults.colors(
                checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                checkedTrackColor = MaterialTheme.colorScheme.primary,
                uncheckedThumbColor = MaterialTheme.colorScheme.onSurfaceVariant,
                uncheckedTrackColor = MaterialTheme.colorScheme.outlineVariant
            )
        )
    }
}

@Composable
private fun DrawerTextField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    keyboardType: androidx.compose.ui.text.input.KeyboardType,
    focusManager: androidx.compose.ui.focus.FocusManager
) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 2.sp, fontSize = 10.sp)
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(2.dp),
            singleLine = true,
            textStyle = MaterialTheme.typography.bodySmall.copy(color = MaterialTheme.colorScheme.onBackground),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor    = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor  = MaterialTheme.colorScheme.outlineVariant,
                focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                cursorColor = MaterialTheme.colorScheme.primary,
            ),
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = keyboardType,
                imeAction = androidx.compose.ui.text.input.ImeAction.Done
            ),
            keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                onDone = { focusManager.clearFocus() }
            )
        )
    }
}


@Composable
private fun DrawerActionRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    desc: String,
    color: Color,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        color = color.copy(0.06f),
        shape = RoundedCornerShape(2.dp),
        modifier = Modifier.fillMaxWidth()
            .drawBehind {
                drawLine(color.copy(0.5f), Offset(0f, 0f), Offset(0f, size.height), 2.dp.toPx())
            }
    ) {
        Row(modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(icon, null, tint = color, modifier = Modifier.size(18.dp))
            Column {
                Text(label, style = MaterialTheme.typography.labelMedium,
                    color = color, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                Text(desc, style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(0.6f), fontSize = 10.sp)
            }
        }
    }
}
