package io.github.sms1sis.oxidoh.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.BatteryAlert
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.sms1sis.oxidoh.ProxyService
import io.github.sms1sis.oxidoh.R

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
    Column(modifier = Modifier.padding(24.dp).verticalScroll(rememberScrollState())) {
        Text(stringResource(R.string.preferences), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(32.dp))
        
        Text(stringResource(R.string.appearance), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(12.dp))
        listOf(
            stringResource(R.string.theme_light), 
            stringResource(R.string.theme_dark), 
            stringResource(R.string.theme_amoled), 
            stringResource(R.string.theme_system)
        ).zip(listOf("Light", "Dark", "AMOLED", "System")).forEach { (label, mode) ->
            NavigationDrawerItem(
                label = { Text(label) },
                selected = themeMode == mode,
                onClick = { onThemeChange(mode) },
                shape = RoundedCornerShape(16.dp)
            )
        }
        
        Spacer(Modifier.height(16.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.notch_support), fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.edge_to_edge), style = MaterialTheme.typography.bodySmall)
            }
            Switch(checked = notchMode, onCheckedChange = onNotchModeChange)
        }
        
        HorizontalDivider(modifier = Modifier.padding(vertical = 24.dp))
        
        Text(stringResource(R.string.service), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(16.dp))

        Surface(
            onClick = { onAppExclusionClick(); onClose() },
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.1f),
            border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Apps, null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(16.dp))
                Column {
                    Text(stringResource(R.string.app_exclusion), fontWeight = FontWeight.Bold)
                    Text(stringResource(R.string.app_exclusion_desc), style = MaterialTheme.typography.bodySmall)
                }
            }
        }

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
                        Text(stringResource(R.string.battery_optimization), fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onErrorContainer)
                        Text(stringResource(R.string.battery_opt_desc), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onErrorContainer)
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
        
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.auto_start), fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.auto_start_desc), style = MaterialTheme.typography.bodySmall)
            }
            Switch(checked = autoStart, onCheckedChange = onAutoStartChange)
        }
        
        Spacer(Modifier.height(24.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.ipv6_support), fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.ipv6_desc), style = MaterialTheme.typography.bodySmall)
            }
            Switch(checked = allowIpv6, onCheckedChange = onAllowIpv6Change)
        }

        Spacer(Modifier.height(24.dp))

        Text(stringResource(R.string.advanced_settings), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(16.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.http3_quic), fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.http3_desc), style = MaterialTheme.typography.bodySmall)
            }
            Switch(checked = useHttp3, onCheckedChange = onHttp3Change)
        }

        Spacer(Modifier.height(16.dp))

        Text(stringResource(R.string.dns_cache_ttl), style = MaterialTheme.typography.labelMedium)
        OutlinedTextField(
            value = cacheTtl,
            onValueChange = onCacheTtlChange,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            singleLine = true,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = androidx.compose.ui.text.input.KeyboardType.Number,
                imeAction = androidx.compose.ui.text.input.ImeAction.Done
            ),
            keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                onDone = { focusManager.clearFocus() }
            )
        )

        Spacer(Modifier.height(12.dp))

        Text(stringResource(R.string.tcp_limit), style = MaterialTheme.typography.labelMedium)
        OutlinedTextField(
            value = tcpLimit,
            onValueChange = onTcpLimitChange,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            singleLine = true,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = androidx.compose.ui.text.input.KeyboardType.Number,
                imeAction = androidx.compose.ui.text.input.ImeAction.Done
            ),
            keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                onDone = { focusManager.clearFocus() }
            )
        )

        Spacer(Modifier.height(12.dp))

        Text(stringResource(R.string.bootstrap_refresh), style = MaterialTheme.typography.labelMedium)
        OutlinedTextField(
            value = pollInterval,
            onValueChange = onPollIntervalChange,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            singleLine = true,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = androidx.compose.ui.text.input.KeyboardType.Number,
                imeAction = androidx.compose.ui.text.input.ImeAction.Done
            ),
            keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                onDone = { focusManager.clearFocus() }
            )
        )

        Spacer(Modifier.height(24.dp))
        
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.latency_pulse), fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.latency_pulse_desc), style = MaterialTheme.typography.bodySmall)
            }
            Switch(checked = heartbeatEnabled, onCheckedChange = onHeartbeatChange)
        }
        
        if (heartbeatEnabled) {
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = heartbeatDomain,
                onValueChange = onHeartbeatDomainChange,
                label = { Text(stringResource(R.string.ping_domain)) },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                singleLine = true,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    imeAction = androidx.compose.ui.text.input.ImeAction.Done
                ),
                keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                    onDone = { focusManager.clearFocus() }
                )
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = heartbeatInterval,
                onValueChange = onHeartbeatIntervalChange,
                label = { Text(stringResource(R.string.interval_sec)) },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                singleLine = true,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    keyboardType = androidx.compose.ui.text.input.KeyboardType.Number,
                    imeAction = androidx.compose.ui.text.input.ImeAction.Done
                ),
                keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                    onDone = { focusManager.clearFocus() }
                )
            )
        }
        
        Spacer(Modifier.height(16.dp))
        NavigationDrawerItem(
            label = { Text(stringResource(R.string.clear_dns_cache)) },
            selected = false,
            icon = { Icon(Icons.Default.DeleteSweep, null) },
            onClick = { 
                ProxyService.clearCache()
                val msg = context.getString(R.string.dns_cache_cleared)
                android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_SHORT).show()
                onClose() 
            },
            shape = RoundedCornerShape(16.dp)
        )

        Spacer(Modifier.height(40.dp))
        NavigationDrawerItem(
            label = { Text(stringResource(R.string.about_application)) },
            selected = false,
            icon = { Icon(Icons.Default.Info, null) },
            onClick = { onAboutClick(); onClose() },
            shape = RoundedCornerShape(16.dp)
        )
    }
}