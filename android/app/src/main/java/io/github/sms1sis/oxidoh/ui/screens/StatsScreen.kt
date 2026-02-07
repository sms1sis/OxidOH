package io.github.sms1sis.oxidoh.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.sms1sis.oxidoh.ProxyService
import io.github.sms1sis.oxidoh.R

@Composable
fun StatsScreen(stats: IntArray) {
    val context = LocalContext.current
    val udp = stats.getOrElse(0) { 0 }
    val tcp = stats.getOrElse(1) { 0 }
    val errors = stats.getOrElse(2) { 0 }
    val total = udp + tcp
    val successRate = if (total > 0) {
        ((total - errors).toFloat() / total.toFloat() * 100).toInt().coerceIn(0, 100)
    } else null

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    stringResource(R.string.traffic_statistics),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    stringResource(R.string.real_time_monitor),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.outline
                )
            }
            
            Surface(
                onClick = {
                    ProxyService.clearStats()
                    android.widget.Toast.makeText(context, context.getString(R.string.stats_cleared), android.widget.Toast.LENGTH_SHORT).show()
                },
                color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.8f),
                shape = CircleShape,
                modifier = Modifier.size(40.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        Icons.Default.DeleteOutline,
                        stringResource(R.string.clear_statistics),
                        modifier = Modifier.size(20.dp),
                        tint = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }

        Spacer(Modifier.height(32.dp))

        // Large Success Rate Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(32.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f)
            )
        ) {
            Column(
                modifier = Modifier.padding(32.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(stringResource(R.string.success_rate), style = MaterialTheme.typography.labelLarge)
                Text(
                    if (successRate != null) "$successRate%" else "--%",
                    style = MaterialTheme.typography.displayLarge,
                    fontWeight = FontWeight.Black,
                    color = if (successRate != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
                )
                LinearProgressIndicator(
                    progress = { (successRate ?: 0) / 100f },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 16.dp)
                        .clip(RoundedCornerShape(8.dp)),
                    color = if (successRate != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline.copy(alpha = 0.2f),
                    trackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                )
            }
        }

        Spacer(Modifier.height(24.dp))

        // Grid of Stats
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            StatCard(
                modifier = Modifier.weight(1f),
                icon = Icons.Default.Dataset,
                label = stringResource(R.string.udp_queries),
                value = udp.toString()
            )
            StatCard(
                modifier = Modifier.weight(1f),
                icon = Icons.Default.SwapCalls,
                label = stringResource(R.string.tcp_queries),
                value = tcp.toString()
            )
        }

        Spacer(Modifier.height(16.dp))

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            StatCard(
                modifier = Modifier.weight(1f),
                icon = Icons.Default.Functions,
                label = stringResource(R.string.total_queries),
                value = total.toString()
            )
            StatCard(
                modifier = Modifier.weight(1f),
                icon = Icons.Default.ErrorOutline,
                label = stringResource(R.string.errors_count),
                value = errors.toString(),
                isError = errors > 0
            )
        }
    }
}

@Composable
fun StatCard(
    modifier: Modifier = Modifier,
    icon: ImageVector,
    label: String,
    value: String,
    isError: Boolean = false
) {
    val color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
        )
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Icon(icon, null, tint = color, modifier = Modifier.size(24.dp))
            Spacer(Modifier.height(12.dp))
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
        }
    }
}
