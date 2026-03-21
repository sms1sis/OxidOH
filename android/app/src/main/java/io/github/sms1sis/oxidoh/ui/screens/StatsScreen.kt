package io.github.sms1sis.oxidoh.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.sms1sis.oxidoh.ProxyService
import io.github.sms1sis.oxidoh.R
import io.github.sms1sis.oxidoh.ui.theme.*
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun StatsScreen(stats: IntArray) {
    val context = LocalContext.current
    val udp       = stats.getOrElse(0) { 0 }
    val tcp       = stats.getOrElse(1) { 0 }
    val malformed = stats.getOrElse(2) { 0 }
    val total     = stats.getOrElse(3) { 0 }
    val https     = stats.getOrElse(4) { 0 }
    val cacheHits = stats.getOrElse(5) { 0 }
    val errors    = stats.getOrElse(6) { 0 }
    val avgLat    = stats.getOrElse(7) { 0 }
    val cacheMiss = stats.getOrElse(8) { 0 }
    val cacheSize = stats.getOrElse(9) { 0 }

    val hitTotal  = cacheHits + cacheMiss
    val hitRate   = if (hitTotal > 0) cacheHits.toFloat() / hitTotal.toFloat() else null
    val successRate = if (total > 0) (total - errors).toFloat() / total.toFloat() else null

    Column(modifier = Modifier
        .fillMaxSize()
        .verticalScroll(rememberScrollState())
        .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // ── Header ────────────────────────────────────────────────────────────
        Row(modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically) {
            Column {
                Text("TELEMETRY", style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.primary, letterSpacing = 3.sp)
                Text("// REAL-TIME TRAFFIC ANALYSIS",
                    style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
            }
            Surface(
                onClick = {
                    ProxyService.clearStats()
                    android.widget.Toast.makeText(context,
                        context.getString(R.string.stats_cleared), android.widget.Toast.LENGTH_SHORT).show()
                },
                color = MaterialTheme.colorScheme.error.copy(0.08f),
                shape = RoundedCornerShape(2.dp),
                modifier = Modifier.size(38.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.DeleteOutline, null,
                        modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.error)
                }
            }
        }

        // ── Radial mission status ─────────────────────────────────────────────
        RadialStatusGauge(successRate, hitRate, avgLat, total)

        // ── Cache hit rate bar ────────────────────────────────────────────────
        if (hitTotal > 0) {
            TacticalProgressBar(
                label = "CACHE HIT RATE",
                value = hitRate ?: 0f,
                displayText = hitRate?.let { "${(it * 100).toInt()}%" } ?: "--",
                color = when {
                    (hitRate ?: 0f) >= 0.6f -> NeonGreen
                    (hitRate ?: 0f) >= 0.3f -> AmberAlert
                    else -> MaterialTheme.colorScheme.error
                },
                sublabel = "HITS:$cacheHits  MISSES:$cacheMiss  STORED:$cacheSize"
            )
        }

        // ── Grid stats ────────────────────────────────────────────────────────
        HudSectionLabel("INBOUND TRAFFIC")
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TacticalStatCard(Modifier.weight(1f), Icons.Default.Dataset,     "UDP",     udp.toString(),     MaterialTheme.colorScheme.primary)
            TacticalStatCard(Modifier.weight(1f), Icons.Default.SwapCalls,   "TCP",     tcp.toString(),     CyanDim)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TacticalStatCard(Modifier.weight(1f), Icons.Default.Functions,   "TOTAL",   total.toString(),   MaterialTheme.colorScheme.onBackground)
            TacticalStatCard(Modifier.weight(1f), Icons.Default.Warning,     "INVALID", malformed.toString(),
                if (malformed > 0) AmberAlert else MaterialTheme.colorScheme.onSurfaceVariant)
        }

        HudSectionLabel("OUTBOUND TRAFFIC")
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TacticalStatCard(Modifier.weight(1f), Icons.Default.Security,    "HTTPS",   https.toString(),   MaterialTheme.colorScheme.primary)
            TacticalStatCard(Modifier.weight(1f), Icons.Default.OfflineBolt, "CACHED",  cacheHits.toString(), NeonGreen)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TacticalStatCard(Modifier.weight(1f), Icons.Default.History,     "AVG_LAT",
                if (avgLat > 0) "${avgLat}ms" else "--",
                when { avgLat in 1..149 -> NeonGreen; avgLat in 150..399 -> AmberAlert; avgLat > 0 -> MaterialTheme.colorScheme.error; else -> MaterialTheme.colorScheme.onSurfaceVariant })
            TacticalStatCard(Modifier.weight(1f), Icons.Default.ErrorOutline,"ERRORS",  errors.toString(),
                if (errors > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
        }

        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun RadialStatusGauge(
    successRate: Float?,
    hitRate: Float?,
    avgLat: Int,
    total: Int
) {
    val inf = rememberInfiniteTransition(label = "gauge")
    val sweep by inf.animateFloat(0f, 360f,
        infiniteRepeatable(tween(8000, easing = LinearEasing)), label = "sweep")

    val outlineVariantColor = MaterialTheme.colorScheme.outlineVariant
    val primaryColor = MaterialTheme.colorScheme.primary
    val onSurfaceVariantColor = MaterialTheme.colorScheme.onSurfaceVariant
    val errorColor = MaterialTheme.colorScheme.error

    Box(modifier = Modifier.fillMaxWidth().height(200.dp),
        contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.size(180.dp)) {
            val cx = size.width / 2f; val cy = size.height / 2f
            val r = size.width / 2f - 8.dp.toPx()

            // Background arcs — topLeft then size (correct order)
            drawArc(outlineVariantColor.copy(0.4f), -90f, 360f, false,
                topLeft = Offset(cx - r, cy - r), size = Size(r * 2, r * 2),
                style = Stroke(6.dp.toPx()))

            // Success rate arc
            successRate?.let { rate ->
                drawArc(
                    color = primaryColor.copy(alpha = 0.9f),
                    startAngle = -90f, sweepAngle = rate * 360f, useCenter = false,
                    topLeft = Offset(cx - r, cy - r), size = Size(r * 2, r * 2),
                    style = Stroke(6.dp.toPx(), cap = StrokeCap.Round)
                )
                drawArc(
                    color = NeonGreen.copy(alpha = 0.7f),
                    startAngle = -90f, sweepAngle = rate * 360f * 0.5f, useCenter = false,
                    topLeft = Offset(cx - r, cy - r), size = Size(r * 2, r * 2),
                    style = Stroke(6.dp.toPx(), cap = StrokeCap.Round)
                )
            }

            // Inner ring — cache hit
            val r2 = r - 16.dp.toPx()
            drawArc(outlineVariantColor.copy(0.25f), -90f, 360f, false,
                topLeft = Offset(cx - r2, cy - r2), size = Size(r2 * 2, r2 * 2),
                style = Stroke(3.dp.toPx()))
            hitRate?.let { rate ->
                val hColor = if (rate >= 0.6f) NeonGreen else if (rate >= 0.3f) AmberAlert else errorColor
                drawArc(hColor, -90f, rate * 360f, false,
                    topLeft = Offset(cx - r2, cy - r2), size = Size(r2 * 2, r2 * 2),
                    style = Stroke(3.dp.toPx(), cap = StrokeCap.Round))
            }

            // Rotating scan tick
            val tickAngle = Math.toRadians((sweep - 90f).toDouble())
            val tickStart = Offset(cx + (r - 10.dp.toPx()) * cos(tickAngle).toFloat(),
                                   cy + (r - 10.dp.toPx()) * sin(tickAngle).toFloat())
            val tickEnd   = Offset(cx + (r + 4.dp.toPx()) * cos(tickAngle).toFloat(),
                                   cy + (r + 4.dp.toPx()) * sin(tickAngle).toFloat())
            drawLine(primaryColor.copy(0.8f), tickStart, tickEnd, 2.dp.toPx(), StrokeCap.Round)
        }

        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(successRate?.let { "${(it * 100).toInt()}%" } ?: "--",
                style = MaterialTheme.typography.displaySmall,
                color = if (successRate != null) NeonGreen else onSurfaceVariantColor,
                fontWeight = FontWeight.Black, letterSpacing = 2.sp)
            Text("SUCCESS RATE", style = MaterialTheme.typography.labelSmall,
                color = onSurfaceVariantColor, letterSpacing = 2.sp)
            Spacer(Modifier.height(4.dp))
            Text("$total QUERIES", style = MaterialTheme.typography.labelSmall,
                color = primaryColor.copy(0.7f), letterSpacing = 1.sp)
        }
    }
}

@Composable
private fun TacticalProgressBar(
    label: String,
    value: Float,
    displayText: String,
    color: Color,
    sublabel: String
) {
    Column(modifier = Modifier
        .fillMaxWidth()
        .background(MaterialTheme.colorScheme.surfaceContainer, RoundedCornerShape(2.dp))
        .drawBehind {
            drawLine(color.copy(0.5f), Offset(0f, 0f), Offset(0f, size.height), 2.dp.toPx())
        }
        .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 2.sp)
            Text(displayText, style = MaterialTheme.typography.labelLarge,
                color = color, fontWeight = FontWeight.Bold)
        }
        Box(modifier = Modifier.fillMaxWidth().height(4.dp)
            .background(MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(1.dp))) {
            Box(modifier = Modifier.fillMaxWidth(value).height(4.dp)
                .background(Brush.horizontalGradient(listOf(color.copy(0.6f), color)),
                    RoundedCornerShape(1.dp)))
        }
        Text(sublabel, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(0.6f), letterSpacing = 1.sp, fontSize = 10.sp)
    }
}

@Composable
private fun HudSectionLabel(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Box(Modifier.width(3.dp).height(12.dp).background(MaterialTheme.colorScheme.primary))
        Text(text, style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary, letterSpacing = 3.sp)
        Box(Modifier.weight(1f).height(0.5.dp).background(MaterialTheme.colorScheme.outlineVariant))
    }
}

@Composable
private fun TacticalStatCard(
    modifier: Modifier,
    icon: ImageVector,
    label: String,
    value: String,
    color: Color
) {
    Column(modifier = modifier
        .background(MaterialTheme.colorScheme.surfaceContainerLow, RoundedCornerShape(2.dp))
        .drawBehind {
            drawLine(color.copy(0.4f), Offset(0f, size.height),
                Offset(size.width, size.height), 1.dp.toPx())
        }
        .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(icon, null, tint = color.copy(0.7f), modifier = Modifier.size(14.dp))
            Text(label, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 2.sp, fontSize = 9.sp)
        }
        Text(value, style = MaterialTheme.typography.titleLarge,
            color = color, fontWeight = FontWeight.Black, letterSpacing = 1.sp)
    }
}
