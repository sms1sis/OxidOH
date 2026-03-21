package io.github.sms1sis.oxidoh.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.*
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.sms1sis.oxidoh.R
import io.github.sms1sis.oxidoh.ui.theme.*
import kotlin.math.*

@Composable
fun StatusHero(isRunning: Boolean, latency: Int, onToggle: () -> Unit) {
    val haptic = LocalHapticFeedback.current
    val inf = rememberInfiniteTransition(label = "hero")

    // Resolve colors in @Composable context
    val primaryColor = MaterialTheme.colorScheme.primary
    val onSurfaceVariantColor = MaterialTheme.colorScheme.onSurfaceVariant
    val primaryContainerColor = MaterialTheme.colorScheme.primaryContainer
    val surfaceVariantColor = MaterialTheme.colorScheme.surfaceVariant
    val errorColor = MaterialTheme.colorScheme.error
    
    val activeColor = if (isRunning) primaryColor else onSurfaceVariantColor
    val activeGreen = NeonGreen

    // ── Animations ────────────────────────────────────────────────────────────
    val radarAngle by inf.animateFloat(0f, 360f,
        infiniteRepeatable(tween(3000, easing = LinearEasing)), label = "radar")
    val hexRotation by inf.animateFloat(0f, 360f,
        infiniteRepeatable(tween(12000, easing = LinearEasing)), label = "hex")
    val pingScale by inf.animateFloat(1f, 2.4f,
        infiniteRepeatable(tween(2000, easing = FastOutSlowInEasing), RepeatMode.Restart), label = "ping")
    val pingAlpha by inf.animateFloat(0.6f, 0f,
        infiniteRepeatable(tween(2000, easing = FastOutSlowInEasing), RepeatMode.Restart), label = "pinga")
    val scanLine by inf.animateFloat(0f, 1f,
        infiniteRepeatable(tween(2500, easing = LinearEasing)), label = "scan")
    val glitch by inf.animateFloat(0f, 1f,
        infiniteRepeatable(tween(4000, easing = LinearEasing)), label = "glitch")

    var pressed by remember { mutableStateOf(false) }
    val btnScale by animateFloatAsState(
        if (pressed) 0.90f else 1f,
        spring(Spring.DampingRatioMediumBouncy), label = "btn")

    Column(horizontalAlignment = Alignment.CenterHorizontally) {

        // ── Main orb ──────────────────────────────────────────────────────────
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(280.dp)) {

            // Outer grid rings + radar sweep
            Canvas(modifier = Modifier.fillMaxSize()) {
                val cx = size.width / 2f
                val cy = size.height / 2f

                // Concentric tactical rings
                listOf(130f, 105f, 80f, 55f).forEachIndexed { i, r ->
                    val alpha = if (isRunning) 0.25f - i * 0.05f else 0.10f - i * 0.02f
                    drawCircle(
                        color = activeColor.copy(alpha = alpha),
                        radius = r.dp.toPx(),
                        center = Offset(cx, cy),
                        style = Stroke(width = if (i == 0) 1.5.dp.toPx() else 0.8.dp.toPx())
                    )
                }

                // Cross-hair lines
                val lineAlpha = if (isRunning) 0.15f else 0.06f
                drawLine(activeColor.copy(alpha = lineAlpha),
                    Offset(cx - 140.dp.toPx(), cy), Offset(cx + 140.dp.toPx(), cy), 0.8.dp.toPx())
                drawLine(activeColor.copy(alpha = lineAlpha),
                    Offset(cx, cy - 140.dp.toPx()), Offset(cx, cy + 140.dp.toPx()), 0.8.dp.toPx())

                if (isRunning) {
                    // Radar sweep
                    rotate(radarAngle, Offset(cx, cy)) {
                        drawArc(
                            brush = Brush.sweepGradient(
                                0f to Color.Transparent,
                                0.15f to primaryColor.copy(alpha = 0.35f),
                                0.18f to primaryColor.copy(alpha = 0.6f),
                                1f to Color.Transparent,
                                center = Offset(cx, cy)
                            ),
                            startAngle = -90f, sweepAngle = 65f,
                            useCenter = true,
                            size = Size(260.dp.toPx(), 260.dp.toPx()),
                            topLeft = Offset(cx - 130.dp.toPx(), cy - 130.dp.toPx())
                        )
                        // Leading edge line
                        drawLine(
                            primaryColor.copy(alpha = 0.9f),
                            Offset(cx, cy),
                            Offset(cx + cos(Math.toRadians(-90.0)).toFloat() * 130.dp.toPx(),
                                   cy + sin(Math.toRadians(-90.0)).toFloat() * 130.dp.toPx()),
                            1.5.dp.toPx()
                        )
                    }

                    // Ping ripple when running
                    drawCircle(
                        color = activeColor.copy(alpha = pingAlpha * 0.4f),
                        radius = 70.dp.toPx() * pingScale,
                        center = Offset(cx, cy),
                        style = Stroke(1.dp.toPx())
                    )
                }

                // Corner bracket decorations
                val bSize = 18.dp.toPx()
                val bOff  = 15.dp.toPx()
                val bAlpha = if (isRunning) 0.8f else 0.3f
                val corners = listOf(
                    Offset(bOff, bOff) to Pair(1f, 1f),
                    Offset(size.width - bOff, bOff) to Pair(-1f, 1f),
                    Offset(bOff, size.height - bOff) to Pair(1f, -1f),
                    Offset(size.width - bOff, size.height - bOff) to Pair(-1f, -1f)
                )
                corners.forEach { (pos, dir) ->
                    val p = android.graphics.Path().apply {
                        moveTo(pos.x, pos.y + dir.second * bSize)
                        lineTo(pos.x, pos.y)
                        lineTo(pos.x + dir.first * bSize, pos.y)
                    }
                    drawPath(p.asComposePath(), activeColor.copy(alpha = bAlpha),
                        style = Stroke(2.dp.toPx(), cap = StrokeCap.Square))
                }
            }

            // Rotating hex ring
            Box(
                Modifier.size(200.dp).rotate(hexRotation).alpha(if (isRunning) 0.5f else 0.15f)
            ) {
                Canvas(modifier = Modifier.fillMaxSize()) {
                    val cx = size.width / 2f; val cy = size.height / 2f
                    val r = size.width / 2f - 4.dp.toPx()
                    val path = Path()
                    for (i in 0..5) {
                        val a = Math.toRadians((60 * i - 30).toDouble())
                        val x = cx + r * cos(a).toFloat()
                        val y = cy + r * sin(a).toFloat()
                        if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
                    }
                    path.close()
                    drawPath(path, primaryColor.copy(alpha = 0.5f), style = Stroke(1.5.dp.toPx()))
                }
            }

            // Core button
            Surface(
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    pressed = true
                    onToggle()
                },
                shape = CircleShape,
                color = if (isRunning) primaryContainerColor else surfaceVariantColor,
                modifier = Modifier
                    .size(150.dp)
                    .scale(btnScale)
                    .border(
                        width = if (isRunning) 2.dp else 1.dp,
                        brush = if (isRunning) Brush.sweepGradient(
                            listOf(primaryColor.copy(0f), primaryColor, primaryColor.copy(0f)))
                        else Brush.linearGradient(listOf(onSurfaceVariantColor.copy(0.3f), onSurfaceVariantColor.copy(0.1f))),
                        shape = CircleShape
                    )
            ) {
                Box(contentAlignment = Alignment.Center,
                    modifier = Modifier.fillMaxSize().drawWithContent {
                        drawContent()
                        if (isRunning) {
                            val y = size.height * scanLine
                            drawLine(
                                brush = Brush.verticalGradient(
                                    listOf(Color.Transparent, primaryColor.copy(0.4f), Color.Transparent),
                                    y - 12f, y + 12f),
                                start = Offset(0f, y), end = Offset(size.width, y),
                                strokeWidth = 1.5.dp.toPx()
                            )
                        }
                    }) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center) {
                        Icon(Icons.Default.Shield, null,
                            modifier = Modifier.size(52.dp),
                            tint = if (isRunning) primaryColor else onSurfaceVariantColor.copy(0.5f))
                    }
                }
            }
        }

        Spacer(Modifier.height(20.dp))

        // ── Status text ───────────────────────────────────────────────────────
        // Glitch effect on status label
        val glitchOffset = if (isRunning && (glitch % 1f) < 0.02f) 3.dp else 0.dp
        Text(
            if (isRunning) "[ SYSTEM PROTECTED ]" else "[ UNPROTECTED ]",
            style = MaterialTheme.typography.titleMedium,
            color = if (isRunning) primaryColor else errorColor.copy(0.8f),
            letterSpacing = 3.sp,
            modifier = Modifier.offset(x = glitchOffset)
        )

        Spacer(Modifier.height(8.dp))

        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            // Blinking status dot
            val dotAlpha by inf.animateFloat(1f, 0.2f,
                infiniteRepeatable(tween(800), RepeatMode.Reverse), label = "dot")
            Box(Modifier.size(6.dp).background(
                if (isRunning) activeGreen else errorColor, CircleShape
            ).alpha(if (isRunning) dotAlpha else 1f))
            Text(
                if (isRunning) "TAP TO DISCONNECT" else "TAP TO ACTIVATE",
                style = MaterialTheme.typography.labelSmall,
                color = if (isRunning) activeGreen.copy(0.7f) else errorColor.copy(0.6f),
                letterSpacing = 2.sp
            )
        }
    }

    // Reset press state
    LaunchedEffect(pressed) {
        if (pressed) {
            kotlinx.coroutines.delay(150)
            pressed = false
        }
    }
}
