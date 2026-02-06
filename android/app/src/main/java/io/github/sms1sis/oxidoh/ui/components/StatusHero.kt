package io.github.sms1sis.oxidoh.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.sms1sis.oxidoh.R

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
            if (isRunning) stringResource(R.string.system_protected) else stringResource(R.string.unprotected), 
            style = MaterialTheme.typography.titleMedium, 
            fontWeight = FontWeight.ExtraBold,
            letterSpacing = 2.sp,
            color = if (isRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
        )

        Spacer(modifier = Modifier.height(12.dp))
        
        Text(
            if (isRunning) stringResource(R.string.tap_to_disconnect) else stringResource(R.string.tap_to_connect), 
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold, 
            color = if (isRunning) MaterialTheme.colorScheme.primary.copy(alpha = 0.7f) else Color(0xFFE91E63).copy(alpha = 0.7f),
            letterSpacing = 1.5.sp
        )
    }
}
