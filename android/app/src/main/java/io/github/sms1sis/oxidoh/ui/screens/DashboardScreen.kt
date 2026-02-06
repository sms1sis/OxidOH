package io.github.sms1sis.oxidoh.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.ShaderBrush
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.addOutline
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.sms1sis.oxidoh.R
import io.github.sms1sis.oxidoh.ui.components.StatusHero
import android.graphics.Matrix
import android.graphics.SweepGradient
import androidx.compose.ui.geometry.center

data class DnsProfile(val name: String, val url: String, val bootstrap: String)

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
    val focusManager = LocalFocusManager.current
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
                        Text(stringResource(R.string.configuration), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    }
                    
                    var expanded by remember { mutableStateOf(false) }
                    Column {
                        Text(stringResource(R.string.service_provider), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
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

                    val isCustom = selectedProfileIndex == profiles.size - 1
                    var textFieldValue by remember(resolverUrl) { 
                        mutableStateOf(androidx.compose.ui.text.input.TextFieldValue(
                            text = resolverUrl,
                            selection = androidx.compose.ui.text.TextRange(resolverUrl.length)
                        )) 
                    }

                    OutlinedTextField(
                        value = textFieldValue,
                        onValueChange = {
                            textFieldValue = it
                            if (isCustom) onUrlChange(it.text)
                        },
                        label = { Text(stringResource(R.string.target_proxy_urls)) },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        singleLine = true,
                        readOnly = !isCustom,
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri,
                            autoCorrectEnabled = false,
                            imeAction = androidx.compose.ui.text.input.ImeAction.Done
                        ),
                        keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                            onDone = { focusManager.clearFocus() }
                        )
                    )
                    
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        var bootstrapValue by remember(bootstrapDns) {
                            mutableStateOf(androidx.compose.ui.text.input.TextFieldValue(
                                text = bootstrapDns,
                                selection = androidx.compose.ui.text.TextRange(bootstrapDns.length)
                            ))
                        }
                        OutlinedTextField(
                            value = bootstrapValue,
                            onValueChange = {
                                bootstrapValue = it
                                if (isCustom) onBootstrapChange(it.text)
                            },
                            label = { Text(stringResource(R.string.bootstrap)) },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(16.dp),
                            singleLine = true,
                            readOnly = !isCustom,
                            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                                keyboardType = androidx.compose.ui.text.input.KeyboardType.Decimal,
                                autoCorrectEnabled = false,
                                imeAction = androidx.compose.ui.text.input.ImeAction.Done
                            ),
                            keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                                onDone = { focusManager.clearFocus() }
                            )
                        )
                        OutlinedTextField(
                            value = listenPort,
                            onValueChange = onPortChange,
                            label = { Text(stringResource(R.string.port)) },
                            modifier = Modifier.weight(0.7f),
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
            }
        }
    }
}