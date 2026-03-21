package io.github.sms1sis.oxidoh.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.sms1sis.oxidoh.R
import io.github.sms1sis.oxidoh.ui.components.StatusHero
import io.github.sms1sis.oxidoh.ui.theme.*

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
    val inf = rememberInfiniteTransition(label = "dash")
    val borderFlow by inf.animateFloat(0f, 360f,
        infiniteRepeatable(tween(6000, easing = LinearEasing)), label = "border")

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .imePadding()
            .padding(horizontal = 20.dp, vertical = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(28.dp)
    ) {
        StatusHero(isRunning, latency, onToggle)

        // ── Config Panel ──────────────────────────────────────────────────────
        val panelShape = RoundedCornerShape(4.dp)
        Box(modifier = Modifier
            .fillMaxWidth()
            .drawWithContent {
                drawContent()
                // Animated scanning border
                val shader = android.graphics.SweepGradient(
                    size.width / 2f, size.height / 2f,
                    intArrayOf(
                        android.graphics.Color.TRANSPARENT,
                        CyanPrimary.copy(0.8f).toArgb(),
                        CyanPrimary.toArgb(),
                        CyanPrimary.copy(0.8f).toArgb(),
                        android.graphics.Color.TRANSPARENT,
                        android.graphics.Color.TRANSPARENT,
                    ),
                    floatArrayOf(0f, 0.1f, 0.15f, 0.2f, 0.3f, 1f)
                )
                val matrix = android.graphics.Matrix()
                matrix.postRotate(borderFlow, size.width / 2f, size.height / 2f)
                shader.setLocalMatrix(matrix)
                val outline = panelShape.createOutline(size, layoutDirection, this)
                val path = Path().apply { addOutline(outline) }
                drawPath(path, ShaderBrush(shader), style = Stroke(1.5.dp.toPx()))
                // Static dim border underneath
                drawPath(path, GridLine.copy(0.6f), style = Stroke(0.8.dp.toPx()))
            }
        ) {
            Column(modifier = Modifier
                .background(MaterialTheme.colorScheme.surfaceContainer, panelShape)
                .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Panel header
                Row(verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, RoundedCornerShape(1.dp)))
                    Text("CONFIG MATRIX", style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary, letterSpacing = 3.sp)
                    Spacer(Modifier.weight(1f))
                    Icon(Icons.Default.Tune, null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)

                // Profile selector
                var expanded by remember { mutableStateOf(false) }
                Column {
                    Text("// RESOLVER PROFILE", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 2.sp)
                    Spacer(Modifier.height(6.dp))
                    Box(modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, if (expanded) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(2.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerLow, RoundedCornerShape(2.dp))
                    ) {
                        Surface(
                            onClick = { expanded = true },
                            color = Color.Transparent,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Text("> ${profiles[selectedProfileIndex].name}",
                                    modifier = Modifier.weight(1f),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                                Icon(Icons.Default.KeyboardArrowDown, null,
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
                            }
                        }
                        DropdownMenu(expanded = expanded,
                            onDismissRequest = { expanded = false },
                            modifier = Modifier.background(MaterialTheme.colorScheme.surfaceContainerHigh)) {
                            profiles.forEachIndexed { index, profile ->
                                DropdownMenuItem(
                                    text = {
                                        Text("> ${profile.name}",
                                            color = if (index == selectedProfileIndex) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                                            fontWeight = if (index == selectedProfileIndex) FontWeight.Bold else FontWeight.Normal)
                                    },
                                    onClick = { onProfileSelect(index); expanded = false }
                                )
                            }
                        }
                    }
                }

                val isCustom = selectedProfileIndex == profiles.size - 1

                // URL field
                SciFiTextField(
                    value = resolverUrl,
                    onValueChange = { if (isCustom) onUrlChange(it) },
                    label = "// TARGET_ENDPOINT",
                    readOnly = !isCustom,
                    keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri,
                    onDone = { focusManager.clearFocus() }
                )

                // Bootstrap + Port row
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Box(Modifier.weight(1f)) {
                        SciFiTextField(
                            value = bootstrapDns,
                            onValueChange = { if (isCustom) onBootstrapChange(it) },
                            label = "// BOOTSTRAP_NS",
                            readOnly = !isCustom,
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Decimal,
                            onDone = { focusManager.clearFocus() }
                        )
                    }
                    Box(Modifier.width(110.dp)) {
                        SciFiTextField(
                            value = listenPort,
                            onValueChange = onPortChange,
                            label = "// PORT",
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.Number,
                            onDone = { focusManager.clearFocus() }
                        )
                    }
                }

                // Status bar at bottom of panel
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    val statusColor = if (isRunning) NeonGreen else MaterialTheme.colorScheme.onSurfaceVariant
                    StatusChip("STATUS", if (isRunning) "ONLINE" else "OFFLINE", statusColor)
                    StatusChip("PROTO", "ODoH", MaterialTheme.colorScheme.primary)
                    StatusChip("ENC", "HPKE", CyanDim)
                }
            }
        }
    }
}


@Composable
private fun SciFiTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    readOnly: Boolean = false,
    keyboardType: androidx.compose.ui.text.input.KeyboardType =
        androidx.compose.ui.text.input.KeyboardType.Text,
    onDone: () -> Unit = {}
) {
    val onSurfaceVariantColor = MaterialTheme.colorScheme.onSurfaceVariant
    val onSurfaceColor = MaterialTheme.colorScheme.onSurface
    val primaryColor = MaterialTheme.colorScheme.primary
    val outlineVariantColor = MaterialTheme.colorScheme.outlineVariant
    val surfaceContainerLowColor = MaterialTheme.colorScheme.surfaceContainerLow

    Column {
        Text(label, style = MaterialTheme.typography.labelSmall, color = onSurfaceVariantColor, letterSpacing = 2.sp)
        Spacer(Modifier.height(4.dp))
        
        var textFieldValue by remember { 
            mutableStateOf(androidx.compose.ui.text.input.TextFieldValue(value)) 
        }

        // Sync external changes (like profile selection) into internal state
        LaunchedEffect(value) {
            if (value != textFieldValue.text) {
                textFieldValue = androidx.compose.ui.text.input.TextFieldValue(
                    text = value,
                    selection = androidx.compose.ui.text.TextRange(value.length)
                )
            }
        }

        OutlinedTextField(
            value = textFieldValue,
            onValueChange = { 
                textFieldValue = it
                if (it.text != value) {
                    onValueChange(it.text)
                }
            },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(2.dp),
            singleLine = true,
            readOnly = readOnly,
            textStyle = MaterialTheme.typography.bodySmall.copy(color = if (readOnly) onSurfaceVariantColor else onSurfaceColor),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor   = primaryColor,
                unfocusedBorderColor = outlineVariantColor,
                focusedContainerColor   = surfaceContainerLowColor,
                unfocusedContainerColor = surfaceContainerLowColor,
                cursorColor = primaryColor,
            ),
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = keyboardType,
                autoCorrectEnabled = false,
                imeAction = androidx.compose.ui.text.input.ImeAction.Done
            ),
            keyboardActions = androidx.compose.foundation.text.KeyboardActions(onDone = { onDone() })
        )
    }
}


@Composable
private fun StatusChip(label: String, value: String, color: Color) {
    Row(verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp, fontSize = 9.sp)
        Text(":", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp)
        Text(value, style = MaterialTheme.typography.labelSmall,
            color = color, fontWeight = FontWeight.Bold, letterSpacing = 1.sp, fontSize = 10.sp)
    }
}

