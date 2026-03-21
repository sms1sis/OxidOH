package io.github.sms1sis.oxidoh.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Update
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.sms1sis.oxidoh.BuildConfig
import io.github.sms1sis.oxidoh.R
import io.github.sms1sis.oxidoh.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun AboutDialog(onDismiss: () -> Unit, uriHandler: androidx.compose.ui.platform.UriHandler) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var checkingUpdate by remember { mutableStateOf(false) }

    // Resolve colors in @Composable context
    val bgColor = MaterialTheme.colorScheme.background
    val borderColor = MaterialTheme.colorScheme.outline.copy(0.3f)
    val primaryColor = MaterialTheme.colorScheme.primary
    val bracketColor = primaryColor.copy(0.6f)
    val onSurfaceVariantColor = MaterialTheme.colorScheme.onSurfaceVariant
    val onBackgroundColor = MaterialTheme.colorScheme.onBackground
    val outlineColor = MaterialTheme.colorScheme.outline
    val outlineVariantColor = MaterialTheme.colorScheme.outlineVariant
    val errorColor = MaterialTheme.colorScheme.error

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth(0.85f)
                .clip(RoundedCornerShape(2.dp))
                .background(bgColor)
                .border(1.dp, borderColor, RoundedCornerShape(2.dp))
                .drawBehind {
                    // Decorative corner brackets
                    val s = 12.dp.toPx()
                    val stroke = 1.5.dp.toPx()

                    // Top Left
                    drawLine(bracketColor, Offset(0f, s), Offset(0f, 0f), stroke)
                    drawLine(bracketColor, Offset(0f, 0f), Offset(s, 0f), stroke)
                    // Bottom Right
                    drawLine(bracketColor, Offset(size.width, size.height - s), Offset(size.width, size.height), stroke)
                    drawLine(bracketColor, Offset(size.width, size.height), Offset(size.width - s, size.height), stroke)
                }
                .padding(16.dp)
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                // Header
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Icon(Icons.Default.Terminal, null, tint = primaryColor, modifier = Modifier.size(20.dp))
                    Text(
                        "SYSTEM_INFO",
                        style = MaterialTheme.typography.titleMedium,
                        color = primaryColor,
                        letterSpacing = 4.sp
                    )
                }

                HorizontalDivider(color = outlineVariantColor, thickness = 0.5.dp)

                // Version Info
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("IDENTIFIER: OxidOH", style = MaterialTheme.typography.labelSmall, color = onSurfaceVariantColor)
                    Text("BUILD_VER: ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.bodyMedium, color = NeonGreen)
                    Text("PLATFORM: ANDROID_ARM64", style = MaterialTheme.typography.labelSmall, color = onSurfaceVariantColor)
                }

                // Developer / Credits
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Default.Code, null, tint = outlineColor, modifier = Modifier.size(16.dp))
                    Text("CORE_ENGINE: sms1sis", style = MaterialTheme.typography.bodySmall, color = onBackgroundColor)
                }

                Spacer(Modifier.height(4.dp))

                // Actions
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    // Check Update Button
                    Surface(
                        onClick = {
                            scope.launch {
                                checkingUpdate = true
                                checkForUpdates(context, uriHandler)
                                checkingUpdate = false
                            }
                        },
                        enabled = !checkingUpdate,
                        color = primaryColor.copy(0.08f),
                        shape = RoundedCornerShape(2.dp),
                        modifier = Modifier.fillMaxWidth().height(48.dp)
                            .border(0.5.dp, if (checkingUpdate) onSurfaceVariantColor else primaryColor.copy(0.4f), RoundedCornerShape(2.dp))
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            if (checkingUpdate) {
                                CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = primaryColor)
                            } else {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Default.Update, null, modifier = Modifier.size(18.dp), tint = primaryColor)
                                    Text("CHECK_INTEGRITY", style = MaterialTheme.typography.labelMedium, color = primaryColor)
                                }
                            }
                        }
                    }

                    // GitHub Link
                    TextButton(
                        onClick = { uriHandler.openUri("https://github.com/sms1sis/OxidOH") },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("// VIEW_SOURCE_REPOSITORY", style = MaterialTheme.typography.labelSmall, color = primaryColor, letterSpacing = 1.sp)
                    }
                }

                // Close
                Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.CenterEnd) {
                    TextButton(onClick = onDismiss) {
                        Text("TERMINATE", style = MaterialTheme.typography.labelMedium, color = errorColor)
                    }
                }
            }
        }
    }
}

private suspend fun checkForUpdates(context: android.content.Context, uriHandler: androidx.compose.ui.platform.UriHandler) {
    val repoUrl = "https://api.github.com/repos/sms1sis/OxidOH/releases/latest"
    val currentVersion = "v${BuildConfig.VERSION_NAME}"

    withContext(Dispatchers.IO) {
        try {
            val connection = java.net.URL(repoUrl).openConnection() as java.net.HttpURLConnection
            connection.requestMethod = "GET"
            connection.setRequestProperty("Accept", "application/vnd.github.v3+json")
            connection.connectTimeout = 5000
            connection.readTimeout = 5000

            if (connection.responseCode == 200) {
                val response = connection.inputStream.bufferedReader().use { it.readText() }
                val tagName = response.substringAfter("\"tag_name\":\"").substringBefore("\"")
                
                withContext(Dispatchers.Main) {
                    if (tagName != currentVersion && tagName.startsWith("v")) {
                        val msg = context.getString(R.string.update_available, tagName)
                        android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_LONG).show()
                        uriHandler.openUri("https://github.com/sms1sis/OxidOH/releases/latest")
                    } else {
                        val msg = context.getString(R.string.latest_version)
                        android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_SHORT).show()
                    }
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                val msg = context.getString(R.string.update_check_failed)
                android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_SHORT).show()
            }
        }
    }
}
