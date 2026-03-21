package io.github.sms1sis.oxidoh.ui.screens

import android.content.ClipData
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.sms1sis.oxidoh.ProxyService
import io.github.sms1sis.oxidoh.R
import io.github.sms1sis.oxidoh.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun LogScreen(logs: Array<String>) {
    val context = LocalContext.current
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()

    // Resolve colors
    val primaryColor = MaterialTheme.colorScheme.primary
    val onSurfaceVariantColor = MaterialTheme.colorScheme.onSurfaceVariant
    val surfaceContainerHighColor = MaterialTheme.colorScheme.surfaceContainerHigh
    val onSurfaceColor = MaterialTheme.colorScheme.onSurface
    val errorColor = MaterialTheme.colorScheme.error

    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) listState.animateScrollToItem(logs.size - 1)
    }

    Column(modifier = Modifier.fillMaxSize()) {

        // ── Header ────────────────────────────────────────────────────────────
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("INTERCEPT LOG", style = MaterialTheme.typography.headlineSmall,
                    color = primaryColor, letterSpacing = 3.sp)
                Text("// ${logs.size} ENTRIES CAPTURED",
                    style = MaterialTheme.typography.labelSmall,
                    color = onSurfaceVariantColor, letterSpacing = 1.sp)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                HudIconButton(Icons.Default.DeleteOutline, errorColor) {
                    ProxyService.clearLogs()
                    android.widget.Toast.makeText(context,
                        context.getString(R.string.logs_cleared), android.widget.Toast.LENGTH_SHORT).show()
                }
                HudIconButton(Icons.Default.ContentCopy, primaryColor) {
                    if (logs.isNotEmpty()) scope.launch {
                        clipboard.setClipEntry(ClipEntry(
                            ClipData.newPlainText("OxidOH Logs", logs.joinToString("\n"))))
                        android.widget.Toast.makeText(context,
                            context.getString(R.string.logs_copied), android.widget.Toast.LENGTH_SHORT).show()
                    }
                }
                HudIconButton(Icons.Default.FileDownload, NeonGreen) {
                    saveLogsToFile(context, logs)
                }
            }
        }

        // ── Terminal window ───────────────────────────────────────────────────
        Box(modifier = Modifier
            .fillMaxWidth()
            .weight(1f)
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .background(surfaceContainerHighColor, RoundedCornerShape(2.dp))
            .drawBehind {
                // Left gutter line (terminal style)
                drawLine(primaryColor.copy(0.2f),
                    Offset(40.dp.toPx(), 0f), Offset(40.dp.toPx(), size.height), 0.8.dp.toPx())
                // Top bar
                drawLine(primaryColor.copy(0.4f),
                    Offset(0f, 0f), Offset(size.width, 0f), 1.dp.toPx())
            }
        ) {
            if (logs.isEmpty()) {
                Column(
                    modifier = Modifier.align(Alignment.Center),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("_", color = primaryColor.copy(0.5f),
                        style = MaterialTheme.typography.displaySmall)
                    Spacer(Modifier.height(8.dp))
                    Text("AWAITING INTERCEPTS...", color = onSurfaceVariantColor,
                        style = MaterialTheme.typography.labelMedium, letterSpacing = 3.sp)
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize().padding(top = 4.dp),
                    contentPadding = PaddingValues(bottom = 16.dp)
                ) {
                    items(logs.size) { i ->
                        val log = logs[i]
                        val isOk    = log.contains("OK")
                        val isError = log.contains("Error") || log.contains("error")
                        val color = when {
                            isError -> errorColor.copy(0.9f)
                            isOk    -> NeonGreen.copy(0.9f)
                            else    -> onSurfaceColor.copy(0.7f)
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            // Line number gutter
                            Text(
                                "${(i + 1).toString().padStart(3, '0')}",
                                modifier = Modifier.width(40.dp).padding(start = 8.dp),
                                style = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 10.sp),
                                color = onSurfaceVariantColor.copy(0.5f)
                            )
                            Text(
                                log,
                                modifier = Modifier.weight(1f).padding(end = 12.dp),
                                style = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                                    lineHeight = 16.sp),
                                color = color
                            )
                        }
                    }
                }
            }
        }
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun HudIconButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    color: Color,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        color = color.copy(0.08f),
        shape = RoundedCornerShape(2.dp),
        modifier = Modifier.size(38.dp)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Icon(icon, null, modifier = Modifier.size(18.dp), tint = color)
        }
    }
}

private fun saveLogsToFile(context: Context, logs: Array<String>) {
    if (logs.isEmpty()) return
    try {
        val fileName = "OxidOH_${System.currentTimeMillis()}.log"
        val dir = android.os.Environment.getExternalStoragePublicDirectory(
            android.os.Environment.DIRECTORY_DOWNLOADS)
        val file = java.io.File(dir, fileName)
        java.io.FileOutputStream(file).use { out ->
            logs.forEach { out.write((it + "\n").toByteArray()) }
        }
        android.media.MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), null, null)
        android.widget.Toast.makeText(context,
            context.getString(R.string.saved_to_downloads), android.widget.Toast.LENGTH_SHORT).show()
    } catch (e: Exception) {
        android.widget.Toast.makeText(context,
            context.getString(R.string.failed_save_logs), android.widget.Toast.LENGTH_SHORT).show()
    }
}
