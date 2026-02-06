package io.github.sms1sis.oxidoh.ui.screens

import android.content.Context
import android.util.Log
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudQueue
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.sms1sis.oxidoh.ProxyService
import io.github.sms1sis.oxidoh.R

@Composable
fun LogScreen(logs: Array<String>) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val listState = rememberLazyListState()
    
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            listState.animateScrollToItem(logs.size - 1)
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(vertical = 24.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(stringResource(R.string.network_activity), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                // Clear Logs Button
                Surface(
                    onClick = { 
                        ProxyService.clearLogs()
                        android.widget.Toast.makeText(context, context.getString(R.string.logs_cleared), android.widget.Toast.LENGTH_SHORT).show()
                    },
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.8f),
                    shape = CircleShape,
                    modifier = Modifier.size(40.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(Icons.Default.DeleteOutline, stringResource(R.string.clear_logs), modifier = Modifier.size(20.dp), tint = MaterialTheme.colorScheme.onErrorContainer)
                    }
                }

                // Copy Logs Button
                Surface(
                    onClick = { 
                        if (logs.isNotEmpty()) {
                            val logText = logs.joinToString("\n")
                            clipboardManager.setText(AnnotatedString(logText))
                            android.widget.Toast.makeText(context, context.getString(R.string.logs_copied), android.widget.Toast.LENGTH_SHORT).show()
                        }
                    },
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = CircleShape,
                    modifier = Modifier.size(40.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(Icons.Default.ContentCopy, stringResource(R.string.copy_logs), modifier = Modifier.size(20.dp))
                    }
                }

                // Save Logs Button
                Surface(
                    onClick = { saveLogsToFile(context, logs) },
                    color = MaterialTheme.colorScheme.primaryContainer,
                    shape = CircleShape,
                    modifier = Modifier.size(40.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(Icons.Default.FileDownload, stringResource(R.string.save_logs), modifier = Modifier.size(20.dp))
                    }
                }
            }
        }
        Spacer(Modifier.height(20.dp))
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(horizontal = 12.dp), 
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f))
        ) {
            if (logs.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.CloudQueue, null, modifier = Modifier.size(48.dp), tint = MaterialTheme.colorScheme.outline)
                        Spacer(Modifier.height(12.dp))
                        Text(stringResource(R.string.no_activity), color = MaterialTheme.colorScheme.outline)
                    }
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize().padding(16.dp),
                    contentPadding = PaddingValues(bottom = 16.dp)
                ) {
                    items(logs.size) { index ->
                        Text(
                            text = logs[index],
                            style = androidx.compose.ui.text.TextStyle(
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                fontSize = 12.sp
                            ),
                            modifier = Modifier.padding(vertical = 8.dp)
                        )
                        if (index < logs.size - 1) {
                            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                        }
                    }
                }
            }
        }
    }
}

private fun saveLogsToFile(context: Context, logs: Array<String>) {
    if (logs.isEmpty()) return
    try {
        val fileName = "OxidOH_Logs_${System.currentTimeMillis()}.txt"
        val downloadsDir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
        val file = java.io.File(downloadsDir, fileName)
        java.io.FileOutputStream(file).use { out ->
            logs.forEach { line -> out.write((line + "
").toByteArray()) }
        }
        android.media.MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), null, null)
        val msg = context.getString(R.string.saved_to_downloads)
        android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_SHORT).show()
    } catch (e: Exception) {
        Log.e("OxidOH", "Failed to save logs", e)
        val msg = context.getString(R.string.failed_save_logs)
        android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_SHORT).show()
    }
}
