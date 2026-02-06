package io.github.sms1sis.oxidoh.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Update
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.sms1sis.oxidoh.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun AboutDialog(onDismiss: () -> Unit, uriHandler: androidx.compose.ui.platform.UriHandler) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var checkingUpdate by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.about_title)) },
        text = {
            Column {
                Text(stringResource(R.string.version_info), fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.developer_info))
                Spacer(Modifier.height(16.dp))
                
                Button(
                    onClick = {
                        scope.launch {
                            checkingUpdate = true
                            checkForUpdates(context, uriHandler)
                            checkingUpdate = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !checkingUpdate,
                    shape = RoundedCornerShape(12.dp)
                ) {
                    if (checkingUpdate) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.checking))
                    } else {
                        Icon(Icons.Default.Update, null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.check_updates))
                    }
                }

                Spacer(Modifier.height(8.dp))
                TextButton(onClick = { uriHandler.openUri("https://github.com/sms1sis/OxidOH") }) {
                    Text(stringResource(R.string.view_github))
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) } }
    )
}

private suspend fun checkForUpdates(context: android.content.Context, uriHandler: androidx.compose.ui.platform.UriHandler) {
    val repoUrl = "https://api.github.com/repos/sms1sis/OxidOH/releases/latest"
    val currentVersion = "v0.1.1"

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