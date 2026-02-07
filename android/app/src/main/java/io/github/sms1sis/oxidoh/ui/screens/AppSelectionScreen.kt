package io.github.sms1sis.oxidoh.ui.screens

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import io.github.sms1sis.oxidoh.R

data class AppInfo(
    val name: String,
    val packageName: String,
    val icon: android.graphics.drawable.Drawable
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppSelectionScreen(
    excludedApps: Set<String>,
    onBack: () -> Unit,
    onToggleApp: (String) -> Unit
) {
    val context = LocalContext.current
    val pm = remember { context.packageManager }
    var searchQuery by remember { mutableStateOf("") }
    
    val allApps = remember {
        pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 || it.packageName == "com.google.android.projection.gearhead" }
            .map { AppInfo(it.loadLabel(pm).toString(), it.packageName, it.loadIcon(pm)) }
            .sortedBy { it.name.lowercase() }
    }

    val filteredApps = remember(searchQuery) {
        if (searchQuery.isBlank()) allApps
        else allApps.filter { it.name.contains(searchQuery, ignoreCase = true) || it.packageName.contains(searchQuery, ignoreCase = true) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_exclusion)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                placeholder = { Text(stringResource(R.string.search_apps)) },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                shape = RoundedCornerShape(16.dp),
                singleLine = true
            )

            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(filteredApps, key = { it.packageName }) { app ->
                    val isExcluded = excludedApps.contains(app.packageName)
                    ListItem(
                        headlineContent = { Text(app.name, fontWeight = FontWeight.SemiBold) },
                        supportingContent = { Text(app.packageName, style = MaterialTheme.typography.bodySmall) },
                        leadingContent = {
                            Image(
                                bitmap = app.icon.toBitmap().asImageBitmap(),
                                contentDescription = null,
                                modifier = Modifier.size(40.dp)
                            )
                        },
                        trailingContent = {
                            Switch(
                                checked = isExcluded,
                                onCheckedChange = { onToggleApp(app.packageName) }
                            )
                        },
                        modifier = Modifier.padding(horizontal = 8.dp)
                    )
                }
            }
        }
    }
}
