package io.github.sms1sis.oxidoh

import android.content.Intent
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class ProxyTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onStopListening() {
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        // Optimistically update the tile to UNAVAILABLE while we wait,
        // so the user gets immediate visual feedback.
        qsTile?.let { tile ->
            tile.state = Tile.STATE_UNAVAILABLE
            tile.updateTile()
        }

        if (ProxyService.isProxyRunning) {
            val intent = Intent(this, ProxyService::class.java).apply { action = "STOP" }
            startService(intent)
        } else {
            val intent = Intent(this, ProxyService::class.java)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        }
        // Poll state twice: once quickly for fast stops, once slower for slow starts
        android.os.Handler(mainLooper).postDelayed({ updateTile() }, 400)
        android.os.Handler(mainLooper).postDelayed({ updateTile() }, 1500)
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val isRunning = ProxyService.isProxyRunning
        tile.state = if (isRunning) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.tile_label)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            tile.subtitle = if (isRunning) getString(R.string.tile_active) else getString(R.string.tile_inactive)
        }
        tile.updateTile()
    }
}
