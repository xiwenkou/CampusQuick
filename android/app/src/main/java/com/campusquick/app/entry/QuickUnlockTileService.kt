package com.campusquick.app.entry

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.campusquick.app.data.PresetRepository

class QuickUnlockTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        val tile = qsTile ?: return
        val preset = PresetRepository.getSelectedPreset(this)
        tile.state = Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = preset.name
        }
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        unlockAndRun {
            launchSelectedPreset()
        }
    }

    @Suppress("DEPRECATION")
    private fun launchSelectedPreset() {
        val preset = PresetRepository.getSelectedPreset(this)
        val proxyIntent = Intent(this, LaunchProxyActivity::class.java).apply {
            putExtra(LaunchProxyActivity.EXTRA_PRESET_ID, preset.id)
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_NO_ANIMATION
            )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pi = PendingIntent.getActivity(
                this,
                1001,
                proxyIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            startActivityAndCollapse(pi)
        } else {
            startActivityAndCollapse(proxyIntent)
        }
    }
}
