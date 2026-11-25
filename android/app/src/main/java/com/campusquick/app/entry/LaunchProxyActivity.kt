package com.campusquick.app.entry

import android.app.Activity
import android.os.Bundle
import com.campusquick.app.core.RouteLauncher
import com.campusquick.app.data.PresetRepository

/**
 * Zero-delay translucent entry proxy invoked by pinned shortcuts, home screen widgets,
 * Control Center QS Tile, and NFC door-frame tags.
 */
class LaunchProxyActivity : Activity() {

    @Suppress("DEPRECATION")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val presetId = intent?.getStringExtra(EXTRA_PRESET_ID)
            ?: intent?.data?.lastPathSegment
        val preset = PresetRepository.findById(this, presetId)
        RouteLauncher.launch(this, preset)
        finish()
        overridePendingTransition(0, 0)
    }

    companion object {
        const val EXTRA_PRESET_ID = "extra_preset_id"
    }
}
