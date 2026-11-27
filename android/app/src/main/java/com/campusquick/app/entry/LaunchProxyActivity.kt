package com.campusquick.app.entry

import android.app.Activity
import android.os.Bundle
import com.campusquick.app.core.RouteLauncher
import com.campusquick.app.data.PresetRepository
import com.campusquick.app.vpn.VpnLifecycleManager
import com.campusquick.app.vpn.VpnStatsStore

/**
 * Zero-delay translucent entry proxy invoked by pinned shortcuts, home screen widgets,
 * Control Center QS Tile, and NFC door-frame tags.
 *
 * If the user enabled built-in local ad-blocking but the OEM background cleaner (e.g. OriginOS
 * single-cleaner) killed the VPN service or ClashMeta was recently turned off, this proxy
 * transparently revives tun0 (~50 ms) BEFORE launching the target app so ad-blocking never misses.
 */
class LaunchProxyActivity : Activity() {

    @Suppress("DEPRECATION")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val presetId = intent?.getStringExtra(EXTRA_PRESET_ID)
            ?: intent?.data?.lastPathSegment
        val preset = PresetRepository.findById(this, presetId)

        if (VpnLifecycleManager.startIfEligible(this, preset.targetPackage)) {
            Thread({
                VpnStatsStore.awaitTunnelReady(AUTO_REVIVE_WAIT_MS)
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        RouteLauncher.launch(this, preset)
                        finish()
                        overridePendingTransition(0, 0)
                    }
                }
            }, "CampusQuick-VpnRevive").start()
        } else {
            RouteLauncher.launch(this, preset)
            finish()
            overridePendingTransition(0, 0)
        }
    }

    companion object {
        const val EXTRA_PRESET_ID = "extra_preset_id"
        private const val AUTO_REVIVE_WAIT_MS = 400L
    }
}
