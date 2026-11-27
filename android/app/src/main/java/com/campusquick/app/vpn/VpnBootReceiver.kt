package com.campusquick.app.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Automatically restores the Per-App Local AdBlock VPN after device reboot or app upgrade
 * if the user previously enabled it and no external VPN (e.g. ClashMeta) is active.
 */
class VpnBootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == Intent.ACTION_BOOT_COMPLETED ||
            action == Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            VpnLifecycleManager.startIfEligible(context)
        }
    }
}
