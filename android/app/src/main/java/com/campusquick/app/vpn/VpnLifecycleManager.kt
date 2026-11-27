package com.campusquick.app.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.campusquick.app.data.PresetRepository

/**
 * Coordinates Per-App Local VPN auto-recovery across OEM background kills (e.g. OriginOS
 * single-cleaner), device reboots, and temporary external VPN (ClashMeta/sing-box) usage.
 */
object VpnLifecycleManager {

    /**
     * Returns true when a third-party VPN (such as ClashMeta or sing-box) owns the active
     * VPN transport while our own local tunnel is NOT running.
     */
    @Suppress("DEPRECATION")
    fun hasExternalVpnActive(context: Context): Boolean {
        if (AdBlockVpnService.isTunnelActive()) return false
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        val activeCaps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
        if (activeCaps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
            return true
        }
        return cm.allNetworks.any { net ->
            cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }

    /**
     * Checks whether the user wants automatic local ad-blocking protection AND we can legally
     * restore it right now without disturbing any third-party VPN or prompting UI.
     */
    fun needsAutoRevive(context: Context): Boolean {
        if (AdBlockVpnService.isTunnelActive()) return false
        if (!PresetRepository.isAutoVpnEnabled(context)) return false
        if (hasExternalVpnActive(context)) return false
        return VpnService.prepare(context) == null
    }

    /**
     * Starts AdBlockVpnService if auto-protection is enabled, no external VPN is running,
     * and VPN consent was previously granted. Returns true if a start request was dispatched.
     */
    fun startIfEligible(context: Context, targetPackage: String? = null): Boolean {
        if (!needsAutoRevive(context)) return false
        val pkg = targetPackage?.takeIf { it.isNotBlank() }
            ?: PresetRepository.getVpnTargetPackage(context)
        val intent = Intent(context, AdBlockVpnService::class.java).apply {
            action = AdBlockVpnService.ACTION_START
            putExtra(AdBlockVpnService.EXTRA_TARGET_PACKAGE, pkg)
        }
        return try {
            ContextCompat.startForegroundService(context, intent)
            true
        } catch (_: Exception) {
            false
        }
    }
}
