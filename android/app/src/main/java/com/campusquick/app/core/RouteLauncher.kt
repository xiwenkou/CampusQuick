package com.campusquick.app.core

import android.bluetooth.BluetoothManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.ShortcutInfo
import android.content.pm.ShortcutManager
import android.graphics.drawable.Icon
import android.net.Uri
import android.widget.Toast
import com.campusquick.app.R
import com.campusquick.app.entry.LaunchProxyActivity
import com.campusquick.app.model.RoutePreset

object RouteLauncher {

    fun buildTargetIntent(preset: RoutePreset): Intent {
        return Intent(Intent.ACTION_VIEW, Uri.parse(preset.uri)).apply {
            setPackage(preset.targetPackage)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    fun launch(context: Context, preset: RoutePreset): Boolean {
        if (preset.requiresBluetooth && !isBluetoothEnabled(context)) {
            Toast.makeText(
                context,
                "提示：手机蓝牙未开启，开锁前请先打开蓝牙",
                Toast.LENGTH_SHORT
            ).show()
        }
        return try {
            context.startActivity(buildTargetIntent(preset))
            true
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(
                context,
                "未找到目标应用 (${preset.targetPackage}) 或不支持该直达协议",
                Toast.LENGTH_LONG
            ).show()
            false
        } catch (e: Exception) {
            Toast.makeText(
                context,
                "拉起失败: ${e.message}",
                Toast.LENGTH_SHORT
            ).show()
            false
        }
    }

    fun pinShortcutToHome(context: Context, preset: RoutePreset): Boolean {
        val shortcutManager = context.getSystemService(ShortcutManager::class.java) ?: return false
        if (!shortcutManager.isRequestPinShortcutSupported) {
            Toast.makeText(context, "当前桌面不支持固定快捷方式", Toast.LENGTH_SHORT).show()
            return false
        }
        val proxyIntent = Intent(context, LaunchProxyActivity::class.java).apply {
            action = Intent.ACTION_VIEW
            putExtra(LaunchProxyActivity.EXTRA_PRESET_ID, preset.id)
        }
        val info = ShortcutInfo.Builder(context, "cq_${preset.id}")
            .setShortLabel(preset.name)
            .setLongLabel(preset.name)
            .setIcon(Icon.createWithResource(context, R.mipmap.ic_launcher))
            .setIntent(proxyIntent)
            .build()
        shortcutManager.requestPinShortcut(info, null)
        return true
    }

    fun isBluetoothEnabled(context: Context): Boolean {
        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        return bm?.adapter?.isEnabled == true
    }
}
