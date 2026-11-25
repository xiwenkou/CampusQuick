package com.campusquick.app.core

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat

data class BleProximityState(
    val scanning: Boolean = false,
    val deviceName: String? = null,
    val rssi: Int? = null,
    val zoneLabel: String = "未开启探测",
    val safeToUnlock: Boolean = false
)

/**
 * Monitors BLE lock proximity (RSSI) to warn users before triggering the lock SDK's
 * hardcoded 31-second BLE reconnect timeout (status=62) when tapping unlock too far from the door.
 */
class BleProximityMonitor(
    private val context: Context,
    private val onStateChanged: (BleProximityState) -> Unit
) {
    private var scanner: BluetoothLeScanner? = null
    private var activePrefix: String = "MVL"
    private var scanning = false

    private val scanCallback = object : ScanCallback() {
        @SuppressLint("MissingPermission")
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val name = result.device?.name ?: result.scanRecord?.deviceName ?: return
            if (!name.startsWith(activePrefix, ignoreCase = true)) return
            val rssi = result.rssi
            val (label, safe) = classifyRssi(rssi)
            onStateChanged(
                BleProximityState(
                    scanning = true,
                    deviceName = name,
                    rssi = rssi,
                    zoneLabel = label,
                    safeToUnlock = safe
                )
            )
        }

        override fun onScanFailed(errorCode: Int) {
            scanning = false
            onStateChanged(
                BleProximityState(
                    scanning = false,
                    zoneLabel = "蓝牙扫描失败 (code=$errorCode)"
                )
            )
        }
    }

    fun hasScanPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_SCAN
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    @SuppressLint("MissingPermission")
    fun start(namePrefix: String): Boolean {
        if (scanning) stop()
        if (!hasScanPermission()) return false
        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = bm?.adapter
        if (adapter == null || !adapter.isEnabled) {
            onStateChanged(BleProximityState(scanning = false, zoneLabel = "请先开启手机蓝牙"))
            return false
        }
        val leScanner = adapter.bluetoothLeScanner ?: return false
        activePrefix = namePrefix.trim().ifEmpty { "MVL" }
        scanner = leScanner
        scanning = true

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        leScanner.startScan(null, settings, scanCallback)
        onStateChanged(
            BleProximityState(
                scanning = true,
                zoneLabel = "正在搜索前缀为 \"$activePrefix\" 的近场门锁信号…（走近门前 1 米内将自动变绿）"
            )
        )
        return true
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        if (!scanning) return
        try {
            scanner?.stopScan(scanCallback)
        } catch (_: Exception) {
        }
        scanning = false
        onStateChanged(BleProximityState(scanning = false, zoneLabel = "未开启探测"))
    }

    companion object {
        fun classifyRssi(rssi: Int): Pair<String, Boolean> = when {
            rssi >= -68 -> "已到门前 (${rssi} dBm) · 可立即秒开" to true
            rssi >= -82 -> "接近门锁 (${rssi} dBm) · 建议再靠近至 1 米内" to false
            else -> "距离较远 (${rssi} dBm) · 请勿提前点开锁（防 31 秒卡顿）" to false
        }
    }
}
