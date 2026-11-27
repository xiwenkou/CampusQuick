package com.campusquick.app.core

import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.PowerManager
import com.campusquick.app.model.RoutePreset
import com.campusquick.app.vpn.VpnStatsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

enum class CheckLevel { PASS, WARN, FAIL }

data class DiagnosticItem(
    val title: String,
    val status: CheckLevel,
    val detail: String
)

object DiagnosticsEngine {

    private val PROBE_AD_HOSTS = listOf(
        "mores.anythinktech.com" to 443,
        "sdk.beizi.biz" to 443,
        "open.e.kuaishou.cn" to 443,
        "v2mi.gdt.qq.com" to 443
    )

    suspend fun runAll(context: Context, preset: RoutePreset): List<DiagnosticItem> =
        withContext(Dispatchers.IO) {
            listOf(
                probeAdBlocking(),
                checkTargetAppAndDeepLink(context, preset),
                checkBatteryWhitelist(context, preset.targetPackage),
                checkBluetoothAndLocation(context),
                checkVpnEnvironment(context)
            )
        }

    /**
     * Real network probe: verifies both DNS-level sinkhole (Per-App VPN NXDOMAIN / 0.0.0.0)
     * and TUN-level SNI REJECT (ClashMeta / sing-box accepts local TCP SYN before resetting on TLS ClientHello).
     */
    private fun probeAdBlocking(): DiagnosticItem {
        var blockedCount = 0
        val reachable = mutableListOf<String>()

        for ((host, port) in PROBE_AD_HOSTS) {
            val isBlocked = isHostBlocked(host, port)
            if (isBlocked) {
                blockedCount++
            } else {
                reachable.add(host)
            }
        }

        return when {
            blockedCount == PROBE_AD_HOSTS.size -> DiagnosticItem(
                title = "广告拦截实测探针",
                status = CheckLevel.PASS,
                detail = "已拦截 TopOn / 倍孜 / 快手联盟 / 腾讯优量汇核心广告域（${blockedCount}/${PROBE_AD_HOSTS.size} 命中拒绝）"
            )
            blockedCount > 0 -> DiagnosticItem(
                title = "广告拦截实测探针",
                status = CheckLevel.WARN,
                detail = "部分放行：${reachable.joinToString()} 仍可达，建议更新去广告规则"
            )
            else -> DiagnosticItem(
                title = "广告拦截实测探针",
                status = CheckLevel.WARN,
                detail = "当前广告域可达：请开启上方「本地去广告 VPN」或在 ClashMeta 启用去广告规则"
            )
        }
    }

    private fun isHostBlocked(host: String, port: Int): Boolean {
        return try {
            val addrs = InetAddress.getAllByName(host)
            if (addrs.isEmpty()) return true
            val first = addrs[0]
            if (first.isAnyLocalAddress || first.isLoopbackAddress) return true

            val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            Socket().use { rawSock ->
                rawSock.soTimeout = 1500
                rawSock.connect(InetSocketAddress(first, port), 1500)
                val sslSock = sslFactory.createSocket(rawSock, host, port, true) as SSLSocket
                sslSock.use { s ->
                    s.soTimeout = 1500
                    // Triggers SNI inspection in ClashMeta / sing-box TUN; REJECT closes/resets here
                    s.startHandshake()
                }
            }
            false
        } catch (_: Exception) {
            // UnknownHostException (NXDOMAIN), ConnectException / SocketException / EOFException (REJECT/RST)
            true
        }
    }

    private fun checkTargetAppAndDeepLink(context: Context, preset: RoutePreset): DiagnosticItem {
        val pm = context.packageManager
        val pkgInfo = try {
            pm.getPackageInfo(preset.targetPackage, 0)
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }
        if (pkgInfo == null) {
            return DiagnosticItem(
                title = "目标应用与直达协议",
                status = CheckLevel.FAIL,
                detail = "未安装 ${preset.targetPackage}"
            )
        }
        val intent = RouteLauncher.buildTargetIntent(preset)
        val resolved = pm.resolveActivity(intent, 0)
        return if (resolved != null) {
            DiagnosticItem(
                title = "目标应用与直达协议",
                status = CheckLevel.PASS,
                detail = "v${pkgInfo.versionName ?: "?"} 已就绪，DeepLink 可直达 (${resolved.activityInfo.name.substringAfterLast('.')})"
            )
        } else {
            DiagnosticItem(
                title = "目标应用与直达协议",
                status = CheckLevel.WARN,
                detail = "已安装 v${pkgInfo.versionName ?: "?"}，但未匹配该直达协议，请检查 URI"
            )
        }
    }

    private fun checkBatteryWhitelist(context: Context, targetPackage: String): DiagnosticItem {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        val selfExempt = pm.isIgnoringBatteryOptimizations(context.packageName)
        val targetExempt = pm.isIgnoringBatteryOptimizations(targetPackage)
        return when {
            selfExempt && targetExempt -> DiagnosticItem(
                title = "后台保活（电池优化白名单）",
                status = CheckLevel.PASS,
                detail = "CampusQuick 与 $targetPackage 均已在系统 Doze 白名单中（防后台杀 VPN、减少冷启动）"
            )
            !selfExempt -> DiagnosticItem(
                title = "后台保活（电池优化白名单）",
                status = CheckLevel.WARN,
                detail = "CampusQuick 自身尚未加入电池白名单，后台可能被系统清理导致本地 VPN 掉线；请点下方按钮一键放行"
            )
            else -> DiagnosticItem(
                title = "后台保活（电池优化白名单）",
                status = CheckLevel.WARN,
                detail = "$targetPackage 尚未加入电池白名单，建议点下方按钮设为不限制以保持 0.35s 热启"
            )
        }
    }

    private fun checkBluetoothAndLocation(context: Context): DiagnosticItem {
        val btOn = RouteLauncher.isBluetoothEnabled(context)
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val locOn = lm.isLocationEnabled
        return when {
            btOn && locOn -> DiagnosticItem(
                title = "蓝牙与定位就绪状态",
                status = CheckLevel.PASS,
                detail = "蓝牙已开启 · 系统定位已开启（满足 BLE 门锁连接要求）"
            )
            !btOn && !locOn -> DiagnosticItem(
                title = "蓝牙与定位就绪状态",
                status = CheckLevel.FAIL,
                detail = "蓝牙与定位均未开启，BLE 门锁将无法连接"
            )
            !btOn -> DiagnosticItem(
                title = "蓝牙与定位就绪状态",
                status = CheckLevel.FAIL,
                detail = "蓝牙未开启，开锁前请打开蓝牙"
            )
            else -> DiagnosticItem(
                title = "蓝牙与定位就绪状态",
                status = CheckLevel.WARN,
                detail = "蓝牙已开启，但系统定位未开启（部分 Android 机型 BLE 门锁需开启定位）"
            )
        }
    }

    private fun checkVpnEnvironment(context: Context): DiagnosticItem {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val active = cm.activeNetwork
        val caps = if (active != null) cm.getNetworkCapabilities(active) else null
        val anyVpnActive = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val localVpnRunning = VpnStatsStore.state.value.running

        return when {
            localVpnRunning -> DiagnosticItem(
                title = "去广告网络模式",
                status = CheckLevel.PASS,
                detail = "正在使用内置 Per-App 本地 DNS VPN（仅过滤目标 App，零外部代理）"
            )
            anyVpnActive -> DiagnosticItem(
                title = "去广告网络模式",
                status = CheckLevel.PASS,
                detail = "检测到外部 VPN（如 ClashMeta / Sing-box）运行中，推荐直接导入规则集避免 VPN 冲突"
            )
            else -> DiagnosticItem(
                title = "去广告网络模式",
                status = CheckLevel.WARN,
                detail = "未检测到代理 VPN，可直接开启内置「本地去广告 VPN」实现零依赖去广告"
            )
        }
    }
}
