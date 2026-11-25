package com.campusquick.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.campusquick.app.R
import com.campusquick.app.core.AdBlockMatcher
import com.campusquick.app.core.DnsPacketCodec
import com.campusquick.app.data.RuleRepository
import com.campusquick.app.ui.MainActivity
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Per-App Local DNS-Filtering VpnService.
 *
 * Design highlights:
 * - Uses addAllowedApplication(targetPackage) so ONLY the target campus app's DNS traffic is captured.
 * - Routes ONLY virtual DNS server 10.120.0.2/32 into TUN; all normal HTTPS/TCP/BLE traffic flows natively.
 * - Blocked ad domains receive an instant local NXDOMAIN (< 1 ms); allowed domains forward via protect()-ed UDP.
 */
class AdBlockVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var readerThread: Thread? = null
    private var workerPool: ExecutorService? = null
    private val running = AtomicBoolean(false)
    private val tunWriteLock = Any()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                val targetPkg = intent?.getStringExtra(EXTRA_TARGET_PACKAGE)
                    ?: RuleRepository.loadBundledRules(this).targetPackage
                startVpn(targetPkg)
                return START_STICKY
            }
        }
    }

    private fun startVpn(targetPackage: String) {
        if (running.get() && vpnInterface != null) return
        running.set(true)

        val rules = RuleRepository.loadBundledRules(this)
        val matcher = AdBlockMatcher(rules)

        ensureNotificationChannel()
        val notification = buildNotification(targetPackage)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        val builder = Builder()
            .setSession("CampusQuick Local AdBlock")
            .setMtu(1500)
            .setBlocking(true)
            .addAddress(VPN_CLIENT_IP, 32)
            .addDnsServer(VPN_DNS_IP)
            .addRoute(VPN_DNS_IP, 32)

        try {
            builder.addAllowedApplication(targetPackage)
            // Also include self so DiagnosticsEngine probes traverse the real local TUN end-to-end;
            // upstream DNS forwarding uses literal IPv4s via protect(socket), so no loop occurs.
            if (targetPackage != packageName) {
                builder.addAllowedApplication(packageName)
            }
        } catch (e: PackageManager.NameNotFoundException) {
            running.set(false)
            VpnStatsStore.setRunning(false, targetPackage, "未安装目标应用: $targetPackage")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val tun = builder.establish()
        if (tun == null) {
            running.set(false)
            VpnStatsStore.setRunning(false, targetPackage, "VPN 权限未授予或被系统占用")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        vpnInterface = tun
        val pool = Executors.newFixedThreadPool(4)
        workerPool = pool
        VpnStatsStore.setRunning(true, targetPackage, null)
        Log.i(TAG, "Per-App local DNS VPN established for $targetPackage (+self probe)")

        val tunOut = FileOutputStream(tun.fileDescriptor)
        val tunIn = FileInputStream(tun.fileDescriptor)

        readerThread = Thread({
            val buf = ByteArray(2048)
            try {
                while (running.get()) {
                    val len = tunIn.read(buf)
                    if (len < 0) break
                    if (len == 0) {
                        Thread.sleep(10)
                        continue
                    }
                    val packetCopy = buf.copyOf(len)
                    val query = DnsPacketCodec.parseIpv4UdpDnsQuery(packetCopy, len) ?: continue

                    if (matcher.shouldBlock(query.domainName)) {
                        Log.d(TAG, "BLOCK ${query.domainName}")
                        val nxResp = DnsPacketCodec.buildNxdomainResponsePacket(query)
                        writeToTun(tunOut, nxResp)
                        VpnStatsStore.recordBlocked(query.domainName)
                    } else {
                        Log.d(TAG, "ALLOW ${query.domainName}")
                        pool.execute {
                            val upstreamResp = forwardDnsUpstream(query.dnsPayload)
                            if (upstreamResp != null && running.get()) {
                                val wrapped = DnsPacketCodec.wrapDnsResponseInIpv4Udp(query, upstreamResp)
                                writeToTun(tunOut, wrapped)
                                VpnStatsStore.recordAllowed()
                            }
                        }
                    }
                }
            } catch (_: Exception) {
                // Expected when TUN fd closes on stopVpn()
            } finally {
                val shouldStopSelf = running.get()
                stopVpn()
                if (shouldStopSelf) {
                    stopSelf()
                }
            }
        }, "CampusQuick-DnsLoop").apply {
            isDaemon = true
            start()
        }
    }

    private fun writeToTun(out: FileOutputStream, packet: ByteArray) {
        synchronized(tunWriteLock) {
            try {
                out.write(packet)
            } catch (_: Exception) {
                // Ignore write error during teardown
            }
        }
    }

    private fun forwardDnsUpstream(dnsQuery: ByteArray): ByteArray? {
        for (upstreamIp in UPSTREAM_DNS_SERVERS) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                if (!protect(socket)) continue
                socket.soTimeout = UPSTREAM_TIMEOUT_MS
                val addr = InetAddress.getByName(upstreamIp)
                val reqPacket = DatagramPacket(dnsQuery, dnsQuery.size, addr, 53)
                socket.send(reqPacket)

                val respBuf = ByteArray(1500)
                val respPacket = DatagramPacket(respBuf, respBuf.size)
                socket.receive(respPacket)
                return respBuf.copyOf(respPacket.length)
            } catch (_: Exception) {
                // Try next upstream server
            } finally {
                socket?.close()
            }
        }
        return null
    }

    private fun stopVpn() {
        running.set(false)
        workerPool?.shutdownNow()
        workerPool = null
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
        readerThread?.interrupt()
        readerThread = null
        VpnStatsStore.setRunning(false, VpnStatsStore.state.value.targetPackage, null)
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onRevoke() {
        stopVpn()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun ensureNotificationChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "本地去广告引擎",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "仅对目标校园 App 的广告域名执行本地 DNS 过滤，不经过外部服务器"
                setShowBadge(false)
            }
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(targetPackage: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java)
        val openPi = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = Intent(this, AdBlockVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPi = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_tile_unlock)
            .setContentTitle("CampusQuick 本地去广告运行中")
            .setContentText("仅接管 $targetPackage 广告 DNS，零外部代理")
            .setOngoing(true)
            .setContentIntent(openPi)
            .addAction(
                Notification.Action.Builder(null, "停止", stopPi).build()
            )
            .build()
    }

    companion object {
        const val ACTION_START = "com.campusquick.app.vpn.START"
        const val ACTION_STOP = "com.campusquick.app.vpn.STOP"
        const val EXTRA_TARGET_PACKAGE = "extra_target_package"

        private const val TAG = "CampusQuickVPN"
        private const val VPN_CLIENT_IP = "10.120.0.1"
        private const val VPN_DNS_IP = "10.120.0.2"
        private const val UPSTREAM_TIMEOUT_MS = 2500
        private val UPSTREAM_DNS_SERVERS = listOf("223.5.5.5", "119.29.29.29")

        private const val CHANNEL_ID = "campusquick_local_vpn"
        private const val NOTIFICATION_ID = 2001
    }
}
