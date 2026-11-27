package com.campusquick.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import com.campusquick.app.R
import com.campusquick.app.core.AdBlockMatcher
import com.campusquick.app.core.DnsPacketCodec
import com.campusquick.app.data.PresetRepository
import com.campusquick.app.data.RuleRepository
import com.campusquick.app.ui.MainActivity
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Per-App Local DNS, Direct-IP HTTPDNS & QUIC Ad-Server Sinkhole VpnService.
 *
 * Design highlights:
 * - Uses addAllowedApplication(targetPackage) so ONLY the target campus app's traffic is affected.
 * - Routes virtual DNS 10.120.0.2/32, static direct-IP HTTPDNS/DoH/DoT resolvers (including GDT
 *   enterprise failover IPs 119.29.29.98/99, 119.28.28.98/99, 1.12.34.56), AND dynamically resolved
 *   regional ad-API server IPs (e.g. v2mi/v3/c3.gdt.qq.com QUIC UDP/443 endpoints, protected by a
 *   live business_allowlist IP collision guard) into TUN.
 * - Blocked ad DNS -> instant local NXDOMAIN (< 1 ms).
 * - Blocked direct-IP TCP -> instant RFC 793 TCP RST+ACK (< 1 ms).
 * - Blocked direct-IP QUIC/UDP -> instant RFC 792 ICMP Type 3 Code 3 Port Unreachable (< 1 ms).
 * - Automatically refreshes underlying networks & regional ad-server IPs across Wi-Fi <-> 5G handoffs.
 */
class AdBlockVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var readerThread: Thread? = null
    private var workerPool: ExecutorService? = null
    private var refreshExecutor: ExecutorService? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val running = AtomicBoolean(false)
    private val tunnelGeneration = AtomicInteger(0)
    private val vpnLock = Any()
    private val tunWriteLock = Any()
    private val udpLogThrottle = ConcurrentHashMap<String, Long>()

    @Volatile
    private var activeTargetPackage: String = "com.tmall.campus.and"

    @Volatile
    private var activeDynamicSinkholeIps: Set<String> = emptySet()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                // Explicit user stop disables auto-revive until the user turns it back on.
                PresetRepository.setAutoVpnEnabled(this, false)
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                val targetPkg = intent?.getStringExtra(EXTRA_TARGET_PACKAGE)
                    ?.takeIf { it.isNotBlank() }
                    ?: PresetRepository.getVpnTargetPackage(this).takeIf { it.isNotBlank() }
                    ?: RuleRepository.loadBundledRules(this).targetPackage
                PresetRepository.setAutoVpnEnabled(this, true)
                PresetRepository.setVpnTargetPackage(this, targetPkg)
                startVpn(targetPkg)
                return START_STICKY
            }
        }
    }

    private fun startVpn(targetPackage: String) {
        synchronized(vpnLock) {
            if (running.get() && vpnInterface != null && activeTargetPackage == targetPackage) {
                VpnStatsStore.setRunning(true, targetPackage, null)
                return
            }
            activeTargetPackage = targetPackage
            running.set(true)

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

            if (workerPool == null || workerPool?.isShutdown == true) {
                workerPool = Executors.newFixedThreadPool(4)
            }
            if (refreshExecutor == null || refreshExecutor?.isShutdown == true) {
                refreshExecutor = Executors.newSingleThreadExecutor()
            }

            val cachedDynamic = PresetRepository.getCachedAdSinkholeIps(this)
            val ok = establishTunnelLocked(targetPackage, cachedDynamic)
            if (!ok) {
                running.set(false)
                tunnelActive.set(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            registerUnderlyingNetworkMonitor()
        }

        // Refresh regional ad-server QUIC/direct IPs asynchronously without delaying startup
        scheduleDynamicAdIpRefresh(targetPackage)
    }

    private fun establishTunnelLocked(targetPackage: String, dynamicIps: Set<String>): Boolean {
        val rules = RuleRepository.loadBundledRules(this)
        val matcher = AdBlockMatcher(rules)
        val safeDynamic = AdIpSinkholeResolver.filterSafeSinkholeIps(dynamicIps, emptySet())
        val allSinkholeIps = LinkedHashSet<String>().apply {
            addAll(AdIpSinkholeResolver.STATIC_HTTPDNS_BLOCK_IPS)
            addAll(safeDynamic)
        }

        val builder = Builder()
            .setSession("CampusQuick Local AdBlock")
            .setMtu(1500)
            .setBlocking(true)
            .addAddress(VPN_CLIENT_IP, 32)
            .addDnsServer(VPN_DNS_IP)
            .addRoute(VPN_DNS_IP, 32)

        for (sinkholeIp in allSinkholeIps) {
            try {
                builder.addRoute(sinkholeIp, 32)
            } catch (_: Exception) {
            }
        }

        try {
            builder.addAllowedApplication(targetPackage)
            // Also include self so DiagnosticsEngine probes traverse the real local TUN end-to-end;
            // upstream DNS forwarding uses literal IPv4s via protect(socket), so no loop occurs.
            if (targetPackage != packageName) {
                builder.addAllowedApplication(packageName)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            VpnStatsStore.setRunning(false, targetPackage, "未安装目标应用: $targetPackage")
            return false
        }

        val newTun = builder.establish()
        if (newTun == null) {
            VpnStatsStore.setRunning(false, targetPackage, "VPN 权限未授予或被其他 VPN 占用")
            return false
        }

        val gen = tunnelGeneration.incrementAndGet()
        val oldTun = vpnInterface
        val oldReader = readerThread

        vpnInterface = newTun
        activeDynamicSinkholeIps = safeDynamic
        tunnelActive.set(true)
        VpnStatsStore.setSinkholeIpCount(allSinkholeIps.size)
        VpnStatsStore.setRunning(true, targetPackage, null)
        Log.i(
            TAG,
            "Per-App local DNS + direct-IP/QUIC VPN established for $targetPackage " +
                "(gen=$gen, staticHttpDns=${AdIpSinkholeResolver.STATIC_HTTPDNS_BLOCK_IPS.size}, " +
                "dynamicAdIps=${safeDynamic.size})"
        )

        val pool = workerPool ?: Executors.newFixedThreadPool(4).also { workerPool = it }
        val tunOut = FileOutputStream(newTun.fileDescriptor)
        val tunIn = FileInputStream(newTun.fileDescriptor)

        readerThread = Thread({
            runPacketLoop(gen, tunIn, tunOut, matcher, pool)
        }, "CampusQuick-DnsLoop-$gen").apply {
            isDaemon = true
            start()
        }

        // Tear down replaced TUN after replacement is already live
        if (oldTun != null) {
            try {
                oldTun.close()
            } catch (_: Exception) {
            }
            oldReader?.interrupt()
        }

        return true
    }

    private fun runPacketLoop(
        gen: Int,
        tunIn: FileInputStream,
        tunOut: FileOutputStream,
        matcher: AdBlockMatcher,
        pool: ExecutorService
    ) {
        val buf = ByteArray(2048)
        try {
            while (running.get() && tunnelGeneration.get() == gen) {
                val len = tunIn.read(buf)
                if (len < 0) break
                if (len == 0) {
                    Thread.sleep(10)
                    continue
                }
                val packetCopy = buf.copyOf(len)

                // Path 1: UDP/53 DNS query (virtual 10.120.0.2 or direct public DNS IP)
                val query = DnsPacketCodec.parseIpv4UdpDnsQuery(packetCopy, len)
                if (query != null) {
                    if (matcher.shouldBlock(query.domainName)) {
                        Log.d(TAG, "BLOCK ${query.domainName}")
                        val nxResp = DnsPacketCodec.buildNxdomainResponsePacket(query)
                        writeToTun(tunOut, nxResp)
                        VpnStatsStore.recordBlocked(query.domainName)
                    } else {
                        Log.d(TAG, "ALLOW ${query.domainName}")
                        pool.execute {
                            val upstreamResp = forwardDnsUpstream(query.dnsPayload)
                            if (upstreamResp != null && running.get() && tunnelGeneration.get() == gen) {
                                val wrapped = DnsPacketCodec.wrapDnsResponseInIpv4Udp(query, upstreamResp)
                                writeToTun(tunOut, wrapped)
                                VpnStatsStore.recordAllowed()
                            }
                        }
                    }
                    continue
                }

                // Path 2: Direct-IP HTTPDNS / DoH / Ad-API TCP -> instant RFC 793 TCP RST+ACK
                val tcp = DnsPacketCodec.parseIpv4TcpPacket(packetCopy, len)
                if (tcp != null) {
                    val rst = DnsPacketCodec.buildTcpRstResponsePacket(tcp)
                    if (rst != null) {
                        writeToTun(tunOut, rst)
                        if (tcp.isSyn && !tcp.isAck) {
                            val prefix = if (tcp.dstIpText in AdIpSinkholeResolver.STATIC_HTTPDNS_BLOCK_IPS) {
                                "HTTPDNS"
                            } else {
                                "DIRECT-IP"
                            }
                            val label = "$prefix ${tcp.dstIpText}:${tcp.dstPort}"
                            Log.d(TAG, "BLOCK $label")
                            VpnStatsStore.recordBlocked(label)
                        }
                    }
                    continue
                }

                // Path 3: Direct-IP QUIC / DoH-H3 UDP (e.g. GDT 120.241.200.244:443) -> instant ICMP Port Unreachable
                val udp = DnsPacketCodec.parseIpv4UdpPacket(packetCopy, len)
                if (udp != null) {
                    val icmpUnreach = DnsPacketCodec.buildIcmpPortUnreachablePacket(packetCopy, len)
                    if (icmpUnreach != null) {
                        writeToTun(tunOut, icmpUnreach)
                    }
                    val key = "${udp.dstIpText}:${udp.dstPort}"
                    val now = SystemClock.elapsedRealtime()
                    val last = udpLogThrottle[key] ?: 0L
                    if (now - last >= 500L) {
                        udpLogThrottle[key] = now
                        val label = "QUIC/UDP $key"
                        Log.d(TAG, "BLOCK $label")
                        VpnStatsStore.recordBlocked(label)
                    }
                }
            }
        } catch (_: Exception) {
            // Expected when TUN fd closes on stopVpn() or seamless generation rebuild
        } finally {
            // Only stop the service if THIS generation is still the active one (not replaced by rebuild)
            if (running.get() && tunnelGeneration.get() == gen) {
                stopVpn()
                stopSelf()
            }
        }
    }

    private fun scheduleDynamicAdIpRefresh(targetPackage: String) {
        val exec = refreshExecutor ?: return
        try {
            exec.execute {
                if (!running.get()) return@execute
                val rules = RuleRepository.loadBundledRules(this)
                val resolved = AdIpSinkholeResolver.resolveSafeDynamicAdIps(rules.allowlist) { sock ->
                    protect(sock)
                }
                if (!running.get() || resolved.isEmpty()) return@execute

                PresetRepository.setCachedAdSinkholeIps(this, resolved)
                synchronized(vpnLock) {
                    if (!running.get()) return@synchronized
                    if (resolved != activeDynamicSinkholeIps) {
                        Log.i(
                            TAG,
                            "Dynamic ad-server IP set updated (${activeDynamicSinkholeIps.size} -> ${resolved.size}), rebuilding TUN seamlessly"
                        )
                        establishTunnelLocked(targetPackage, resolved)
                    }
                }
            }
        } catch (_: Exception) {
        }
    }

    private fun registerUnderlyingNetworkMonitor() {
        if (networkCallback != null) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        try {
            setUnderlyingNetworks(null)
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    try {
                        setUnderlyingNetworks(null)
                    } catch (_: Exception) {
                    }
                    // Carrier/Wi-Fi handoff can change regional GDT QUIC edge IPs; refresh asynchronously
                    if (running.get()) {
                        scheduleDynamicAdIpRefresh(activeTargetPackage)
                    }
                }

                override fun onLost(network: Network) {
                    try {
                        setUnderlyingNetworks(null)
                    } catch (_: Exception) {
                    }
                }
            }
            cm.registerDefaultNetworkCallback(cb)
            networkCallback = cb
        } catch (_: Exception) {
        }
    }

    private fun unregisterUnderlyingNetworkMonitor() {
        val cb = networkCallback ?: return
        networkCallback = null
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        try {
            cm.unregisterNetworkCallback(cb)
        } catch (_: Exception) {
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
        synchronized(vpnLock) {
            running.set(false)
            tunnelActive.set(false)
            tunnelGeneration.incrementAndGet()
            unregisterUnderlyingNetworkMonitor()
            workerPool?.shutdownNow()
            workerPool = null
            refreshExecutor?.shutdownNow()
            refreshExecutor = null
            try {
                vpnInterface?.close()
            } catch (_: Exception) {
            }
            vpnInterface = null
            readerThread?.interrupt()
            readerThread = null
            udpLogThrottle.clear()
            VpnStatsStore.setRunning(false, VpnStatsStore.state.value.targetPackage, null)
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    override fun onRevoke() {
        // Keep auto-protect preference intact so CampusQuick seamlessly restores once ClashMeta exits.
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
                description = "仅对目标校园 App 的广告 DNS、直连 HTTPDNS 与 QUIC 广告节点执行本地过滤，不经过外部服务器"
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
            .setContentText("仅接管 $targetPackage 广告 DNS / HTTPDNS / QUIC · 零外部代理")
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
        private const val UPSTREAM_TIMEOUT_MS = 1500
        private val UPSTREAM_DNS_SERVERS = listOf("223.5.5.5", "119.29.29.29", "223.6.6.6")

        private const val CHANNEL_ID = "campusquick_local_vpn"
        private const val NOTIFICATION_ID = 2001

        private val tunnelActive = AtomicBoolean(false)

        fun isTunnelActive(): Boolean = tunnelActive.get()
    }
}
