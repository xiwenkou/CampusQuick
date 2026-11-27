package com.campusquick.app.vpn

import com.campusquick.app.core.DnsPacketCodec
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Resolves and maintains the Per-App direct-IP sinkhole set for:
 * 1. Static HTTPDNS / DoH / DoT bypass IPs (including Tencent GDT enterprise failover IPs
 *    119.29.29.98/99, 119.28.28.98/99 and gdt.dot.pub 1.12.34.56 extracted from gdtadv2.jar).
 * 2. Dynamic regional ad-API server IPs (e.g. v2mi/v3/c3.gdt.qq.com QUIC UDP/443 endpoints)
 *    that SDKs persist on disk and reconnect to directly without issuing a new DNS lookup.
 *
 * Safety invariant: every dynamic candidate IP is checked against live-resolved IPs of
 * `business_allowlist` domains AND private/Alibaba-HTTPDNS subnets before inclusion so
 * shared CDN edges can never disrupt business traffic.
 */
object AdIpSinkholeResolver {

    private val txIdGen = AtomicInteger(0x4100)

    // Hardcoded direct-IP HTTPDNS / DoH / DoT resolvers used by ad SDKs (GDT yaq3_0.sec, etc.).
    // Note: Alibaba MTOP httpdns.alicdn.com (203.107.1.x) is deliberately NOT in this list.
    val STATIC_HTTPDNS_BLOCK_IPS: Set<String> = linkedSetOf(
        "119.29.29.29",
        "119.28.28.28",
        "119.29.29.98",
        "119.28.28.98",
        "119.29.29.99",
        "119.28.28.99",
        "182.254.116.116",
        "182.254.118.118",
        "1.12.12.12",
        "1.12.34.56",
        "120.53.53.53",
        "180.76.76.76",
        "223.5.5.5",
        "223.6.6.6",
        "114.114.114.114",
        "114.114.115.115"
    )

    // Dedicated ad-API servers (non-shared-CDN) whose SDKs cache IPs or use QUIC UDP/443.
    // Deliberately excludes shared ByteDance/Volcengine CDN edges (gromore/mssdk) that may share
    // China Mobile CDN nodes with business domains.
    val DYNAMIC_SINKHOLE_AD_HOSTS: List<String> = listOf(
        "v2mi.gdt.qq.com",
        "v3.gdt.qq.com",
        "v3mi.gdt.qq.com",
        "mi.gdt.qq.com",
        "v2.gdt.qq.com",
        "c2.gdt.qq.com",
        "c3.gdt.qq.com",
        "sdk.e.qq.com",
        "gdt.dot.pub",
        "sdk.beizi.biz",
        "cn-api.anythinktech.com",
        "apiv4.anythinktech.com",
        "datk.anythinktech.com",
        "open.e.kuaishou.cn",
        "open.e.kuaishou.com",
        "g-api.kwai.com",
        "mobads.baidu.com",
        "songzhaopian.com"
    )

    private val UPSTREAM_DNS = listOf("223.5.5.5", "119.29.29.29")

    /**
     * Resolves [DYNAMIC_SINKHOLE_AD_HOSTS] and [businessAllowlist] in parallel via protected
     * UDP/53 sockets, returning ONLY safe public ad-server IPv4 addresses that do not collide
     * with any business allowlist IP or reserved range.
     */
    fun resolveSafeDynamicAdIps(
        businessAllowlist: Collection<String>,
        protectSocket: (DatagramSocket) -> Boolean
    ): Set<String> {
        val pool = Executors.newFixedThreadPool(6)
        try {
            val bizTasks = businessAllowlist.distinct().map { host ->
                Callable { queryARecords(host, protectSocket) }
            }
            val adTasks = DYNAMIC_SINKHOLE_AD_HOSTS.map { host ->
                Callable { queryARecords(host, protectSocket) }
            }

            val protectedIps = HashSet<String>()
            val bizFutures = pool.invokeAll(bizTasks, 2500L, TimeUnit.MILLISECONDS)
            for (f in bizFutures) {
                if (f.isDone && !f.isCancelled) {
                    try {
                        protectedIps.addAll(f.get())
                    } catch (_: Exception) {
                    }
                }
            }

            // Safety gate: if every single business domain failed to resolve (offline / DNS down),
            // do not risk guessing dynamic routes; keep existing cached set or static list.
            if (businessAllowlist.isNotEmpty() && protectedIps.isEmpty()) {
                return emptySet()
            }

            val candidateIps = LinkedHashSet<String>()
            val adFutures = pool.invokeAll(adTasks, 2500L, TimeUnit.MILLISECONDS)
            for (f in adFutures) {
                if (f.isDone && !f.isCancelled) {
                    try {
                        candidateIps.addAll(f.get())
                    } catch (_: Exception) {
                    }
                }
            }

            return filterSafeSinkholeIps(candidateIps, protectedIps)
        } catch (_: Exception) {
            return emptySet()
        } finally {
            pool.shutdownNow()
        }
    }

    /**
     * Pure collision & safety filter (unit-tested on JVM).
     */
    fun filterSafeSinkholeIps(
        candidateIps: Collection<String>,
        protectedBusinessIps: Set<String>
    ): Set<String> {
        val out = LinkedHashSet<String>()
        for (raw in candidateIps) {
            val ip = raw.trim()
            if (!isSafePublicSinkholeIpv4(ip)) continue
            if (ip in protectedBusinessIps) continue
            if (ip in STATIC_HTTPDNS_BLOCK_IPS) continue
            out.add(ip)
        }
        return out
    }

    internal fun isSafePublicSinkholeIpv4(ip: String): Boolean {
        val parts = ip.split('.')
        if (parts.size != 4) return false
        val octets = IntArray(4)
        for (i in 0 until 4) {
            val v = parts[i].toIntOrNull() ?: return false
            if (v !in 0..255) return false
            octets[i] = v
        }
        val a = octets[0]
        val b = octets[1]
        // Reject RFC 1918, loopback, link-local, CGNAT, multicast, zero, broadcast
        if (a == 0 || a == 10 || a == 127 || a >= 224) return false
        if (a == 100 && b in 64..127) return false
        if (a == 169 && b == 254) return false
        if (a == 172 && b in 16..31) return false
        if (a == 192 && b == 168) return false
        // Never block Alibaba MTOP HTTPDNS subnet (203.107.1.0/24)
        if (a == 203 && b == 107 && octets[2] == 1) return false
        return true
    }

    private fun queryARecords(
        host: String,
        protectSocket: (DatagramSocket) -> Boolean
    ): List<String> {
        val txId = txIdGen.incrementAndGet() and 0xFFFF
        val queryBytes = DnsPacketCodec.buildSimpleDnsAQuery(host, txId) ?: return emptyList()
        for (upstream in UPSTREAM_DNS) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                if (!protectSocket(socket)) continue
                socket.soTimeout = 1200
                val addr = InetAddress.getByName(upstream)
                socket.send(DatagramPacket(queryBytes, queryBytes.size, addr, 53))
                val buf = ByteArray(1500)
                val resp = DatagramPacket(buf, buf.size)
                socket.receive(resp)
                val ips = DnsPacketCodec.parseDnsARecordIps(buf.copyOf(resp.length))
                if (ips.isNotEmpty()) return ips
            } catch (_: Exception) {
                // Try next upstream resolver
            } finally {
                socket?.close()
            }
        }
        return emptyList()
    }
}
