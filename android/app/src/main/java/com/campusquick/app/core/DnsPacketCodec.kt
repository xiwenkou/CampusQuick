package com.campusquick.app.core

/**
 * Zero-dependency IPv4 + UDP + DNS packet parser and synthesizer for Per-App Local DNS VPN.
 * Only handles DNS-over-UDP (port 53) packets routed through the local TUN interface.
 */
object DnsPacketCodec {

    private const val IP_PROTOCOL_ICMP = 1
    private const val IP_PROTOCOL_TCP = 6
    private const val IP_PROTOCOL_UDP = 17
    private const val DNS_PORT = 53
    private const val IPV4_HEADER_LEN = 20
    private const val ICMP_HEADER_LEN = 8
    private const val TCP_HEADER_LEN = 20
    private const val UDP_HEADER_LEN = 8
    private const val DNS_HEADER_LEN = 12

    private const val TCP_FLAG_FIN = 0x01
    private const val TCP_FLAG_SYN = 0x02
    private const val TCP_FLAG_RST = 0x04
    private const val TCP_FLAG_ACK = 0x10

    data class ParsedUdpPacket(
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val ihl: Int
    ) {
        val dstIpText: String
            get() = "${dstIp[0].toInt() and 0xFF}.${dstIp[1].toInt() and 0xFF}." +
                "${dstIp[2].toInt() and 0xFF}.${dstIp[3].toInt() and 0xFF}"
    }

    data class ParsedTcpPacket(
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val seqNum: Long,
        val ackNum: Long,
        val flags: Int,
        val payloadLength: Int
    ) {
        val dstIpText: String
            get() = "${dstIp[0].toInt() and 0xFF}.${dstIp[1].toInt() and 0xFF}." +
                "${dstIp[2].toInt() and 0xFF}.${dstIp[3].toInt() and 0xFF}"

        val isRst: Boolean get() = (flags and TCP_FLAG_RST) != 0
        val isSyn: Boolean get() = (flags and TCP_FLAG_SYN) != 0
        val isAck: Boolean get() = (flags and TCP_FLAG_ACK) != 0
    }

    data class ParsedDnsQuery(
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val dnsPayload: ByteArray,
        val domainName: String,
        val questionEndOffset: Int
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ParsedDnsQuery) return false
            return srcIp.contentEquals(other.srcIp) &&
                dstIp.contentEquals(other.dstIp) &&
                srcPort == other.srcPort &&
                dstPort == other.dstPort &&
                dnsPayload.contentEquals(other.dnsPayload) &&
                domainName == other.domainName &&
                questionEndOffset == other.questionEndOffset
        }

        override fun hashCode(): Int {
            var result = srcIp.contentHashCode()
            result = 31 * result + dstIp.contentHashCode()
            result = 31 * result + srcPort
            result = 31 * result + dstPort
            result = 31 * result + dnsPayload.contentHashCode()
            result = 31 * result + domainName.hashCode()
            result = 31 * result + questionEndOffset
            return result
        }
    }

    /**
     * Parses an IPv4 UDP DNS query packet from TUN. Returns null for non-IPv4, non-UDP,
     * non-port-53, or malformed packets.
     */
    fun parseIpv4UdpDnsQuery(packet: ByteArray, length: Int = packet.size): ParsedDnsQuery? {
        if (length < IPV4_HEADER_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN) return null

        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < IPV4_HEADER_LEN || length < ihl + UDP_HEADER_LEN + DNS_HEADER_LEN) return null

        val ipTotalLen = readU16(packet, 2)
        val effectiveLen = minOf(length, ipTotalLen)
        if (effectiveLen < ihl + UDP_HEADER_LEN + DNS_HEADER_LEN) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != IP_PROTOCOL_UDP) return null

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)

        val srcPort = readU16(packet, ihl)
        val dstPort = readU16(packet, ihl + 2)
        if (dstPort != DNS_PORT) return null

        val udpLen = readU16(packet, ihl + 4)
        if (udpLen < UDP_HEADER_LEN + DNS_HEADER_LEN) return null

        val dnsStart = ihl + UDP_HEADER_LEN
        val dnsEnd = minOf(effectiveLen, ihl + udpLen)
        if (dnsEnd - dnsStart < DNS_HEADER_LEN) return null

        val dnsPayload = packet.copyOfRange(dnsStart, dnsEnd)
        // Must be a standard query (QR == 0) with at least 1 question
        val flags = readU16(dnsPayload, 2)
        if ((flags and 0x8000) != 0) return null
        val qdCount = readU16(dnsPayload, 4)
        if (qdCount < 1) return null

        val parsedQ = parseQuestion(dnsPayload) ?: return null
        return ParsedDnsQuery(
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = srcPort,
            dstPort = dstPort,
            dnsPayload = dnsPayload,
            domainName = parsedQ.first,
            questionEndOffset = parsedQ.second
        )
    }

    /**
     * Synthesizes a valid IPv4/UDP DNS NXDOMAIN response packet for a blocked query.
     */
    fun buildNxdomainResponsePacket(query: ParsedDnsQuery): ByteArray {
        val dnsResp = ByteArray(query.questionEndOffset)
        System.arraycopy(query.dnsPayload, 0, dnsResp, 0, query.questionEndOffset)

        // Header flags: QR=1, preserve OPCODE & RD, RA=1, RCODE=3 (NXDOMAIN)
        val reqByte2 = query.dnsPayload[2].toInt() and 0xFF
        dnsResp[2] = ((reqByte2 and 0x79) or 0x80).toByte()
        dnsResp[3] = 0x83.toByte()

        // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        writeU16(dnsResp, 4, 1)
        writeU16(dnsResp, 6, 0)
        writeU16(dnsResp, 8, 0)
        writeU16(dnsResp, 10, 0)

        return wrapDnsResponseInIpv4Udp(query, dnsResp)
    }

    /**
     * Wraps a raw DNS response payload (either synthetic or forwarded from upstream)
     * in a valid IPv4 + UDP packet with swapped endpoints and freshly computed checksums.
     */
    fun wrapDnsResponseInIpv4Udp(query: ParsedDnsQuery, dnsResponse: ByteArray): ByteArray {
        val udpLen = UDP_HEADER_LEN + dnsResponse.size
        val totalLen = IPV4_HEADER_LEN + udpLen
        val out = ByteArray(totalLen)

        // IPv4 Header (20 bytes)
        out[0] = 0x45.toByte() // Version 4, IHL 5
        out[1] = 0x00
        writeU16(out, 2, totalLen)
        // Copy DNS transaction ID into IP identification for uniqueness
        out[4] = if (dnsResponse.size >= 2) dnsResponse[0] else 0
        out[5] = if (dnsResponse.size >= 2) dnsResponse[1] else 0
        out[6] = 0x40.toByte() // Don't Fragment
        out[7] = 0x00
        out[8] = 64.toByte() // TTL
        out[9] = IP_PROTOCOL_UDP.toByte()
        out[10] = 0x00
        out[11] = 0x00
        // Swap src <-> dst IP
        System.arraycopy(query.dstIp, 0, out, 12, 4)
        System.arraycopy(query.srcIp, 0, out, 16, 4)

        val ipChecksum = computeChecksum(out, 0, IPV4_HEADER_LEN)
        writeU16(out, 10, ipChecksum)

        // UDP Header (8 bytes) — swap src <-> dst port
        writeU16(out, IPV4_HEADER_LEN, query.dstPort)
        writeU16(out, IPV4_HEADER_LEN + 2, query.srcPort)
        writeU16(out, IPV4_HEADER_LEN + 4, udpLen)
        writeU16(out, IPV4_HEADER_LEN + 6, 0)

        // DNS Payload
        System.arraycopy(dnsResponse, 0, out, IPV4_HEADER_LEN + UDP_HEADER_LEN, dnsResponse.size)

        val udpChecksum = computeUdpChecksum(out, query.dstIp, query.srcIp, IPV4_HEADER_LEN, udpLen)
        writeU16(out, IPV4_HEADER_LEN + 6, udpChecksum)

        return out
    }

    /**
     * Parses QNAME and returns (domainName, offsetAfterQuestionSection).
     */
    private fun parseQuestion(dns: ByteArray): Pair<String, Int>? {
        var pos = DNS_HEADER_LEN
        val labels = ArrayList<String>(6)
        var guard = 0
        while (pos < dns.size && guard++ < 128) {
            val len = dns[pos].toInt() and 0xFF
            if (len == 0) {
                pos += 1
                break
            }
            // Reject compression pointers in query QNAME
            if ((len and 0xC0) != 0) return null
            if (pos + 1 + len > dns.size) return null
            labels.add(String(dns, pos + 1, len, Charsets.US_ASCII))
            pos += 1 + len
        }
        // Need 4 remaining bytes for QTYPE + QCLASS
        if (labels.isEmpty() || pos + 4 > dns.size) return null
        return Pair(labels.joinToString(".").lowercase(), pos + 4)
    }

    internal fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    internal fun computeUdpChecksum(
        packet: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        udpOffset: Int,
        udpLen: Int
    ): Int {
        var sum = 0L
        // IPv4 pseudo-header
        sum += readU16(srcIp, 0)
        sum += readU16(srcIp, 2)
        sum += readU16(dstIp, 0)
        sum += readU16(dstIp, 2)
        sum += IP_PROTOCOL_UDP
        sum += udpLen

        // UDP header + payload
        var i = udpOffset
        val end = udpOffset + udpLen
        while (i + 1 < end) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val result = (sum.inv() and 0xFFFF).toInt()
        // Per RFC 768, a computed checksum of 0 is transmitted as 0xFFFF
        return if (result == 0) 0xFFFF else result
    }

    /**
     * Parses an IPv4 TCP packet from TUN (used to reject direct-IP HTTPDNS/DoH bypasses
     * such as 119.29.29.29:80 with an instant local TCP RST instead of letting SYN hang).
     */
    fun parseIpv4TcpPacket(packet: ByteArray, length: Int = packet.size): ParsedTcpPacket? {
        if (length < IPV4_HEADER_LEN + TCP_HEADER_LEN) return null

        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < IPV4_HEADER_LEN || length < ihl + TCP_HEADER_LEN) return null

        val ipTotalLen = readU16(packet, 2)
        val effectiveLen = minOf(length, ipTotalLen)
        if (effectiveLen < ihl + TCP_HEADER_LEN) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != IP_PROTOCOL_TCP) return null

        val dataOffset = ((packet[ihl + 12].toInt() ushr 4) and 0x0F) * 4
        if (dataOffset < TCP_HEADER_LEN || effectiveLen < ihl + dataOffset) return null

        return ParsedTcpPacket(
            srcIp = packet.copyOfRange(12, 16),
            dstIp = packet.copyOfRange(16, 20),
            srcPort = readU16(packet, ihl),
            dstPort = readU16(packet, ihl + 2),
            seqNum = readU32(packet, ihl + 4),
            ackNum = readU32(packet, ihl + 8),
            flags = packet[ihl + 13].toInt() and 0xFF,
            payloadLength = effectiveLen - ihl - dataOffset
        )
    }

    /**
     * Synthesizes a valid RFC 793 IPv4/TCP RST (or RST+ACK for SYN) packet so blocked
     * direct-IP HTTPDNS connections fail in < 1 ms with ECONNREFUSED.
     * Returns null if the incoming segment already has RST set.
     */
    fun buildTcpRstResponsePacket(tcp: ParsedTcpPacket): ByteArray? {
        if (tcp.isRst) return null

        val totalLen = IPV4_HEADER_LEN + TCP_HEADER_LEN
        val out = ByteArray(totalLen)

        // IPv4 header
        out[0] = 0x45.toByte()
        out[1] = 0x00
        writeU16(out, 2, totalLen)
        writeU16(out, 4, (tcp.srcPort xor tcp.dstPort) and 0xFFFF)
        out[6] = 0x40.toByte() // DF
        out[7] = 0x00
        out[8] = 64.toByte() // TTL
        out[9] = IP_PROTOCOL_TCP.toByte()
        out[10] = 0x00
        out[11] = 0x00
        System.arraycopy(tcp.dstIp, 0, out, 12, 4)
        System.arraycopy(tcp.srcIp, 0, out, 16, 4)
        writeU16(out, 10, computeChecksum(out, 0, IPV4_HEADER_LEN))

        // TCP header (20 bytes)
        writeU16(out, IPV4_HEADER_LEN, tcp.dstPort)
        writeU16(out, IPV4_HEADER_LEN + 2, tcp.srcPort)

        val respSeq: Long
        val respAck: Long
        val respFlags: Int
        if (tcp.isAck) {
            respSeq = tcp.ackNum and 0xFFFFFFFFL
            respAck = 0L
            respFlags = TCP_FLAG_RST
        } else {
            val synFinAdvance =
                (if (tcp.isSyn) 1L else 0L) + (if ((tcp.flags and TCP_FLAG_FIN) != 0) 1L else 0L)
            respSeq = 0L
            respAck = (tcp.seqNum + tcp.payloadLength.toLong() + synFinAdvance) and 0xFFFFFFFFL
            respFlags = TCP_FLAG_RST or TCP_FLAG_ACK
        }

        writeU32(out, IPV4_HEADER_LEN + 4, respSeq)
        writeU32(out, IPV4_HEADER_LEN + 8, respAck)
        out[IPV4_HEADER_LEN + 12] = 0x50.toByte() // Data offset = 5 (20 bytes)
        out[IPV4_HEADER_LEN + 13] = respFlags.toByte()
        writeU16(out, IPV4_HEADER_LEN + 14, 0) // Window = 0
        writeU16(out, IPV4_HEADER_LEN + 16, 0) // Checksum placeholder
        writeU16(out, IPV4_HEADER_LEN + 18, 0) // Urgent pointer = 0

        val tcpChecksum = computeTransportChecksum(
            packet = out,
            srcIp = tcp.dstIp,
            dstIp = tcp.srcIp,
            protocol = IP_PROTOCOL_TCP,
            transportOffset = IPV4_HEADER_LEN,
            transportLen = TCP_HEADER_LEN
        )
        writeU16(out, IPV4_HEADER_LEN + 16, tcpChecksum)
        return out
    }

    /**
     * Parses any IPv4 UDP packet from TUN (used to detect and instantly reject non-DNS UDP such as
     * QUIC UDP/443 to cached ad-server IPs like 120.241.200.244:443).
     */
    fun parseIpv4UdpPacket(packet: ByteArray, length: Int = packet.size): ParsedUdpPacket? {
        if (length < IPV4_HEADER_LEN + UDP_HEADER_LEN) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < IPV4_HEADER_LEN || length < ihl + UDP_HEADER_LEN) return null
        val ipTotalLen = readU16(packet, 2)
        val effectiveLen = minOf(length, ipTotalLen)
        if (effectiveLen < ihl + UDP_HEADER_LEN) return null
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != IP_PROTOCOL_UDP) return null

        return ParsedUdpPacket(
            srcIp = packet.copyOfRange(12, 16),
            dstIp = packet.copyOfRange(16, 20),
            srcPort = readU16(packet, ihl),
            dstPort = readU16(packet, ihl + 2),
            ihl = ihl
        )
    }

    /**
     * Synthesizes a valid RFC 792 IPv4/ICMP Type 3 Code 3 (Port Unreachable) response for a
     * blocked UDP datagram (e.g. QUIC UDP/443), making connected UDP sockets fail with
     * ECONNREFUSED in < 1 ms instead of stalling on handshake timeouts.
     */
    fun buildIcmpPortUnreachablePacket(rawPacket: ByteArray, length: Int = rawPacket.size): ByteArray? {
        if (length < IPV4_HEADER_LEN + UDP_HEADER_LEN) return null
        val version = (rawPacket[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val ihl = (rawPacket[0].toInt() and 0x0F) * 4
        if (ihl < IPV4_HEADER_LEN || length < ihl + UDP_HEADER_LEN) return null
        val protocol = rawPacket[9].toInt() and 0xFF
        if (protocol == IP_PROTOCOL_ICMP) return null

        val ipTotalLen = readU16(rawPacket, 2)
        val effectiveLen = minOf(length, ipTotalLen)
        val quotedLen = minOf(ihl + 8, effectiveLen)
        if (quotedLen < IPV4_HEADER_LEN + 8) return null

        val icmpLen = ICMP_HEADER_LEN + quotedLen
        val totalLen = IPV4_HEADER_LEN + icmpLen
        val out = ByteArray(totalLen)

        // IPv4 header
        out[0] = 0x45.toByte()
        out[1] = 0x00
        writeU16(out, 2, totalLen)
        out[4] = rawPacket[4]
        out[5] = rawPacket[5]
        out[6] = 0x40.toByte() // DF
        out[7] = 0x00
        out[8] = 64.toByte() // TTL
        out[9] = IP_PROTOCOL_ICMP.toByte()
        out[10] = 0x00
        out[11] = 0x00
        // Swap src <-> dst IP
        System.arraycopy(rawPacket, 16, out, 12, 4)
        System.arraycopy(rawPacket, 12, out, 16, 4)
        writeU16(out, 10, computeChecksum(out, 0, IPV4_HEADER_LEN))

        // ICMP header: Type 3 (Dest Unreachable), Code 3 (Port Unreachable)
        out[IPV4_HEADER_LEN] = 3.toByte()
        out[IPV4_HEADER_LEN + 1] = 3.toByte()
        out[IPV4_HEADER_LEN + 2] = 0x00
        out[IPV4_HEADER_LEN + 3] = 0x00
        // Unused 4 bytes = 0
        System.arraycopy(rawPacket, 0, out, IPV4_HEADER_LEN + ICMP_HEADER_LEN, quotedLen)
        val icmpChecksum = computeChecksum(out, IPV4_HEADER_LEN, icmpLen)
        writeU16(out, IPV4_HEADER_LEN + 2, icmpChecksum)
        return out
    }

    /**
     * Builds a minimal RFC 1035 standard DNS A-record query payload (UDP/53) for internal
     * protected resolution of ad-server & business-allowlist IP addresses.
     */
    fun buildSimpleDnsAQuery(domain: String, txId: Int): ByteArray? {
        val cleaned = domain.trim().trimEnd('.').lowercase()
        if (cleaned.isEmpty()) return null
        val labels = cleaned.split('.')
        if (labels.any { it.isEmpty() || it.length > 63 }) return null

        val qnameLen = labels.sumOf { 1 + it.length } + 1
        val out = ByteArray(DNS_HEADER_LEN + qnameLen + 4)
        writeU16(out, 0, txId and 0xFFFF)
        out[2] = 0x01 // RD=1
        out[3] = 0x00
        writeU16(out, 4, 1) // QDCOUNT=1

        var pos = DNS_HEADER_LEN
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out[pos++] = bytes.size.toByte()
            System.arraycopy(bytes, 0, out, pos, bytes.size)
            pos += bytes.size
        }
        out[pos++] = 0x00
        writeU16(out, pos, 1) // QTYPE = A
        writeU16(out, pos + 2, 1) // QCLASS = IN
        return out
    }

    /**
     * Extracts all IPv4 A-record addresses from a raw DNS response payload, safely handling
     * CNAME records and RFC 1035 name compression pointers.
     */
    fun parseDnsARecordIps(dnsResp: ByteArray): List<String> {
        if (dnsResp.size < DNS_HEADER_LEN) return emptyList()
        val flags = readU16(dnsResp, 2)
        // Must be response (QR=1) with NOERROR (RCODE=0)
        if ((flags and 0x8000) == 0 || (flags and 0x000F) != 0) return emptyList()

        val qdCount = readU16(dnsResp, 4)
        val anCount = readU16(dnsResp, 6)
        if (anCount == 0) return emptyList()

        var pos = DNS_HEADER_LEN
        repeat(qdCount) {
            pos = skipDnsName(dnsResp, pos)
            if (pos < 0 || pos + 4 > dnsResp.size) return emptyList()
            pos += 4
        }

        val ips = ArrayList<String>(anCount)
        repeat(anCount) {
            pos = skipDnsName(dnsResp, pos)
            if (pos < 0 || pos + 10 > dnsResp.size) return ips
            val rType = readU16(dnsResp, pos)
            val rClass = readU16(dnsResp, pos + 2)
            val rdLen = readU16(dnsResp, pos + 8)
            pos += 10
            if (pos + rdLen > dnsResp.size) return ips
            if (rType == 1 && rClass == 1 && rdLen == 4) {
                val ip = "${dnsResp[pos].toInt() and 0xFF}." +
                    "${dnsResp[pos + 1].toInt() and 0xFF}." +
                    "${dnsResp[pos + 2].toInt() and 0xFF}." +
                    "${dnsResp[pos + 3].toInt() and 0xFF}"
                ips.add(ip)
            }
            pos += rdLen
        }
        return ips
    }

    private fun skipDnsName(dns: ByteArray, startOffset: Int): Int {
        var pos = startOffset
        var guard = 0
        while (pos < dns.size && guard++ < 128) {
            val len = dns[pos].toInt() and 0xFF
            if (len == 0) return pos + 1
            if ((len and 0xC0) == 0xC0) {
                return if (pos + 2 <= dns.size) pos + 2 else -1
            }
            pos += 1 + len
        }
        return -1
    }

    internal fun computeTransportChecksum(
        packet: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        protocol: Int,
        transportOffset: Int,
        transportLen: Int
    ): Int {
        var sum = 0L
        sum += readU16(srcIp, 0)
        sum += readU16(srcIp, 2)
        sum += readU16(dstIp, 0)
        sum += readU16(dstIp, 2)
        sum += protocol
        sum += transportLen

        var i = transportOffset
        val end = transportOffset + transportLen
        while (i + 1 < end) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun readU16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    private fun readU32(buf: ByteArray, offset: Int): Long =
        ((buf[offset].toLong() and 0xFF) shl 24) or
            ((buf[offset + 1].toLong() and 0xFF) shl 16) or
            ((buf[offset + 2].toLong() and 0xFF) shl 8) or
            (buf[offset + 3].toLong() and 0xFF)

    private fun writeU16(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeU32(buf: ByteArray, offset: Int, value: Long) {
        buf[offset] = ((value ushr 24) and 0xFF).toByte()
        buf[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        buf[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 3] = (value and 0xFF).toByte()
    }
}
