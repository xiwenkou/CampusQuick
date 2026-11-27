package com.campusquick.app

import com.campusquick.app.core.DnsPacketCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class DnsPacketCodecTest {

    private fun buildSampleIpv4UdpDnsQuery(domain: String, txId: Int = 0x1234): ByteArray {
        val dns = ByteArrayOutputStream().apply {
            // TxID
            write((txId ushr 8) and 0xFF)
            write(txId and 0xFF)
            // Flags: standard query RD=1
            write(0x01)
            write(0x00)
            // QDCOUNT=1, AN=0, NS=0, AR=0
            write(0x00); write(0x01)
            write(0x00); write(0x00)
            write(0x00); write(0x00)
            write(0x00); write(0x00)
            // QNAME
            for (label in domain.split(".")) {
                val bytes = label.toByteArray(Charsets.US_ASCII)
                write(bytes.size)
                write(bytes)
            }
            write(0x00)
            // QTYPE=A (1), QCLASS=IN (1)
            write(0x00); write(0x01)
            write(0x00); write(0x01)
        }.toByteArray()

        val udpLen = 8 + dns.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45.toByte()
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64
        pkt[9] = 17 // UDP
        // src = 10.120.0.1, dst = 10.120.0.2
        pkt[12] = 10; pkt[13] = 120; pkt[14] = 0; pkt[15] = 1
        pkt[16] = 10; pkt[17] = 120; pkt[18] = 0; pkt[19] = 2
        val ipSum = DnsPacketCodec.computeChecksum(pkt, 0, 20)
        pkt[10] = ((ipSum ushr 8) and 0xFF).toByte()
        pkt[11] = (ipSum and 0xFF).toByte()
        // UDP srcPort=54321, dstPort=53
        pkt[20] = ((54321 ushr 8) and 0xFF).toByte()
        pkt[21] = (54321 and 0xFF).toByte()
        pkt[22] = 0
        pkt[23] = 53
        pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        System.arraycopy(dns, 0, pkt, 28, dns.size)
        return pkt
    }

    @Test
    fun parsesValidDnsQueryAndBuildsValidNxdomainPacket() {
        val raw = buildSampleIpv4UdpDnsQuery("datk.anythinktech.com", 0xABCD)
        val parsed = DnsPacketCodec.parseIpv4UdpDnsQuery(raw)
        assertNotNull(parsed)
        parsed!!

        assertEquals("datk.anythinktech.com", parsed.domainName)
        assertEquals(54321, parsed.srcPort)
        assertEquals(53, parsed.dstPort)

        val resp = DnsPacketCodec.buildNxdomainResponsePacket(parsed)
        // Verify IPv4 header checksum validates to 0
        assertEquals(0, DnsPacketCodec.computeChecksum(resp, 0, 20))
        // Verify src/dst IPs were swapped (10.120.0.2 -> 10.120.0.1)
        assertEquals(2, resp[15].toInt() and 0xFF)
        assertEquals(1, resp[19].toInt() and 0xFF)
        // Verify UDP ports were swapped (53 -> 54321)
        val respSrcPort = ((resp[20].toInt() and 0xFF) shl 8) or (resp[21].toInt() and 0xFF)
        val respDstPort = ((resp[22].toInt() and 0xFF) shl 8) or (resp[23].toInt() and 0xFF)
        assertEquals(53, respSrcPort)
        assertEquals(54321, respDstPort)
        // Verify DNS TxID preserved and QR=1, RCODE=3 (NXDOMAIN)
        assertEquals(0xAB, resp[28].toInt() and 0xFF)
        assertEquals(0xCD, resp[29].toInt() and 0xFF)
        assertTrue((resp[30].toInt() and 0x80) != 0)
        assertEquals(3, resp[31].toInt() and 0x0F)
    }

    @Test
    fun rejectsNonDnsOrTruncatedPackets() {
        assertNull(DnsPacketCodec.parseIpv4UdpDnsQuery(ByteArray(10)))
        val tcpPkt = buildSampleIpv4UdpDnsQuery("biz.confong.cn").also { it[9] = 6 }
        assertNull(DnsPacketCodec.parseIpv4UdpDnsQuery(tcpPkt))
        val nonDnsPort = buildSampleIpv4UdpDnsQuery("biz.confong.cn").also { it[23] = 80 }
        assertNull(DnsPacketCodec.parseIpv4UdpDnsQuery(nonDnsPort))
    }

    @Test
    fun parsesTcpSynAndSynthesizesValidRstAckForDirectHttpDnsBypass() {
        // Build 40-byte IPv4/TCP SYN from 10.120.0.1:45678 -> 119.29.29.29:80
        val syn = ByteArray(40)
        syn[0] = 0x45.toByte()
        syn[2] = 0
        syn[3] = 40
        syn[8] = 64
        syn[9] = 6 // TCP
        syn[12] = 10; syn[13] = 120; syn[14] = 0; syn[15] = 1
        syn[16] = 119; syn[17] = 29; syn[18] = 29; syn[19] = 29
        val ipSum = DnsPacketCodec.computeChecksum(syn, 0, 20)
        syn[10] = ((ipSum ushr 8) and 0xFF).toByte()
        syn[11] = (ipSum and 0xFF).toByte()
        // srcPort=45678, dstPort=80, seq=1000, dataOffset=5 (0x50), flags=SYN(0x02)
        syn[20] = ((45678 ushr 8) and 0xFF).toByte()
        syn[21] = (45678 and 0xFF).toByte()
        syn[22] = 0; syn[23] = 80
        syn[24] = 0; syn[25] = 0; syn[26] = 0x03; syn[27] = 0xE8.toByte()
        syn[32] = 0x50.toByte()
        syn[33] = 0x02.toByte()

        val parsed = DnsPacketCodec.parseIpv4TcpPacket(syn)
        assertNotNull(parsed)
        parsed!!
        assertEquals("119.29.29.29", parsed.dstIpText)
        assertEquals(80, parsed.dstPort)
        assertTrue(parsed.isSyn)

        val rst = DnsPacketCodec.buildTcpRstResponsePacket(parsed)
        assertNotNull(rst)
        rst!!
        assertEquals(40, rst.size)
        // IPv4 header checksum validates to 0
        assertEquals(0, DnsPacketCodec.computeChecksum(rst, 0, 20))
        // TCP checksum validates to 0
        val tcpCheck = DnsPacketCodec.computeTransportChecksum(
            packet = rst,
            srcIp = rst.copyOfRange(12, 16),
            dstIp = rst.copyOfRange(16, 20),
            protocol = 6,
            transportOffset = 20,
            transportLen = 20
        )
        assertEquals(0, tcpCheck)
        // Swapped src/dst ports: 80 -> 45678
        assertEquals(80, ((rst[20].toInt() and 0xFF) shl 8) or (rst[21].toInt() and 0xFF))
        assertEquals(45678, ((rst[22].toInt() and 0xFF) shl 8) or (rst[23].toInt() and 0xFF))
        // Flags = RST|ACK (0x14), ack = 1001
        assertEquals(0x14, rst[33].toInt() and 0xFF)
        val ackNum = ((rst[28].toLong() and 0xFF) shl 24) or
            ((rst[29].toLong() and 0xFF) shl 16) or
            ((rst[30].toLong() and 0xFF) shl 8) or
            (rst[31].toLong() and 0xFF)
        assertEquals(1001L, ackNum)

        // Incoming RST must NOT generate a reply (avoid RST loops)
        val rstParsed = DnsPacketCodec.parseIpv4TcpPacket(rst)
        assertNotNull(rstParsed)
        assertNull(DnsPacketCodec.buildTcpRstResponsePacket(rstParsed!!))
    }

    @Test
    fun parsesQuicUdp443AndSynthesizesValidIcmpPortUnreachable() {
        // Build 48-byte IPv4/UDP packet from 10.120.0.1:41234 -> 120.241.200.244:443 (GDT QUIC)
        val udp = ByteArray(48)
        udp[0] = 0x45.toByte()
        udp[2] = 0; udp[3] = 48
        udp[4] = 0x22; udp[5] = 0x33
        udp[8] = 64
        udp[9] = 17 // UDP
        udp[12] = 10; udp[13] = 120; udp[14] = 0; udp[15] = 1
        udp[16] = 120; udp[17] = 241.toByte(); udp[18] = 200.toByte(); udp[19] = 244.toByte()
        val ipSum = DnsPacketCodec.computeChecksum(udp, 0, 20)
        udp[10] = ((ipSum ushr 8) and 0xFF).toByte()
        udp[11] = (ipSum and 0xFF).toByte()
        // srcPort=41234, dstPort=443, udpLen=28
        udp[20] = ((41234 ushr 8) and 0xFF).toByte()
        udp[21] = (41234 and 0xFF).toByte()
        udp[22] = ((443 ushr 8) and 0xFF).toByte()
        udp[23] = (443 and 0xFF).toByte()
        udp[24] = 0; udp[25] = 28

        val parsed = DnsPacketCodec.parseIpv4UdpPacket(udp)
        assertNotNull(parsed)
        parsed!!
        assertEquals("120.241.200.244", parsed.dstIpText)
        assertEquals(443, parsed.dstPort)

        val icmp = DnsPacketCodec.buildIcmpPortUnreachablePacket(udp)
        assertNotNull(icmp)
        icmp!!
        // 20 (IPv4) + 8 (ICMP) + 28 (quoted IPv4+UDP header) = 56 bytes
        assertEquals(56, icmp.size)
        // IPv4 protocol = ICMP (1), header checksum validates to 0
        assertEquals(1, icmp[9].toInt() and 0xFF)
        assertEquals(0, DnsPacketCodec.computeChecksum(icmp, 0, 20))
        // Swapped src <-> dst IP (120.241.200.244 -> 10.120.0.1)
        assertEquals(120, icmp[12].toInt() and 0xFF)
        assertEquals(244, icmp[15].toInt() and 0xFF)
        assertEquals(10, icmp[16].toInt() and 0xFF)
        assertEquals(1, icmp[19].toInt() and 0xFF)
        // ICMP Type 3 (Destination Unreachable), Code 3 (Port Unreachable), ICMP checksum validates to 0
        assertEquals(3, icmp[20].toInt() and 0xFF)
        assertEquals(3, icmp[21].toInt() and 0xFF)
        assertEquals(0, DnsPacketCodec.computeChecksum(icmp, 20, 36))

        // Must never reply ICMP to ICMP (prevents ICMP error loops)
        assertNull(DnsPacketCodec.buildIcmpPortUnreachablePacket(icmp))
    }

    @Test
    fun buildsSimpleDnsAQueryAndParsesCompressedARecordResponse() {
        val query = DnsPacketCodec.buildSimpleDnsAQuery("v2mi.gdt.qq.com", 0x55AA)
        assertNotNull(query)
        query!!
        assertEquals(0x55, query[0].toInt() and 0xFF)
        assertEquals(0xAA, query[1].toInt() and 0xFF)

        // Build DNS response mirroring the question + 1 CNAME + 2 A records (112.53.5.61, 120.241.200.244)
        val resp = ByteArrayOutputStream().apply {
            write(query)
            // CNAME answer using pointer 0xC0 0x0C -> dummy target 0x01 'a' 0x00
            write(0xC0); write(0x0C)
            write(0x00); write(0x05) // TYPE=CNAME
            write(0x00); write(0x01) // CLASS=IN
            write(0x00); write(0x00); write(0x00); write(0x3C) // TTL=60
            write(0x00); write(0x03) // RDLEN=3
            write(0x01); write('a'.code); write(0x00)
            // A record #1: 112.53.5.61
            write(0xC0); write(0x0C)
            write(0x00); write(0x01) // TYPE=A
            write(0x00); write(0x01) // CLASS=IN
            write(0x00); write(0x00); write(0x00); write(0x3C)
            write(0x00); write(0x04) // RDLEN=4
            write(112); write(53); write(5); write(61)
            // A record #2: 120.241.200.244
            write(0xC0); write(0x0C)
            write(0x00); write(0x01)
            write(0x00); write(0x01)
            write(0x00); write(0x00); write(0x00); write(0x3C)
            write(0x00); write(0x04)
            write(120); write(241); write(200); write(244)
        }.toByteArray()
        // Mark response QR=1, ANCOUNT=3
        resp[2] = 0x81.toByte()
        resp[3] = 0x80.toByte()
        resp[6] = 0x00; resp[7] = 0x03

        val ips = DnsPacketCodec.parseDnsARecordIps(resp)
        assertEquals(listOf("112.53.5.61", "120.241.200.244"), ips)
    }
}
