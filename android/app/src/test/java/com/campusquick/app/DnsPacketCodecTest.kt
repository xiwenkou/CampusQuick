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
}
