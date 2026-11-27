package com.campusquick.app

import com.campusquick.app.core.AdSkipMatcher
import com.campusquick.app.vpn.AdIpSinkholeResolver
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdIpSinkholeAndSkipTest {

    @Test
    fun sinkholeFilterBlocksGdtQuicIpWhileProtectingBusinessAndPrivateIps() {
        val candidates = listOf(
            "120.241.200.244", // GDT v2mi.gdt.qq.com QUIC edge -> MUST INCLUDE
            "112.53.5.61",     // GDT v2mi/v3.gdt.qq.com -> MUST INCLUDE
            "120.226.18.11",   // Shared CMCC CDN overlapping biz.confong.cn -> MUST EXCLUDE
            "203.107.1.33",    // Alibaba MTOP HTTPDNS range -> MUST EXCLUDE
            "10.120.0.2",      // Private RFC1918 -> MUST EXCLUDE
            "127.0.0.1",       // Loopback -> MUST EXCLUDE
            "119.29.29.98",    // Already in STATIC_HTTPDNS_BLOCK_IPS -> deduplicated
            "not-an-ip"
        )
        val businessIps = setOf("120.226.18.11", "106.11.43.249")

        val safe = AdIpSinkholeResolver.filterSafeSinkholeIps(candidates, businessIps)
        assertEquals(setOf("120.241.200.244", "112.53.5.61"), safe)
    }

    @Test
    fun staticHttpDnsListCoversGdtEnterpriseFailoverAndDotPubIps() {
        val staticIps = AdIpSinkholeResolver.STATIC_HTTPDNS_BLOCK_IPS
        assertTrue("119.29.29.29" in staticIps)
        assertTrue("119.29.29.98" in staticIps)
        assertTrue("119.28.28.98" in staticIps)
        assertTrue("119.29.29.99" in staticIps)
        assertTrue("119.28.28.99" in staticIps)
        assertTrue("1.12.34.56" in staticIps)
        assertFalse("203.107.1.1" in staticIps)
    }

    @Test
    fun adSkipMatcherMatchesExactSkipLabelsAndRejectsNormalText() {
        assertTrue(AdSkipMatcher.isSkipLabel("跳过"))
        assertTrue(AdSkipMatcher.isSkipLabel("跳过广告"))
        assertTrue(AdSkipMatcher.isSkipLabel("跳过 5"))
        assertTrue(AdSkipMatcher.isSkipLabel("跳过 3s"))
        assertTrue(AdSkipMatcher.isSkipLabel("5s 跳过"))
        assertTrue(AdSkipMatcher.isSkipLabel("跳过|4"))
        assertTrue(AdSkipMatcher.isSkipLabel("跳过(3)"))
        assertTrue(AdSkipMatcher.isSkipLabel("关闭广告"))

        assertFalse(AdSkipMatcher.isSkipLabel(""))
        assertFalse(AdSkipMatcher.isSkipLabel("跳过此步骤进入设置"))
        assertFalse(AdSkipMatcher.isSkipLabel("一键开锁"))
        assertFalse(AdSkipMatcher.isSkipLabel("点击查看详情"))

        assertTrue(AdSkipMatcher.isSplashOrAdContext("com.tmall.campus.launcher.SplashActivity"))
        assertTrue(AdSkipMatcher.isSplashOrAdContext("com.tmall.campus.launcher.HotSplashActivity"))
        assertFalse(AdSkipMatcher.isSplashOrAdContext("com.tmall.campus.bizwebview.ui.CampusWebActivity"))
    }

    @Test
    fun adSkipMatcherRestrictsGestureBoundsToCompactTopArea() {
        // Real GDT top-right skip pill from 1080x2282 device capture: [879,63][1044,147]
        assertTrue(AdSkipMatcher.isCompactSkipButtonBounds(879, 63, 1044, 147, 1080, 2282))
        // Fullscreen ad creative must NEVER be tapped
        assertFalse(AdSkipMatcher.isCompactSkipButtonBounds(0, 0, 1080, 2282, 1080, 2282))
        // Bottom CTA card must NEVER be tapped
        assertFalse(AdSkipMatcher.isCompactSkipButtonBounds(297, 1847, 783, 2006, 1080, 2282))
    }
}
