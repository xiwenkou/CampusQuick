package com.campusquick.app

import com.campusquick.app.core.AdBlockMatcher
import com.campusquick.app.model.AdBlockRuleSet
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdBlockMatcherTest {

    private val ruleSet = AdBlockRuleSet(
        version = "2.1.0",
        targetPackage = "com.tmall.campus.and",
        exactDomains = setOf(
            "sdk.e.qq.com",
            "open.e.kuaishou.com",
            "g-api.kwai.com",
            "impdsp.meituan.com"
        ),
        domainSuffixes = listOf(
            "anythinktech.com",
            "beizi.biz",
            "hubcloud.com.cn",
            "kuaishouzt.com",
            "kwaizt.com",
            "zhangyuyidong.cn",
            "douyin.com",
            "yximgs.com"
        ),
        domainKeywords = listOf(
            "pangolin-sdk-toutiao",
            "pglstatp-toutiao"
        ),
        allowlist = setOf(
            "biz.confong.cn",
            "content.confong.cn",
            "o.alicdn.com",
            "tls-tmall-campus.dingtalk.com",
            "mtop.taobao.com"
        )
    )

    private val matcher = AdBlockMatcher(ruleSet)

    @Test
    fun blocksPrimaryAndFallbackAdDomains() {
        val blocked = listOf(
            "datk.anythinktech.com",
            "MORES.ANYTHINKTECH.COM.",
            "sdk.beizi.biz",
            "sdktmp.hubcloud.com.cn",
            "api-access.pangolin-sdk-toutiao.com",
            "api-access.pangolin-sdk-toutiao1.com",
            "sf6-fe-tos.pglstatp-toutiao.com",
            "sdk.e.qq.com",
            "open.e.kuaishou.com",
            "open.kuaishouzt.com",
            "open.kwaizt.com",
            "g-api.kwai.com",
            "impdsp.meituan.com",
            "webcast-open.douyin.com",
            "ali.pull.yximgs.com"
        )
        for (domain in blocked) {
            assertTrue("Expected blocked: $domain", matcher.shouldBlock(domain))
        }
    }

    @Test
    fun neverBlocksBusinessAllowlistOrUnrelatedDomains() {
        val allowed = listOf(
            "biz.confong.cn",
            "BIZ.CONFONG.CN.",
            "content.confong.cn",
            "o.alicdn.com",
            "tls-tmall-campus.dingtalk.com",
            "mtop.taobao.com",
            "www.meituan.com",
            "www.qq.com",
            "notanythinktech.com",
            ""
        )
        for (domain in allowed) {
            assertFalse("Expected allowed: $domain", matcher.shouldBlock(domain))
        }
    }

    @Test
    fun allowlistOverridesBlockRule() {
        val overridingMatcher = AdBlockMatcher(
            ruleSet.copy(allowlist = ruleSet.allowlist + "safe.anythinktech.com")
        )
        assertFalse(overridingMatcher.shouldBlock("safe.anythinktech.com"))
        assertTrue(overridingMatcher.shouldBlock("datk.anythinktech.com"))
    }
}
