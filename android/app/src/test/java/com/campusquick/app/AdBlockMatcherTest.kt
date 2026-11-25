package com.campusquick.app

import com.campusquick.app.core.AdBlockMatcher
import com.campusquick.app.data.RuleRepository
import com.campusquick.app.model.AdBlockRuleSet
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdBlockMatcherTest {

    private val ruleSet = AdBlockRuleSet(
        version = "2.2.0",
        targetPackage = "com.tmall.campus.and",
        exactDomains = setOf(
            "g-api.kwai.com",
            "ulog-sdk.gifshow.com",
            "ad.zhuanzhuan.com",
            "oc-adpict.oss-cn-shanghai.aliyuncs.com",
            "impdsp.meituan.com"
        ),
        domainSuffixes = listOf(
            "anythinktech.com",
            "beizi.biz",
            "hubcloud.com.cn",
            "e.qq.com",
            "e.kuaishou.com",
            "e.kuaishou.cn",
            "kuaishouzt.com",
            "kwaizt.com",
            "kskwai.com",
            "gskwai.com",
            "zhangyuyidong.cn",
            "douyin.com",
            "yximgs.com",
            "httpdns.bcelive.com",
            "sdkoptedge.chinanetcenter.com",
            "doh.pub",
            "dns.alidns.com"
        ),
        domainKeywords = listOf(
            "pangolin-sdk-toutiao",
            "pglstatp-toutiao"
        ),
        allowlist = setOf(
            "biz.confong.cn",
            "content.confong.cn",
            "o.alicdn.com",
            "httpdns.alicdn.com",
            "tls-tmall-campus.dingtalk.com",
            "mtop.taobao.com",
            "static.luckas.cn"
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
            "open.e.kuaishou.cn",
            "api.e.kuaishou.cn",
            "w1.kskwai.com",
            "w2.gskwai.com",
            "ulog-sdk.gifshow.com",
            "open.kuaishouzt.com",
            "open.kwaizt.com",
            "g-api.kwai.com",
            "httpdns.bcelive.com",
            "sdkoptedge.chinanetcenter.com",
            "doh.pub",
            "dns.alidns.com",
            "ad.zhuanzhuan.com",
            "oc-adpict.oss-cn-shanghai.aliyuncs.com",
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

    @Test
    fun clashExportIsolatesProcessScopedDomains() {
        val scopedRules = ruleSet.copy(
            domainSuffixes = listOf("anythinktech.com", "e.kuaishou.cn", "kuaishou.cn", "doh.pub", "httpdns.bcelive.com"),
            processScopedSuffixes = setOf("kuaishou.cn", "doh.pub", "httpdns.bcelive.com")
        )
        val snippet = RuleRepository.exportClashRulesSnippet(scopedRules)
        assertTrue(snippet.contains("- DOMAIN-SUFFIX,anythinktech.com,REJECT"))
        assertTrue(snippet.contains("- DOMAIN-SUFFIX,e.kuaishou.cn,REJECT"))
        assertTrue(snippet.contains("- AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,kuaishou.cn)),REJECT"))
        assertTrue(snippet.contains("- AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,doh.pub)),REJECT"))
        assertFalse(snippet.contains("- DOMAIN-SUFFIX,kuaishou.cn,REJECT"))
        assertFalse(snippet.contains("- DOMAIN-SUFFIX,doh.pub,REJECT"))
    }
}
