package com.campusquick.app

import com.campusquick.app.core.BleProximityMonitor
import com.campusquick.app.data.PresetRepository
import com.campusquick.app.data.RuleRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PresetRepositoryTest {

    @Test
    fun parsesAndRoundTripsPresetsCleanly() {
        val sample = """
            {
              "schemaVersion": 1,
              "presets": [
                {
                  "id": "tmall_doorlock",
                  "name": "宿舍极速开锁",
                  "description": "直达门锁",
                  "targetPackage": "com.tmall.campus.and",
                  "uri": "tmallcampus://web/open?url=https%3A%2F%2Fbiz.confong.cn%2FdoorLock",
                  "category": "doorlock",
                  "bleNamePrefix": "MVL",
                  "requiresBluetooth": true
                }
              ]
            }
        """.trimIndent()

        val list = PresetRepository.parsePresetsJson(sample)
        assertEquals(1, list.size)
        assertEquals("tmall_doorlock", list[0].id)
        assertEquals("MVL", list[0].bleNamePrefix)
        assertTrue(list[0].requiresBluetooth)

        val serialized = PresetRepository.serializePresets(list)
        val roundTripped = PresetRepository.parsePresetsJson(serialized)
        assertEquals(list[0].uri, roundTripped[0].uri)
        assertEquals(list[0].targetPackage, roundTripped[0].targetPackage)
    }

    @Test
    fun exportsClashRulesWithProcessScopedIsolation() {
        val rulesJson = """
            {
              "version": "2.1.0",
              "targetPackage": "com.tmall.campus.and",
              "exactDomains": ["sdk.e.qq.com"],
              "domainSuffixes": ["anythinktech.com", "douyin.com"],
              "domainKeywords": ["pangolin-sdk-toutiao"],
              "allowlist": ["biz.confong.cn"]
            }
        """.trimIndent()
        val parsed = RuleRepository.parseRulesJson(rulesJson)
        val clash = RuleRepository.exportClashRulesSnippet(parsed)

        assertTrue(clash.contains("DOMAIN-SUFFIX,anythinktech.com,REJECT"))
        assertTrue(clash.contains("DOMAIN-KEYWORD,pangolin-sdk-toutiao,REJECT"))
        assertTrue(clash.contains("DOMAIN,sdk.e.qq.com,REJECT"))
        assertTrue(
            clash.contains(
                "AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,douyin.com)),REJECT"
            )
        )
        assertFalse(clash.contains("DOMAIN-SUFFIX,douyin.com,REJECT"))
    }

    @Test
    fun classifiesBleRssiZonesAccurately() {
        assertTrue(BleProximityMonitor.classifyRssi(-60).second)
        assertFalse(BleProximityMonitor.classifyRssi(-75).second)
        assertFalse(BleProximityMonitor.classifyRssi(-92).second)
    }
}
