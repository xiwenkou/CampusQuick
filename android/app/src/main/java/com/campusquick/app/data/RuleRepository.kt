package com.campusquick.app.data

import android.content.Context
import com.campusquick.app.model.AdBlockRuleSet
import org.json.JSONArray
import org.json.JSONObject

object RuleRepository {

    private const val ASSET_RULES_FILE = "adblock_rules.json"

    @Volatile
    private var cached: AdBlockRuleSet? = null

    fun loadBundledRules(context: Context): AdBlockRuleSet {
        cached?.let { return it }
        val jsonText = context.assets.open(ASSET_RULES_FILE).bufferedReader(Charsets.UTF_8).use {
            it.readText()
        }
        return parseRulesJson(jsonText).also { cached = it }
    }

    fun parseRulesJson(jsonText: String): AdBlockRuleSet {
        val root = JSONObject(jsonText)
        return AdBlockRuleSet(
            version = root.optString("version", "1.0.0"),
            targetPackage = root.optString("targetPackage", "com.tmall.campus.and"),
            exactDomains = readStringList(root.optJSONArray("exactDomains")).toSet(),
            domainSuffixes = readStringList(root.optJSONArray("domainSuffixes")),
            domainKeywords = readStringList(root.optJSONArray("domainKeywords")),
            allowlist = readStringList(root.optJSONArray("allowlist")).toSet(),
            processScopedSuffixes = readStringList(root.optJSONArray("processScopedSuffixes"))
                .map { it.lowercase() }
                .toSet()
        )
    }

    /**
     * Produces ready-to-paste ClashMeta / mihomo inline rules with PROCESS-NAME isolation
     * for shared consumer media / HTTPDNS / DoH domains.
     */
    fun exportClashRulesSnippet(rules: AdBlockRuleSet): String {
        val processScoped = rules.processScopedSuffixes.ifEmpty {
            setOf(
                "zijieapi.com", "snssdk.com", "douyin.com", "bytedance.com", "bytedance.net",
                "volces.com", "bytescm.com", "yximgs.com", "etoote.com",
                "kuaishou.com", "kuaishou.cn", "kwai.com", "kwimgs.com",
                "gifshow.com", "ksapisrv.com", "httpdns.bcelive.com",
                "sdkoptedge.chinanetcenter.com", "doh.pub", "dns.alidns.com",
                "qzs.qq.com", "gtimg.cn", "bdstatic.com", "bcebos.com"
            )
        }
        val sb = StringBuilder()
        sb.appendLine("# CampusQuick ClashMeta Rules v${rules.version} (${rules.targetPackage})")
        sb.appendLine("# 粘贴到 ClashMeta 配置 `rules:` 的最顶部（必须在 cn_domain / DIRECT 之前）")
        for (s in rules.domainSuffixes) {
            if (s.lowercase() in processScoped) {
                sb.appendLine("  - AND,((PROCESS-NAME,${rules.targetPackage}),(DOMAIN-SUFFIX,$s)),REJECT")
            } else {
                sb.appendLine("  - DOMAIN-SUFFIX,$s,REJECT")
            }
        }
        for (kw in rules.domainKeywords) {
            sb.appendLine("  - DOMAIN-KEYWORD,$kw,REJECT")
        }
        for (h in rules.exactDomains) {
            sb.appendLine("  - DOMAIN,$h,REJECT")
        }
        return sb.toString()
    }

    private fun readStringList(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        val list = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) {
            val v = arr.optString(i).trim()
            if (v.isNotEmpty()) list.add(v)
        }
        return list
    }
}
