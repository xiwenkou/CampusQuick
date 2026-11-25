package com.campusquick.app.core

import com.campusquick.app.model.AdBlockRuleSet

/**
 * Pure domain matcher used by the Per-App Local DNS VPN.
 * Precedence: allowlist (never block) > exact > suffix > keyword.
 */
class AdBlockMatcher(private val rules: AdBlockRuleSet) {

    private val allowlistLower: Set<String> =
        rules.allowlist.map { normalize(it) }.toSet()

    private val exactLower: Set<String> =
        rules.exactDomains.map { normalize(it) }.toSet()

    private val suffixesLower: List<String> =
        rules.domainSuffixes.map { normalize(it) }

    private val keywordsLower: List<String> =
        rules.domainKeywords.map { it.trim().lowercase() }.filter { it.isNotEmpty() }

    fun shouldBlock(rawDomain: String): Boolean {
        val host = normalize(rawDomain)
        if (host.isEmpty()) return false

        // Safety guard: business domains are never blocked
        if (host in allowlistLower) return false

        if (host in exactLower) return true

        for (suffix in suffixesLower) {
            if (host == suffix || host.endsWith(".$suffix")) {
                return true
            }
        }

        for (kw in keywordsLower) {
            if (host.contains(kw)) {
                return true
            }
        }
        return false
    }

    val ruleVersion: String get() = rules.version
    val targetPackage: String get() = rules.targetPackage
    val totalRuleCount: Int
        get() = exactLower.size + suffixesLower.size + keywordsLower.size

    companion object {
        fun normalize(domain: String): String =
            domain.trim().trimEnd('.').lowercase()
    }
}
