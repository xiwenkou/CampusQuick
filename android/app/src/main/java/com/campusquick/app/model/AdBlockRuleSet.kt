package com.campusquick.app.model

data class AdBlockRuleSet(
    val version: String,
    val targetPackage: String,
    val exactDomains: Set<String>,
    val domainSuffixes: List<String>,
    val domainKeywords: List<String>,
    val allowlist: Set<String>
)
