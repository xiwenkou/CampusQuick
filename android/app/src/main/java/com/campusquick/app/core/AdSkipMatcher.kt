package com.campusquick.app.core

/**
 * Pure matching logic for the optional, target-scoped Accessibility auto-skipper.
 * Kept strictly conservative to prevent accidental clicks on normal app UI controls.
 */
object AdSkipMatcher {

    const val TARGET_PACKAGE = "com.tmall.campus.and"
    const val SPLASH_AD_CONTAINER_ID = "com.tmall.campus.and:id/adsFl"

    // High-precision resource IDs verified from Tmall Campus & bundled ad SDK layouts
    val EXACT_SKIP_VIEW_IDS: List<String> = listOf(
        "com.tmall.campus.and:id/cl_skip",
        "com.tmall.campus.and:id/tv_skip_countdown",
        "com.tmall.campus.and:id/iv_close_ad",
        "com.tmall.campus.and:id/ksad_splash_skip_view",
        "com.tmall.campus.and:id/ksad_splash_circle_skip_view",
        "com.tmall.campus.and:id/tt_splash_skip_btn",
        "com.tmall.campus.and:id/beizi_ad_skip_view"
    )

    private val SKIP_LABEL_REGEX = Regex(
        """^(?:跳过(?:广告)?(?:\s*[|｜·•]?\s*\d{0,2}\s*[sS秒]?)?|\d{1,2}\s*[sS秒]?\s*[|｜·•]?\s*跳过(?:广告)?|跳过\s*\(\d{1,2}[sS秒]?\)|关闭广告)$"""
    )

    private val SPLASH_ACTIVITY_TOKENS = listOf(
        "SplashActivity",
        "HotSplashActivity",
        "OperateAdDialog",
        "com.qq.e.ads",
        "com.beizi.",
        "com.kwad.",
        "com.bytedance.sdk.openadsdk",
        "com.anythink."
    )

    fun isSplashOrAdContext(activityOrClassName: String?): Boolean {
        if (activityOrClassName.isNullOrBlank()) return false
        return SPLASH_ACTIVITY_TOKENS.any { activityOrClassName.contains(it, ignoreCase = true) }
    }

    /**
     * Returns true ONLY for compact splash/popup skip labels (e.g. "跳过", "跳过 5", "3s 跳过",
     * "跳过|4", "跳过广告", "关闭广告"). Rejects longer sentences or regular navigation text.
     */
    fun isSkipLabel(rawText: CharSequence?): Boolean {
        if (rawText == null) return false
        val normalized = rawText.toString().trim()
        if (normalized.isEmpty() || normalized.length > 10) return false
        return SKIP_LABEL_REGEX.matches(normalized)
    }

    /**
     * Ensures gesture-fallback taps only target compact skip pill buttons (not fullscreen ad
     * banners or bottom CTA cards that would inadvertently open an advertiser landing page).
     */
    fun isCompactSkipButtonBounds(
        left: Int,
        top: Int,
        right: Int,
        bottom: Int,
        screenWidth: Int,
        screenHeight: Int
    ): Boolean {
        val w = right - left
        val h = bottom - top
        if (w <= 0 || h <= 0) return false
        if (screenWidth <= 0 || screenHeight <= 0) return false
        // Must be compact (<= 40% screen width and <= 12% screen height)
        if (w > (screenWidth * 0.40f) || h > (screenHeight * 0.12f)) return false
        // Splash skip pills sit in the upper 35% of the screen (usually top-right)
        val centerY = (top + bottom) / 2
        return centerY <= (screenHeight * 0.35f)
    }
}
