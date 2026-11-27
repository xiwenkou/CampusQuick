package com.campusquick.app.accessibility

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.ComponentName
import android.content.Context
import android.graphics.Path
import android.graphics.Rect
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.campusquick.app.core.AdSkipMatcher
import java.util.concurrent.atomic.AtomicLong

/**
 * Optional, strictly target-scoped (android:packageNames="com.tmall.campus.and") Accessibility
 * auto-skipper that acts as a < 50 ms fallback for:
 * 1. First-party in-house MTOP splash/popup ads (AdSplashView id/cl_skip & OperateAdDialog id/iv_close_ad)
 *    which share business API domains and cannot be DNS-blocked.
 * 2. Residual pre-cached offline ads before the user flushes target app cache.
 *
 * Zero events from other apps are ever delivered to this service by Android OS.
 */
class AdSkipAccessibilityService : AccessibilityService() {

    private var lastActivityName: String? = null
    private var lastClickElapsedMs: Long = 0L

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        val pkg = event.packageName?.toString() ?: return
        if (pkg != AdSkipMatcher.TARGET_PACKAGE) return

        if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            val cls = event.className?.toString()
            if (!cls.isNullOrBlank()) {
                lastActivityName = cls
            }
        }

        val now = SystemClock.elapsedRealtime()
        if (now - lastClickElapsedMs < CLICK_COOLDOWN_MS) return

        val root = rootInActiveWindow ?: return
        try {
            if (tryClickByExactIds(root)) {
                lastClickElapsedMs = SystemClock.elapsedRealtime()
                return
            }

            // Text-based skip fallback ONLY inside SplashActivity / HotSplashActivity or when adsFl exists
            val inSplashContext = AdSkipMatcher.isSplashOrAdContext(lastActivityName) ||
                hasViewId(root, AdSkipMatcher.SPLASH_AD_CONTAINER_ID)
            if (inSplashContext && tryClickBySkipText(root)) {
                lastClickElapsedMs = SystemClock.elapsedRealtime()
            }
        } catch (_: Exception) {
            // Ignore transient AccessibilityNodeInfo recycling races
        }
    }

    override fun onInterrupt() {
        // Nothing to release
    }

    private fun tryClickByExactIds(root: AccessibilityNodeInfo): Boolean {
        for (viewId in AdSkipMatcher.EXACT_SKIP_VIEW_IDS) {
            val nodes = root.findAccessibilityNodeInfosByViewId(viewId)
            if (nodes.isNullOrEmpty()) continue
            for (node in nodes) {
                if (!node.isVisibleToUser) continue
                if (clickNodeOrAncestor(node)) {
                    recordSkip("id:${viewId.substringAfterLast('/')}")
                    return true
                }
            }
        }
        return false
    }

    private fun tryClickBySkipText(root: AccessibilityNodeInfo): Boolean {
        val candidates = root.findAccessibilityNodeInfosByText("跳过")
        if (candidates.isNullOrEmpty()) return false

        val dm = resources.displayMetrics
        for (node in candidates) {
            if (!node.isVisibleToUser) continue
            val text = node.text ?: node.contentDescription
            if (!AdSkipMatcher.isSkipLabel(text)) continue

            val rect = Rect()
            node.getBoundsInScreen(rect)
            if (!AdSkipMatcher.isCompactSkipButtonBounds(
                    rect.left,
                    rect.top,
                    rect.right,
                    rect.bottom,
                    dm.widthPixels,
                    dm.heightPixels
                )
            ) {
                continue
            }

            if (clickNodeOrAncestor(node)) {
                recordSkip("text:${text.toString().trim()}")
                return true
            }
            if (dispatchTapAt(rect.centerX().toFloat(), rect.centerY().toFloat())) {
                recordSkip("gesture:${text.toString().trim()}")
                return true
            }
        }
        return false
    }

    private fun hasViewId(root: AccessibilityNodeInfo, viewId: String): Boolean {
        val nodes = root.findAccessibilityNodeInfosByViewId(viewId)
        return !nodes.isNullOrEmpty()
    }

    private fun clickNodeOrAncestor(node: AccessibilityNodeInfo): Boolean {
        var cur: AccessibilityNodeInfo? = node
        var depth = 0
        while (cur != null && depth < 4) {
            if (cur.isClickable && cur.isEnabled) {
                if (cur.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                    return true
                }
            }
            cur = cur.parent
            depth++
        }
        return false
    }

    private fun dispatchTapAt(x: Float, y: Float): Boolean {
        if (x <= 0f || y <= 0f) return false
        val path = Path().apply { moveTo(x, y) }
        val stroke = GestureDescription.StrokeDescription(path, 0L, 40L)
        val gesture = GestureDescription.Builder().addStroke(stroke).build()
        return dispatchGesture(gesture, null, null)
    }

    private fun recordSkip(reason: String) {
        val count = skippedCounter.incrementAndGet()
        Log.i(TAG, "Auto-skipped ad ($reason), total=$count")
    }

    companion object {
        private const val TAG = "CampusQuickSkip"
        private const val CLICK_COOLDOWN_MS = 350L
        private val skippedCounter = AtomicLong(0L)

        fun getSkippedCount(): Long = skippedCounter.get()

        fun isServiceEnabled(context: Context): Boolean {
            val expected = ComponentName(context, AdSkipAccessibilityService::class.java)
                .flattenToString()
            val expectedShort = ComponentName(context, AdSkipAccessibilityService::class.java)
                .flattenToShortString()
            val enabled = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ) ?: return false
            return enabled.split(':').any { entry ->
                entry.equals(expected, ignoreCase = true) ||
                    entry.equals(expectedShort, ignoreCase = true)
            }
        }
    }
}
