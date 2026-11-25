package com.campusquick.app.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

data class VpnRuntimeSnapshot(
    val running: Boolean = false,
    val targetPackage: String = "com.tmall.campus.and",
    val blockedCount: Long = 0L,
    val allowedCount: Long = 0L,
    val recentBlocked: List<String> = emptyList(),
    val lastError: String? = null
)

object VpnStatsStore {
    private const val MAX_RECENT = 20

    private val blockedCounter = AtomicLong(0L)
    private val allowedCounter = AtomicLong(0L)
    private val recentLock = Any()
    private val recentQueue = ArrayDeque<String>(MAX_RECENT + 1)

    private val _state = MutableStateFlow(VpnRuntimeSnapshot())
    val state: StateFlow<VpnRuntimeSnapshot> = _state.asStateFlow()

    fun setRunning(running: Boolean, targetPackage: String, error: String? = null) {
        synchronized(recentLock) {
            _state.value = _state.value.copy(
                running = running,
                targetPackage = targetPackage,
                lastError = error
            )
        }
    }

    fun recordBlocked(domain: String) {
        val count = blockedCounter.incrementAndGet()
        val ts = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        synchronized(recentLock) {
            recentQueue.addFirst("$ts  REJECT  $domain")
            while (recentQueue.size > MAX_RECENT) {
                recentQueue.removeLast()
            }
            _state.value = _state.value.copy(
                blockedCount = count,
                recentBlocked = recentQueue.toList()
            )
        }
    }

    fun recordAllowed() {
        val count = allowedCounter.incrementAndGet()
        _state.value = _state.value.copy(allowedCount = count)
    }

    fun resetCounters() {
        blockedCounter.set(0L)
        allowedCounter.set(0L)
        synchronized(recentLock) {
            recentQueue.clear()
            _state.value = _state.value.copy(
                blockedCount = 0L,
                allowedCount = 0L,
                recentBlocked = emptyList(),
                lastError = null
            )
        }
    }
}
