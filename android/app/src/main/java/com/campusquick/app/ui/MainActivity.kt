package com.campusquick.app.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.nfc.NfcAdapter
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.campusquick.app.R
import com.campusquick.app.core.BleProximityMonitor
import com.campusquick.app.core.CheckLevel
import com.campusquick.app.core.DiagnosticItem
import com.campusquick.app.core.DiagnosticsEngine
import com.campusquick.app.core.NfcTagHelper
import com.campusquick.app.core.RouteLauncher
import com.campusquick.app.data.PresetRepository
import com.campusquick.app.data.RuleRepository
import com.campusquick.app.databinding.ActivityMainBinding
import com.campusquick.app.entry.QuickUnlockWidgetProvider
import com.campusquick.app.model.RoutePreset
import com.campusquick.app.vpn.AdBlockVpnService
import com.campusquick.app.vpn.VpnStatsStore
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var currentPreset: RoutePreset
    private lateinit var bleMonitor: BleProximityMonitor

    private var bleScanning = false
    private var nfcWriteMode = false
    private var suppressVpnSwitchCallback = false
    private var lastObservedVpnRunning: Boolean? = null

    private val vpnConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startLocalVpnService()
        } else {
            syncVpnSwitch(false)
            Toast.makeText(this, "未授予 VPN 权限，已取消启动", Toast.LENGTH_SHORT).show()
        }
    }

    private val notificationPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        prepareAndStartLocalVpn()
    }

    private val blePermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        if (grants.values.all { it }) {
            toggleBleScan()
        } else {
            Toast.makeText(this, "需要蓝牙扫描权限才能检测门锁近场距离", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        bleMonitor = BleProximityMonitor(this) { state ->
            runOnUiThread {
                bleScanning = state.scanning
                binding.btnToggleBleScan.text = if (state.scanning) "停止测距" else "开启近场测距"
                val prefix = if (state.deviceName != null) "[${state.deviceName}] " else ""
                binding.tvBleStatus.text = "BLE 近场防呆：$prefix${state.zoneLabel}"
                val colorRes = if (state.safeToUnlock) R.color.status_pass else R.color.text_secondary
                binding.tvBleStatus.setTextColor(ContextCompat.getColor(this, colorRes))
            }
        }

        currentPreset = PresetRepository.getSelectedPreset(this)
        binding.etBlePrefix.setText(PresetRepository.getBlePrefix(this))
        val bundledRules = RuleRepository.loadBundledRules(this)
        binding.btnCopyClashRules.text =
            "已在使用 ClashMeta？一键复制 ${bundledRules.totalRuleCount} 条进程隔离规则"

        bindListeners()
        renderActivePreset()
        observeVpnState()
        runDiagnostics()
    }

    override fun onPause() {
        super.onPause()
        disableNfcWriteMode()
        if (bleScanning) {
            bleMonitor.stop()
        }
    }

    private fun bindListeners() {
        binding.btnLaunchNow.setOnClickListener {
            RouteLauncher.launch(this, currentPreset)
        }

        binding.btnSwitchPreset.setOnClickListener {
            showPresetPickerDialog()
        }

        binding.btnAddPreset.setOnClickListener {
            showAddCustomPresetDialog()
        }

        binding.btnPinShortcut.setOnClickListener {
            if (RouteLauncher.pinShortcutToHome(this, currentPreset)) {
                Toast.makeText(this, "已向系统桌面发送「${currentPreset.name}」快捷方式请求", Toast.LENGTH_SHORT).show()
            }
        }

        binding.switchLocalVpn.setOnCheckedChangeListener { _, isChecked ->
            if (suppressVpnSwitchCallback) return@setOnCheckedChangeListener
            if (isChecked) {
                requestStartLocalVpn()
            } else {
                stopLocalVpnService()
            }
        }

        binding.btnCopyClashRules.setOnClickListener {
            val rules = RuleRepository.loadBundledRules(this)
            val snippet = RuleRepository.exportClashRulesSnippet(rules)
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("CampusQuick ClashMeta Rules", snippet))
            Toast.makeText(
                this,
                "已复制 v${rules.version} 进程隔离规则到剪贴板，请粘贴至 ClashMeta rules 顶部",
                Toast.LENGTH_LONG
            ).show()
        }

        binding.btnWriteNfc.setOnClickListener {
            if (nfcWriteMode) {
                disableNfcWriteMode()
            } else {
                enableNfcWriteMode()
            }
        }

        binding.btnToggleBleScan.setOnClickListener {
            if (bleScanning) {
                bleMonitor.stop()
            } else {
                val prefix = binding.etBlePrefix.text.toString().trim().ifEmpty { "MVL" }
                PresetRepository.setBlePrefix(this, prefix)
                toggleBleScan()
            }
        }

        binding.btnRunDiagnostics.setOnClickListener {
            runDiagnostics()
        }

        binding.btnOpenBatterySettings.setOnClickListener {
            openBatterySettings()
        }
    }

    private fun renderActivePreset() {
        binding.tvActivePresetName.text = currentPreset.name
        binding.tvActivePresetDesc.text = currentPreset.description.ifBlank {
            "${currentPreset.targetPackage} · ${currentPreset.uri}"
        }
        val hint = currentPreset.recommendedMaxDistanceHint
            ?: "点击下方按钮直达目标页面，配合去广告引擎可跳过开屏与弹窗"
        binding.tvDistanceHint.text = "提示：$hint"
        QuickUnlockWidgetProvider.refreshAll(this)
    }

    private fun showPresetPickerDialog() {
        val presets = PresetRepository.loadAll(this)
        val labels = presets.map { p ->
            val tag = if (p.isUserCustom) " [自定义]" else ""
            "${p.name}$tag"
        }.toTypedArray()
        val checkedIdx = presets.indexOfFirst { it.id == currentPreset.id }.coerceAtLeast(0)

        AlertDialog.Builder(this)
            .setTitle("选择直达预设")
            .setSingleChoiceItems(labels, checkedIdx) { dialog, which ->
                currentPreset = presets[which]
                PresetRepository.setSelectedPresetId(this, currentPreset.id)
                renderActivePreset()
                runDiagnostics()
                dialog.dismiss()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun showAddCustomPresetDialog() {
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_add_preset, null)
        val etName = dialogView.findViewById<EditText>(R.id.etPresetName)
        val etPkg = dialogView.findViewById<EditText>(R.id.etPresetPackage)
        val etUri = dialogView.findViewById<EditText>(R.id.etPresetUri)
        val cbBt = dialogView.findViewById<CheckBox>(R.id.cbRequiresBluetooth)

        AlertDialog.Builder(this)
            .setTitle("新增自定义直达入口")
            .setView(dialogView)
            .setPositiveButton("保存") { _, _ ->
                val name = etName.text.toString().trim()
                val pkg = etPkg.text.toString().trim()
                val uri = etUri.text.toString().trim()
                if (name.isEmpty() || pkg.isEmpty() || uri.isEmpty()) {
                    Toast.makeText(this, "请完整填写名称、包名和 DeepLink URI", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                val id = "custom_${System.currentTimeMillis()}"
                val created = RoutePreset(
                    id = id,
                    name = name,
                    description = "自定义快捷直达 ($pkg)",
                    targetPackage = pkg,
                    uri = uri,
                    category = "custom",
                    requiresBluetooth = cbBt.isChecked,
                    isUserCustom = true
                )
                PresetRepository.addCustomPreset(this, created)
                currentPreset = created
                renderActivePreset()
                runDiagnostics()
                Toast.makeText(this, "已保存并切换到「$name」", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun observeVpnState() {
        lifecycleScope.launch {
            VpnStatsStore.state.collect { snap ->
                syncVpnSwitch(snap.running)
                binding.tvVpnStatus.text = when {
                    snap.lastError != null -> "状态：${snap.lastError}"
                    snap.running -> "状态：运行中（仅接管 ${snap.targetPackage} 广告 DNS，零外部代理）"
                    else -> "状态：未启动（若已在用 ClashMeta 规则则无需开启本开关）"
                }
                binding.tvVpnStats.text =
                    "已拦截 ${snap.blockedCount} 次广告请求 · 放行 ${snap.allowedCount} 次业务查询"
                binding.tvVpnRecentLog.text = if (snap.recentBlocked.isEmpty()) {
                    "（启动本地 VPN 后将在此实时展示拦截到的广告域名）"
                } else {
                    snap.recentBlocked.take(6).joinToString("\n")
                }
                if (lastObservedVpnRunning != null && lastObservedVpnRunning != snap.running) {
                    binding.root.postDelayed({ runDiagnostics() }, 400)
                }
                lastObservedVpnRunning = snap.running
            }
        }
    }

    private fun syncVpnSwitch(checked: Boolean) {
        if (binding.switchLocalVpn.isChecked == checked) return
        suppressVpnSwitchCallback = true
        binding.switchLocalVpn.isChecked = checked
        suppressVpnSwitchCallback = false
    }

    private fun requestStartLocalVpn() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }
        prepareAndStartLocalVpn()
    }

    private fun prepareAndStartLocalVpn() {
        val prep = VpnService.prepare(this)
        if (prep != null) {
            vpnConsentLauncher.launch(prep)
        } else {
            startLocalVpnService()
        }
    }

    private fun startLocalVpnService() {
        val intent = Intent(this, AdBlockVpnService::class.java).apply {
            action = AdBlockVpnService.ACTION_START
            putExtra(AdBlockVpnService.EXTRA_TARGET_PACKAGE, currentPreset.targetPackage)
        }
        ContextCompat.startForegroundService(this, intent)
        binding.root.postDelayed({ runDiagnostics() }, 800)
    }

    private fun stopLocalVpnService() {
        val intent = Intent(this, AdBlockVpnService::class.java).apply {
            action = AdBlockVpnService.ACTION_STOP
        }
        startService(intent)
        binding.root.postDelayed({ runDiagnostics() }, 600)
    }

    private fun enableNfcWriteMode() {
        val adapter = NfcAdapter.getDefaultAdapter(this)
        if (adapter == null) {
            Toast.makeText(this, "当前设备不支持 NFC", Toast.LENGTH_SHORT).show()
            return
        }
        if (!adapter.isEnabled) {
            Toast.makeText(this, "请先在系统设置中打开 NFC 开关", Toast.LENGTH_SHORT).show()
            return
        }
        nfcWriteMode = true
        binding.btnWriteNfc.text = "取消等待（请将手机背面贴近门框 NFC 贴纸…）"
        binding.tvNfcHint.text = "等待写入预设「${currentPreset.name}」：请保持手机背面紧贴空白 NFC 标签 1 秒"

        val flags = NfcAdapter.FLAG_READER_NFC_A or
            NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_NFC_F or
            NfcAdapter.FLAG_READER_NFC_V
        adapter.enableReaderMode(
            this,
            { tag ->
                val result = NfcTagHelper.writePresetTag(tag, packageName, currentPreset.id)
                runOnUiThread {
                    disableNfcWriteMode()
                    val msg = result.getOrElse { it.message ?: "写入失败" }
                    binding.tvNfcHint.text = msg
                    Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
                }
            },
            flags,
            null
        )
    }

    private fun disableNfcWriteMode() {
        if (!nfcWriteMode) return
        nfcWriteMode = false
        NfcAdapter.getDefaultAdapter(this)?.disableReaderMode(this)
        binding.btnWriteNfc.text = "写入门框 NFC 贴纸（一碰直达开锁页）"
    }

    private fun toggleBleScan() {
        if (!bleMonitor.hasScanPermission()) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                blePermLauncher.launch(
                    arrayOf(
                        Manifest.permission.BLUETOOTH_SCAN,
                        Manifest.permission.BLUETOOTH_CONNECT
                    )
                )
            } else {
                Toast.makeText(this, "请先授予蓝牙权限", Toast.LENGTH_SHORT).show()
            }
            return
        }
        val prefix = binding.etBlePrefix.text.toString().trim().ifEmpty { "MVL" }
        bleMonitor.start(prefix)
    }

    private fun runDiagnostics() {
        binding.containerDiagnostics.removeAllViews()
        val loadingTv = TextView(this).apply {
            text = "正在执行 5 项实时环境体检…"
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.text_muted))
            textSize = 13f
            setPadding(0, 8, 0, 8)
        }
        binding.containerDiagnostics.addView(loadingTv)

        lifecycleScope.launch {
            val items = DiagnosticsEngine.runAll(this@MainActivity, currentPreset)
            renderDiagnostics(items)
        }
    }

    private fun renderDiagnostics(items: List<DiagnosticItem>) {
        binding.containerDiagnostics.removeAllViews()
        for (item in items) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, 10, 0, 10)
            }
            val (badge, colorRes) = when (item.status) {
                CheckLevel.PASS -> "● 正常" to R.color.status_pass
                CheckLevel.WARN -> "▲ 建议优化" to R.color.status_warn
                CheckLevel.FAIL -> "✖ 异常" to R.color.status_fail
            }
            val titleTv = TextView(this).apply {
                text = "${item.title}   $badge"
                textSize = 14f
                setTextColor(ContextCompat.getColor(this@MainActivity, colorRes))
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            }
            val detailTv = TextView(this).apply {
                text = item.detail
                textSize = 12f
                setTextColor(ContextCompat.getColor(this@MainActivity, R.color.text_secondary))
                setPadding(0, 3, 0, 0)
            }
            row.addView(titleTv)
            row.addView(detailTv)
            binding.containerDiagnostics.addView(row)
        }
    }

    private fun openBatterySettings() {
        val targetIntent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
        try {
            startActivity(targetIntent)
        } catch (_: Exception) {
            val fallback = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:${currentPreset.targetPackage}")
            }
            startActivity(fallback)
        }
    }
}
