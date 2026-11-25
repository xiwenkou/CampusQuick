package com.campusquick.app.data

import android.content.Context
import com.campusquick.app.model.RoutePreset
import org.json.JSONArray
import org.json.JSONObject

object PresetRepository {

    private const val ASSET_PRESETS_FILE = "presets.json"
    private const val PREFS_NAME = "campus_quick_prefs"
    private const val KEY_SELECTED_ID = "selected_preset_id"
    private const val KEY_CUSTOM_PRESETS = "custom_presets_json"
    private const val KEY_BLE_PREFIX = "ble_name_prefix"

    fun parsePresetsJson(jsonText: String, userCustom: Boolean = false): List<RoutePreset> {
        val root = JSONObject(jsonText)
        val arr = root.optJSONArray("presets") ?: JSONArray()
        val out = ArrayList<RoutePreset>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val id = obj.optString("id").trim()
            val name = obj.optString("name").trim()
            val pkg = obj.optString("targetPackage").trim()
            val uri = obj.optString("uri").trim()
            if (id.isEmpty() || name.isEmpty() || pkg.isEmpty() || uri.isEmpty()) continue
            out.add(
                RoutePreset(
                    id = id,
                    name = name,
                    description = obj.optString("description", ""),
                    targetPackage = pkg,
                    uri = uri,
                    category = obj.optString("category", "custom"),
                    bleNamePrefix = obj.optString("bleNamePrefix").takeIf { it.isNotBlank() },
                    requiresBluetooth = obj.optBoolean("requiresBluetooth", false),
                    recommendedMaxDistanceHint = obj.optString("recommendedMaxDistanceHint")
                        .takeIf { it.isNotBlank() },
                    isUserCustom = userCustom
                )
            )
        }
        return out
    }

    fun serializePresets(presets: List<RoutePreset>): String {
        val arr = JSONArray()
        for (p in presets) {
            arr.put(
                JSONObject().apply {
                    put("id", p.id)
                    put("name", p.name)
                    put("description", p.description)
                    put("targetPackage", p.targetPackage)
                    put("uri", p.uri)
                    put("category", p.category)
                    p.bleNamePrefix?.let { put("bleNamePrefix", it) }
                    put("requiresBluetooth", p.requiresBluetooth)
                    p.recommendedMaxDistanceHint?.let { put("recommendedMaxDistanceHint", it) }
                }
            )
        }
        return JSONObject().apply {
            put("schemaVersion", 1)
            put("presets", arr)
        }.toString()
    }

    fun loadAll(context: Context): List<RoutePreset> {
        val bundledJson = context.assets.open(ASSET_PRESETS_FILE).bufferedReader(Charsets.UTF_8).use {
            it.readText()
        }
        val bundled = parsePresetsJson(bundledJson, userCustom = false)
        val custom = loadCustomPresets(context)
        return bundled + custom
    }

    private fun loadCustomPresets(context: Context): List<RoutePreset> {
        val raw = prefs(context).getString(KEY_CUSTOM_PRESETS, null) ?: return emptyList()
        return try {
            parsePresetsJson(raw, userCustom = true)
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun addCustomPreset(context: Context, preset: RoutePreset) {
        val current = loadCustomPresets(context).filterNot { it.id == preset.id } + preset.copy(
            isUserCustom = true
        )
        prefs(context).edit()
            .putString(KEY_CUSTOM_PRESETS, serializePresets(current))
            .putString(KEY_SELECTED_ID, preset.id)
            .apply()
    }

    fun getSelectedPreset(context: Context): RoutePreset {
        val all = loadAll(context)
        val selectedId = prefs(context).getString(KEY_SELECTED_ID, null)
        return all.firstOrNull { it.id == selectedId } ?: all.first()
    }

    fun setSelectedPresetId(context: Context, id: String) {
        prefs(context).edit().putString(KEY_SELECTED_ID, id).apply()
    }

    fun findById(context: Context, id: String?): RoutePreset {
        val all = loadAll(context)
        if (!id.isNullOrBlank()) {
            all.firstOrNull { it.id == id }?.let { return it }
        }
        return getSelectedPreset(context)
    }

    fun getBlePrefix(context: Context): String {
        return prefs(context).getString(KEY_BLE_PREFIX, null)?.takeIf { it.isNotBlank() }
            ?: getSelectedPreset(context).bleNamePrefix
            ?: "MVL"
    }

    fun setBlePrefix(context: Context, prefix: String) {
        prefs(context).edit().putString(KEY_BLE_PREFIX, prefix.trim()).apply()
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
}
