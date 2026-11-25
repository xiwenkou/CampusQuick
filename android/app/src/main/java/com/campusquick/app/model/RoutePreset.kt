package com.campusquick.app.model

data class RoutePreset(
    val id: String,
    val name: String,
    val description: String,
    val targetPackage: String,
    val uri: String,
    val category: String = "custom",
    val bleNamePrefix: String? = null,
    val requiresBluetooth: Boolean = false,
    val recommendedMaxDistanceHint: String? = null,
    val isUserCustom: Boolean = false
)
