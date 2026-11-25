package com.campusquick.app.entry

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import com.campusquick.app.R
import com.campusquick.app.data.PresetRepository

class QuickUnlockWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        for (widgetId in appWidgetIds) {
            updateWidget(context, appWidgetManager, widgetId)
        }
    }

    companion object {
        fun refreshAll(context: Context) {
            val mgr = AppWidgetManager.getInstance(context)
            val ids = mgr.getAppWidgetIds(
                ComponentName(context, QuickUnlockWidgetProvider::class.java)
            )
            for (id in ids) {
                updateWidget(context, mgr, id)
            }
        }

        private fun updateWidget(
            context: Context,
            appWidgetManager: AppWidgetManager,
            appWidgetId: Int
        ) {
            val preset = PresetRepository.getSelectedPreset(context)
            val proxyIntent = Intent(context, LaunchProxyActivity::class.java).apply {
                putExtra(LaunchProxyActivity.EXTRA_PRESET_ID, preset.id)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
            val pi = PendingIntent.getActivity(
                context,
                appWidgetId,
                proxyIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val views = RemoteViews(context.packageName, R.layout.widget_quick_unlock).apply {
                setTextViewText(R.id.widgetTitle, preset.name)
                setOnClickPendingIntent(R.id.widgetRoot, pi)
            }
            appWidgetManager.updateAppWidget(appWidgetId, views)
        }
    }
}
