package com.campusquick.app.core

import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.Tag
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable

object NfcTagHelper {

    fun buildNdefMessage(appPackage: String, presetId: String): NdefMessage {
        val uriRecord = NdefRecord.createUri("campusquick://launch/$presetId")
        val aarRecord = NdefRecord.createApplicationRecord(appPackage)
        return NdefMessage(arrayOf(uriRecord, aarRecord))
    }

    fun writePresetTag(tag: Tag, appPackage: String, presetId: String): Result<String> {
        val message = buildNdefMessage(appPackage, presetId)
        val byteSize = message.toByteArray().size

        return try {
            val ndef = Ndef.get(tag)
            if (ndef != null) {
                ndef.connect()
                try {
                    if (!ndef.isWritable) {
                        return Result.failure(IllegalStateException("该 NFC 标签为只读状态，无法写入"))
                    }
                    if (ndef.maxSize < byteSize) {
                        return Result.failure(
                            IllegalStateException("标签容量不足（需 ${byteSize}B，可用 ${ndef.maxSize}B）")
                        )
                    }
                    ndef.writeNdefMessage(message)
                } finally {
                    ndef.close()
                }
                Result.success("写入成功！贴到门框上，手机轻触即可直达开锁页")
            } else {
                val formatable = NdefFormatable.get(tag)
                    ?: return Result.failure(IllegalStateException("不支持的 NFC 标签类型（推荐使用 NTAG213/215）"))
                formatable.connect()
                try {
                    formatable.format(message)
                } finally {
                    formatable.close()
                }
                Result.success("格式化并写入成功！贴到门框上，手机轻触即可直达开锁页")
            }
        } catch (e: Exception) {
            Result.failure(IllegalStateException("写入失败: ${e.message ?: "请贴稳后重试"}"))
        }
    }
}
