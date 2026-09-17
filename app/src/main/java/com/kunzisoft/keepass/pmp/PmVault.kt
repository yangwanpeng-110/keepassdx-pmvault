/*
 * PmVault extensions for KeePassDX - application facade, per-device key and
 * on-disk locations. The device key is a 0600 random 32-byte secret kept in the
 * app's private storage; it never enters the KDBX database and is not synced.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import android.content.Context
import java.io.File

object PmVault {
    private lateinit var app: Context

    @Synchronized
    fun init(context: Context) {
        if (!::app.isInitialized) {
            app = context.applicationContext
            dir("") // ensure base dir
        }
    }

    private fun ctx(): Context {
        check(::app.isInitialized) { "PmVault.init(context) must be called first" }
        return app
    }

    fun dir(sub: String): File {
        val base = File(ctx().filesDir, "pmp")
        val d = if (sub.isEmpty()) base else File(base, sub)
        if (!d.exists()) d.mkdirs()
        return d
    }

    @Synchronized
    fun deviceKey(): ByteArray {
        val f = File(dir(""), "device.key")
        if (f.exists()) {
            val b = f.readBytes()
            if (b.size == 32) return b
        }
        val k = PmpCrypto.randomBytes(32)
        f.writeBytes(k)
        try {
            f.setReadable(false, false); f.setWritable(false, false)
            f.setReadable(true, true); f.setWritable(true, true)
        } catch (_: Exception) {
        }
        return k
    }

    fun deriveKey(domain: String, len: Int = 32): ByteArray =
        PmpCrypto.hkdf(deviceKey(), "PmVault".toByteArray(), domain.toByteArray(), len)

    /** Stable non-reversible id for a database file uri (hex, 32 chars). */
    fun dbId(fileUri: String?): String {
        val norm = (fileUri ?: "").trim().lowercase()
        return PmpCrypto.toHex(PmpCrypto.sha256(norm.toByteArray())).take(32)
    }

    fun setLastDatabaseUri(uri: String?) {
        if (!uri.isNullOrEmpty()) File(dir(""), "last-db.txt").writeText(uri)
    }

    fun getLastDatabaseUri(): String? {
        val f = File(dir(""), "last-db.txt")
        return if (f.exists()) f.readText().trim().ifEmpty { null } else null
    }
}
