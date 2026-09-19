/*
 * PmVault extensions for KeePassDX - TOTP second-factor unlock gate.
 *
 * Port of the desktop PmpTwoFactor. After the database master credential
 * succeeds, an enrolled database additionally requires a manually entered
 * 6-digit TOTP code (Google Authenticator compatible). The app never reads codes
 * from an authenticator app; the 160-bit seed is generated here, shown as an
 * otpauth:// URI, and stored in an on-device AES-GCM vault OUTSIDE the KDBX
 * database. It does not participate in the KDF and is bound per device.
 *
 * Defences: +/-1 step tolerance, one-time use with replay rejection, constant
 * time comparison, exponential back-off and a 15-minute hard lock after 10
 * failures.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import org.json.JSONObject
import java.io.File
import java.net.URLEncoder

object PmpSecondFactor {
    const val OK = 0
    const val NOT_ENROLLED = 1
    const val LOCKED = 2
    const val REPLAY = 3
    const val WRONG = 4
    const val ERROR = 5

    const val DIGITS = 6
    const val STEP = 30L
    const val HARD_LOCK_FAILURES = 10
    private const val VAULT_AAD = "PmVault/twofa-vault/v1"

    data class EnrollStart(val secretB32: String, val otpauthUri: String)

    private data class Vault(
        var enabled: Boolean = false,
        var secretB32: String = "",
        var lastCounter: Long = 0L,
        var failCount: Int = 0,
        var lockUntilMs: Long = 0L,
        var enrolledAtMs: Long = 0L
    )

    private val pending = HashMap<String, EnrollStart>()

    private fun id16(fileUri: String?) = PmVault.dbId(fileUri).take(16)
    private fun vaultFile(id: String) = File(PmVault.dir("twofa"), "$id.vault")
    private fun key(id: String) = PmVault.deriveKey("twofa:$id")

    // ---- RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) ----
    private fun generateTotp(secretB32: String, epochSeconds: Long): String? {
        val seed = PmpCrypto.base32Decode(secretB32) ?: return null
        val counter = epochSeconds / STEP
        val data = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            data[i] = (c and 0xff).toByte()
            c = c ushr 8
        }
        val mac = javax.crypto.Mac.getInstance("HmacSHA1")
        mac.init(javax.crypto.spec.SecretKeySpec(seed, "HmacSHA1"))
        val h = mac.doFinal(data)
        val off = (h[h.size - 1].toInt() and 0x0f)
        val bin = ((h[off].toInt() and 0x7f) shl 24) or
                ((h[off + 1].toInt() and 0xff) shl 16) or
                ((h[off + 2].toInt() and 0xff) shl 8) or
                (h[off + 3].toInt() and 0xff)
        val code = bin % 1_000_000
        return code.toString().padStart(6, '0')
    }

    private fun constantTimeEqual(a: String, b: String): Boolean {
        val ab = a.toByteArray(); val bb = b.toByteArray()
        if (ab.size != bb.size) return false
        var diff = 0
        for (i in ab.indices) diff = diff or (ab[i].toInt() xor bb[i].toInt())
        return diff == 0
    }

    private fun loadVault(id: String): Vault? {
        val f = vaultFile(id)
        if (!f.exists()) return null
        val sealed = PmpCrypto.fromB64(f.readText().trim())
        val plain = PmpCrypto.aesGcmOpen(key(id), sealed, VAULT_AAD.toByteArray()) ?: return null
        val o = JSONObject(String(plain, Charsets.UTF_8))
        val v = Vault(
            o.optBoolean("enabled"),
            o.optString("secret"),
            o.optLong("lastCounter"),
            o.optInt("failCount"),
            o.optLong("lockUntil"),
            o.optLong("enrolledAt")
        )
        return if (v.enabled && v.secretB32.isNotEmpty()) v else null
    }

    private fun saveVault(id: String, v: Vault): Boolean {
        val o = JSONObject()
            .put("enabled", v.enabled)
            .put("secret", v.secretB32)
            .put("lastCounter", v.lastCounter)
            .put("failCount", v.failCount)
            .put("lockUntil", v.lockUntilMs)
            .put("enrolledAt", v.enrolledAtMs)
        val sealed = PmpCrypto.aesGcmSeal(key(id), o.toString().toByteArray(), VAULT_AAD.toByteArray())
        return runCatching { vaultFile(id).writeText(PmpCrypto.toB64(sealed)); true }.getOrDefault(false)
    }

    fun isEnrolled(fileUri: String?): Boolean = loadVault(id16(fileUri)) != null

    fun beginEnroll(fileUri: String?, label: String): EnrollStart {
        val id = id16(fileUri)
        val secret = PmpCrypto.base32Encode(PmpCrypto.randomBytes(20))
            .uppercase().replace("=", "")
        val safeLabel = label.ifEmpty { "database" }
        val encLabel = URLEncoder.encode(safeLabel, "UTF-8")
        val uri = "otpauth://totp/PmVault:$encLabel?secret=$secret&issuer=PmVault" +
                "&algorithm=SHA1&digits=$DIGITS&period=$STEP"
        val start = EnrollStart(secret, uri)
        pending[id] = start
        return start
    }

    fun confirmEnroll(fileUri: String?, code: String): Pair<Boolean, String> {
        val id = id16(fileUri)
        val start = pending[id]
            ?: return false to "No enrollment in progress. Start enrollment again."
        val match = matchCode(start.secretB32, code)
            ?: return false to "The TOTP code did not match. Scan the QR code and try again."
        val v = Vault(
            enabled = true, secretB32 = start.secretB32, lastCounter = match,
            failCount = 0, lockUntilMs = 0, enrolledAtMs = System.currentTimeMillis()
        )
        if (!saveVault(id, v)) return false to "Failed to write the local second-factor vault."
        pending.remove(id)
        PmpAuditLog.bindDatabase(fileUri)
        PmpAuditLog.record(PmpAuditLog.EV_TWO_FACTOR_ENROLL, PmpAuditLog.OC_SUCCESS,
            PmpAuditLog.FLD_NONE, PmpAuditLog.TGT_LOCAL_DATABASE)
        return true to ""
    }

    fun removeEnrollment(fileUri: String?) {
        val id = id16(fileUri)
        if (vaultFile(id).delete()) {
            PmpAuditLog.bindDatabase(fileUri)
            PmpAuditLog.record(PmpAuditLog.EV_TWO_FACTOR_UNENROLL, PmpAuditLog.OC_SUCCESS,
                PmpAuditLog.FLD_NONE, PmpAuditLog.TGT_LOCAL_DATABASE)
        }
        pending.remove(id)
    }

    /** Returns (result, humanMessage). Result is one of the * constants. */
    fun verifyInteractive(fileUri: String?, code: String): Pair<Int, String> {
        val id = id16(fileUri)
        val v = loadVault(id) ?: return NOT_ENROLLED to ""
        PmpAuditLog.bindDatabase(fileUri)
        val now = System.currentTimeMillis()

        if (v.lockUntilMs > now) {
            val secs = (v.lockUntilMs - now + 999) / 1000
            PmpAuditLog.record(PmpAuditLog.EV_TWO_FACTOR_FAILED, PmpAuditLog.OC_DENIED,
                PmpAuditLog.FLD_TOTP, PmpAuditLog.TGT_LOCAL_DATABASE)
            return LOCKED to "Too many failed attempts. Try again in $secs second(s)."
        }
        val entered = code.filter { it.isDigit() }
        if (entered.length != DIGITS) return WRONG to "Enter the $DIGITS-digit code."

        val matched = matchCode(v.secretB32, entered)
        if (matched != null && matched <= v.lastCounter) {
            PmpAuditLog.record(PmpAuditLog.EV_TWO_FACTOR_FAILED, PmpAuditLog.OC_DENIED,
                PmpAuditLog.FLD_TOTP, PmpAuditLog.TGT_LOCAL_DATABASE)
            return REPLAY to "This code has already been used. Wait for the next code."
        }
        if (matched != null) {
            v.lastCounter = maxOf(v.lastCounter, matched)
            v.failCount = 0
            v.lockUntilMs = 0
            saveVault(id, v)
            PmpAuditLog.record(PmpAuditLog.EV_TWO_FACTOR, PmpAuditLog.OC_SUCCESS,
                PmpAuditLog.FLD_TOTP, PmpAuditLog.TGT_LOCAL_DATABASE)
            return OK to ""
        }

        v.failCount += 1
        v.lockUntilMs = if (v.failCount >= HARD_LOCK_FAILURES) {
            now + 15 * 60 * 1000L
        } else {
            val shift = minOf(v.failCount - 1, 5)
            now + minOf(2000L * (1L shl shift), 60_000L)
        }
        saveVault(id, v)
        val secs = (v.lockUntilMs - now + 999) / 1000
        val remaining = maxOf(0, HARD_LOCK_FAILURES - v.failCount)
        PmpAuditLog.record(PmpAuditLog.EV_TWO_FACTOR_FAILED, PmpAuditLog.OC_FAILURE,
            PmpAuditLog.FLD_TOTP, PmpAuditLog.TGT_LOCAL_DATABASE)
        return WRONG to "Incorrect code. $remaining attempt(s) remaining before a longer lockout. Retry in $secs second(s)."
    }

    /** Matches over the +/-1 window; returns the matched counter, or null. */
    private fun matchCode(secretB32: String, code: String): Long? {
        val entered = code.filter { it.isDigit() }
        if (entered.length != DIGITS) return null
        val nowSec = System.currentTimeMillis() / 1000
        for (off in -1..1) {
            val c = nowSec / STEP + off
            if (c < 0) continue
            val expected = generateTotp(secretB32, c * STEP) ?: continue
            if (constantTimeEqual(expected, entered)) return c
        }
        return null
    }

    fun failCount(fileUri: String?): Int = loadVault(id16(fileUri))?.failCount ?: 0
}
