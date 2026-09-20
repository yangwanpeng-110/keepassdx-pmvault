/*
 * PmVault extensions for KeePassDX - local encrypted, tamper-evident audit log.
 *
 * This is a port of the desktop PmpAuditLog and shares the exact on-disk format:
 *  - fixed event/outcome/field/target enumeration; the record API takes no
 *    value-class parameters (never passwords, names, codes, titles or URLs);
 *  - each record is AES-256-GCM sealed with the previous chain link as AAD;
 *  - link = HMAC(chainKey, prevLink || sealed), forming a hash chain;
 *  - a separately sealed anchor (AAD "PmVault/audit-anchor/v1") pins the last
 *    sequence and link, detecting tail truncation;
 *  - logs live OUTSIDE the KDBX database in app-private storage and never sync.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import org.json.JSONObject
import java.io.File

object PmpAuditLog {
    // Numeric values are part of the on-disk format: never renumber.
    const val EV_UNKNOWN = 0
    const val EV_UNLOCK = 1
    const val EV_UNLOCK_FAILED = 2
    const val EV_TWO_FACTOR = 3
    const val EV_TWO_FACTOR_FAILED = 4
    const val EV_TWO_FACTOR_ENROLL = 5
    const val EV_TWO_FACTOR_UNENROLL = 6
    const val EV_LOCK = 7
    const val EV_PASSWORD_CHANGE = 8
    const val EV_COPY = 9
    const val EV_BROWSER_FILL = 10
    const val EV_AUTO_TYPE = 11
    const val EV_SYNC = 12
    const val EV_SYNC_FAILED = 13
    const val EV_CONFIG_CHANGE = 14
    const val EV_LOG_ROTATE = 15

    const val OC_INFO = 0
    const val OC_SUCCESS = 1
    const val OC_FAILURE = 2
    const val OC_DENIED = 3

    const val FLD_NONE = 0
    const val FLD_USERNAME = 1
    const val FLD_PASSWORD = 2
    const val FLD_TOTP = 3
    const val FLD_URL = 4
    const val FLD_NOTES = 5
    const val FLD_OTHER = 6

    const val TGT_NONE = 0
    const val TGT_LOCAL_DATABASE = 1
    const val TGT_BROWSER_DOM = 2
    const val TGT_DESKTOP_WINDOW = 3
    const val TGT_LAN_PEER = 4

    private const val ANCHOR_AAD = "PmVault/audit-anchor/v1"
    private const val ARCHIVE_KEEP = 5
    private const val MAX_BYTES = 10L * 1024 * 1024
    private const val RETENTION_DAYS = 90L

    private val lock = Any()
    private var currentId = ""
    private var lastSeq = 0L
    private var lastLink = ByteArray(32)
    @Volatile
    var verbose = true

    data class Record(
        val seq: Long, val ts: Long, val event: Int, val outcome: Int,
        val field: Int, val target: Int, val dbId: String,
        // Optional, backward-compatible 10th field. Network/TLS diagnostics only;
        // never entry titles, URLs, usernames, passwords or TOTP codes.
        val detail: String = ""
    )

    data class VerifyResult(
        var chainOk: Boolean = false,
        var anchorOk: Boolean = false,
        var truncated: Boolean = false,
        var readableCount: Int = 0,
        var totalCount: Int = 0,
        var lastSeq: Long = 0,
        var message: String = ""
    )

    private fun genesis() = ByteArray(32)
    private fun id16(fileUri: String?) = PmVault.dbId(fileUri).take(16)
    private fun logFile(id: String) = File(PmVault.dir("audit"), "$id.logx")
    private fun anchorFile(id: String) = File(PmVault.dir("audit"), "$id.anchor")
    private fun logKey(id: String) = PmVault.deriveKey("audit-log:$id")
    private fun chainKey(id: String) = PmVault.deriveKey("audit-chain:$id")

    private class Chain(var seq: Long = 0L, var link: ByteArray = ByteArray(32), var readable: Int = 0)

    fun bindDatabase(fileUri: String?) = synchronized(lock) {
        currentId = id16(fileUri)
        val st = replay(currentId)
        lastSeq = st.seq
        lastLink = st.link
        pruneArchives(currentId)
    }

    fun closeDatabase() = synchronized(lock) {
        currentId = ""
        lastSeq = 0L
        lastLink = genesis()
    }

    private fun securityCritical(event: Int) = when (event) {
        EV_UNLOCK, EV_UNLOCK_FAILED, EV_TWO_FACTOR, EV_TWO_FACTOR_FAILED,
        EV_TWO_FACTOR_ENROLL, EV_TWO_FACTOR_UNENROLL, EV_LOCK,
        EV_PASSWORD_CHANGE, EV_SYNC, EV_SYNC_FAILED, EV_LOG_ROTATE -> true
        else -> false
    }

    /**
     * Sanitize an optional diagnostic detail: strip the field delimiter, line
     * breaks and control characters, percent-encode the rest, and bound the
     * length. Only network/TLS stage and error text is allowed.
     */
    private fun encodeDetail(detail: String): String {
        if (detail.isEmpty()) return ""
        val cleaned = StringBuilder(detail.length)
        for (ch in detail) {
            if (ch.code < 0x20 || ch == '|' || ch == '\u007f') {
                cleaned.append(' ')
            } else {
                cleaned.append(ch)
            }
        }
        var s = cleaned.toString().trim()
        if (s.length > 600) s = s.substring(0, 600)
        return runCatching { java.net.URLEncoder.encode(s, "UTF-8") }.getOrDefault("")
    }

    /** The ONLY recording entry point. No free-text value parameters (detail is diagnostics only). */
    fun record(event: Int, outcome: Int = OC_SUCCESS, field: Int = FLD_NONE, target: Int = TGT_NONE,
               detail: String = "") =
        synchronized(lock) {
            if (currentId.isEmpty()) return@synchronized
            if (!verbose && !securityCritical(event)) return@synchronized
            rotateIfNeeded(currentId)

            val seq = lastSeq + 1
            val ts = System.currentTimeMillis()
            var plainLine = "v1|$seq|$ts|$event|$outcome|$field|$target|$currentId|"
            val encDetail = encodeDetail(detail)
            if (encDetail.isNotEmpty()) plainLine += encDetail
            val plain = plainLine.toByteArray(Charsets.UTF_8)
            val prevLink = lastLink
            val sealed = PmpCrypto.aesGcmSeal(logKey(currentId), plain, prevLink)
            val f = logFile(currentId)
            f.appendText(PmpCrypto.toB64(sealed) + "\n")

            lastLink = PmpCrypto.hmacSha256(chainKey(currentId), prevLink + sealed)
            lastSeq = seq
            writeAnchor(currentId, lastSeq, lastLink)
        }

    private fun writeAnchor(id: String, seq: Long, link: ByteArray) {
        val plain = "$seq|${PmpCrypto.toHex(link)}".toByteArray(Charsets.UTF_8)
        val sealed = PmpCrypto.aesGcmSeal(logKey(id), plain, ANCHOR_AAD.toByteArray())
        anchorFile(id).writeText(PmpCrypto.toB64(sealed) + "\n")
    }

    private fun openLine(id: String, line: String, prevLink: ByteArray): ByteArray? {
        val sealed = PmpCrypto.fromB64(line.trim())
        return PmpCrypto.aesGcmOpen(logKey(id), sealed, prevLink)
    }

    private fun decode(plain: ByteArray): Record? {
        val p = String(plain, Charsets.UTF_8).split('|')
        if (p.size < 9 || p[0] != "v1") return null
        return runCatching {
            val detail = if (p.size >= 10) {
                runCatching { java.net.URLDecoder.decode(p[9], "UTF-8") }.getOrDefault("")
            } else ""
            Record(p[1].toLong(), p[2].toLong(), p[3].toInt(), p[4].toInt(),
                p[5].toInt(), p[6].toInt(), p[7], detail)
        }.getOrNull()
    }

    private fun replay(id: String): Chain {
        val st = Chain()
        val f = logFile(id)
        if (!f.exists()) return st
        f.forEachLine { raw ->
            if (raw.isBlank()) return@forEachLine
            val plain = openLine(id, raw, st.link) ?: return@forEachLine
            val rec = decode(plain) ?: return@forEachLine
            val sealed = PmpCrypto.fromB64(raw.trim())
            st.link = PmpCrypto.hmacSha256(chainKey(id), st.link + sealed)
            st.seq = rec.seq
            st.readable++
        }
        return st
    }

    fun verify(fileUri: String? = null): VerifyResult = synchronized(lock) {
        val id = if (fileUri != null) id16(fileUri) else currentId
        val res = VerifyResult()
        if (id.isEmpty()) {
            res.message = "No database bound to the audit log."
            return@synchronized res
        }
        val st = replay(id)
        res.readableCount = st.readable
        res.lastSeq = st.seq
        var total = 0
        logFile(id).takeIf { it.exists() }?.forEachLine { if (it.isNotBlank()) total++ }
        res.totalCount = total
        res.chainOk = st.readable == total

        val af = anchorFile(id)
        if (af.exists()) {
            val sealed = PmpCrypto.fromB64(af.readText().trim())
            val plain = PmpCrypto.aesGcmOpen(logKey(id), sealed, ANCHOR_AAD.toByteArray())
            if (plain != null) {
                val parts = String(plain, Charsets.UTF_8).split('|')
                if (parts.size == 2) {
                    val anchorSeq = parts[0].toLong()
                    val anchorLink = PmpCrypto.fromHex(parts[1])
                    res.anchorOk = anchorSeq == st.seq && anchorLink.contentEquals(st.link)
                }
            }
        }
        res.truncated = res.chainOk && !res.anchorOk
        res.message = when {
            res.chainOk && res.anchorOk -> "Audit chain intact: ${st.readable} record(s)."
            !res.chainOk -> "Tampering detected: chain breaks at record ${st.readable + 1} of $total."
            else -> "Truncation detected: the log tail does not match the integrity anchor."
        }
        res
    }

    fun readAll(fileUri: String? = null, max: Int = 5000): List<Record> = synchronized(lock) {
        val id = if (fileUri != null) id16(fileUri) else currentId
        val out = ArrayList<Record>()
        if (id.isEmpty() || !logFile(id).exists()) return@synchronized out
        var link = genesis()
        logFile(id).forEachLine { raw ->
            if (out.size >= max) return@forEachLine
            if (raw.isBlank()) return@forEachLine
            val plain = openLine(id, raw, link) ?: return@forEachLine
            val rec = decode(plain) ?: return@forEachLine
            val sealed = PmpCrypto.fromB64(raw.trim())
            link = PmpCrypto.hmacSha256(chainKey(id), link + sealed)
            out.add(rec)
        }
        out
    }

    private fun rotateIfNeeded(id: String) {
        val path = logFile(id)
        if (!path.exists() || path.length() < MAX_BYTES) return
        val archive = File(path.parentFile, "$id.logx.${System.currentTimeMillis()}")
        path.renameTo(archive)
        pruneArchives(id)

        val seq = lastSeq + 1
        val ts = System.currentTimeMillis()
        val plain = "v1|$seq|$ts|$EV_LOG_ROTATE|$OC_INFO|$FLD_NONE|$TGT_NONE|$id|"
            .toByteArray(Charsets.UTF_8)
        val sealed = PmpCrypto.aesGcmSeal(logKey(id), plain, lastLink)
        path.appendText(PmpCrypto.toB64(sealed) + "\n")
        lastLink = PmpCrypto.hmacSha256(chainKey(id), lastLink + sealed)
        lastSeq = seq
        writeAnchor(id, lastSeq, lastLink)
    }

    private fun pruneArchives(id: String) {
        val dir = PmVault.dir("audit")
        val prefix = "$id.logx."
        val cutoff = System.currentTimeMillis() - RETENTION_DAYS * 86400_000L
        val archives = dir.listFiles { f -> f.name.startsWith(prefix) }?.toMutableList() ?: return
        for (f in archives) {
            if (f.lastModified() < cutoff) f.delete()
        }
        val fresh = dir.listFiles { f -> f.name.startsWith(prefix) }?.sortedByDescending { it.lastModified() }
            ?: return
        fresh.drop(ARCHIVE_KEEP).forEach { it.delete() }
    }

    fun eventName(e: Int) = when (e) {
        EV_UNLOCK -> "Unlock"; EV_UNLOCK_FAILED -> "Unlock failed"
        EV_TWO_FACTOR -> "Second factor"; EV_TWO_FACTOR_FAILED -> "Second factor failed"
        EV_TWO_FACTOR_ENROLL -> "Second factor enrolled"; EV_TWO_FACTOR_UNENROLL -> "Second factor removed"
        EV_LOCK -> "Lock"; EV_PASSWORD_CHANGE -> "Password changed"; EV_COPY -> "Copy"
        EV_BROWSER_FILL -> "Browser DOM fill"; EV_AUTO_TYPE -> "Auto-Type"
        EV_SYNC -> "LAN sync"; EV_SYNC_FAILED -> "LAN sync failed"
        EV_CONFIG_CHANGE -> "Configuration changed"; EV_LOG_ROTATE -> "Log rotated"
        else -> "Unknown"
    }

    fun outcomeName(o: Int) = when (o) {
        OC_SUCCESS -> "Success"; OC_FAILURE -> "Failure"; OC_DENIED -> "Denied"; else -> "Info"
    }

    fun fieldName(f: Int) = when (f) {
        FLD_USERNAME -> "username"; FLD_PASSWORD -> "password"; FLD_TOTP -> "TOTP"
        FLD_URL -> "URL"; FLD_NOTES -> "notes"; FLD_OTHER -> "other"; else -> ""
    }

    fun targetName(t: Int) = when (t) {
        TGT_LOCAL_DATABASE -> "local database"; TGT_BROWSER_DOM -> "browser DOM"
        TGT_DESKTOP_WINDOW -> "desktop window"; TGT_LAN_PEER -> "LAN peer"; else -> ""
    }
}
