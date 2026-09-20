/*
 * PmVault extensions for KeePassDX - LAN TLS 1.3 two-way sync engine.
 *
 * Symmetric line-delimited JSON protocol, identical to the desktop client:
 *   HELLO -> MANIFEST -> WANT -> ENTRIES -> APPLIED -> BYE
 * Both sides connect (or accept once), verify the peer certificate by
 * SHA-256 fingerprint pinning (never the system CA store), negotiate TLS 1.3
 * with a mutual client certificate, exchange vector-clock manifests, fetch only
 * changed entry snapshots, then merge deterministically with PmpSyncCore.
 *
 * The engine is independent of the KeePassDX database API; persistence is
 * isolated behind PmpSyncStore so the network/merge core is deterministic and
 * testable. Defaults: feature off, port 19532, single 30 s accept window,
 * KeepBoth conflict policy, LAN-only peers.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import org.json.JSONArray
import org.json.JSONObject
import android.os.Build
import java.io.BufferedReader
import java.io.EOFException
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLProtocolException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

const val SYNC_DEFAULT_PORT = 19532
private const val ACCEPT_TIMEOUT_MS = 60_000
private const val IO_TIMEOUT_MS = 30_000
private const val CONNECT_TIMEOUT_MS = 15_000

/** Enumerate this device's non-loopback IPv4 addresses (helps the user aim the peer). */
fun pmpLocalIpv4Addresses(): List<String> {
    val out = ArrayList<String>()
    try {
        for (iface in NetworkInterface.getNetworkInterfaces()) {
            if (!iface.isUp || iface.isLoopback) continue
            for (addr in iface.inetAddresses) {
                if (addr is Inet4Address && !addr.isLoopbackAddress) {
                    out.add(addr.hostAddress ?: continue)
                }
            }
        }
    } catch (_: Exception) {
    }
    return out
}

/** Abstraction over the concrete KeePassDX database (kept out of the network core). */
interface PmpSyncStore {
    fun selfNodeId(): String
    fun dbId(): String
    /** Build the local causal state; also ticks clocks for locally edited entries. */
    fun buildLocalState(): State
    /** Apply a planned merge; returns the number of upserts/deletes/conflict copies. */
    fun apply(actions: List<Action>, remote: State): IntArray // [upserted, deleted, copies]
    fun peerTrusted(fingerprint: String): Boolean
    fun trustPeer(fingerprint: String)
    /** Called once the peer node id is known (before apply), for conflict-copy naming. */
    fun onPeerNode(node: String) {}
}

data class SyncReport(
    var ok: Boolean = false,
    var message: String = "",
    var peerNode: String = "",
    var peerFingerprint: String = "",
    var upserted: Int = 0,
    var deleted: Int = 0,
    var conflictCopies: Int = 0
)

class PmpSyncRunner(
    private val store: PmpSyncStore,
    private val listen: Boolean,
    private val host: String,
    private val port: Int = SYNC_DEFAULT_PORT,
    private val policy: Int = POLICY_KEEP_BOTH,
    private val confirmPeer: (String) -> Boolean,
    private val onLog: (String) -> Unit,
    private val onDone: (SyncReport) -> Unit
) {
    private val executor = Executors.newSingleThreadExecutor()
    private val finished = AtomicBoolean(false)
    private val report = SyncReport()

    // Bounded phase trace; the concrete failure is written to the encrypted audit log.
    private val trace = StringBuilder()

    @Synchronized
    private fun note(line: String) {
        onLog(line)
        if (trace.length > 2400) trace.delete(0, trace.length - 2000)
        trace.append(line).append('\n')
    }

    private fun traceTail(max: Int = 600): String {
        synchronized(this) {
            val s = trace.toString().replace('\n', ';').trim(';')
            return if (s.length > max) s.substring(s.length - max) else s
        }
    }

    /** Map a raw exception to a concrete, actionable Chinese diagnosis. */
    private fun classify(e: Throwable): String {
        val chain = StringBuilder()
        var t: Throwable? = e
        var guard = 0
        while (t != null && guard < 4) {
            if (chain.isNotEmpty()) chain.append(" / ")
            chain.append(t.javaClass.simpleName).append(": ").append(t.message)
            t = t.cause
            guard++
        }
        val raw = chain.toString()
        return when {
            e is SocketTimeoutException ->
                "连接超时（$raw）。通常是两端不在同一 Wi-Fi、路由器开启了 AP 隔离、" +
                "电脑防火墙未放行入站 TCP $port 端口，或 IP 地址填错。"
            e is ConnectException ->
                "无法建立 TCP 连接（$raw）。请确认对端已点击“开始监听”、IP 与端口正确、" +
                "两端在同一 Wi-Fi，并在电脑防火墙允许程序入站连接。"
            e is UnknownHostException ->
                "无法解析对端主机名（$raw），请直接填写电脑的局域网 IPv4 地址（如 192.168.x.x）。"
            e is SSLHandshakeException ->
                "TLS 握手失败（$raw）。可能是证书未被信任（请在两端都确认指纹）、" +
                "系统不支持 TLS 1.3（需 Android 10 及以上），或被代理/VPN 劫持。"
            e is SSLPeerUnverifiedException ->
                "对端证书校验未通过（$raw），请核对并信任对端显示的证书指纹。"
            e is SSLProtocolException ->
                "TLS 协议协商失败（$raw），通常是代理/VPN（如 Clash 的 TUN/局域网劫持）拦截，" +
                "或系统不支持 TLS 1.3。"
            e is SSLException ->
                "TLS 连接异常（$raw），请检查代理/VPN 与 TLS 1.3 支持。"
            e is EOFException ->
                "对端在握手或同步过程中断开（$raw），请查看电脑端同步窗口的红字提示。"
            else -> raw
        }
    }

    fun start() {
        executor.execute {
            try {
                note("环境：Android API ${Build.VERSION.SDK_INT}，端口 $port，" +
                    if (listen) "本机监听，等待对端连接" else "主动连接对端 $host")
                val ips = pmpLocalIpv4Addresses()
                note("本机 IPv4：" + (ips.joinToString("，").ifEmpty { "未检测到（请确认已连接 Wi-Fi）" }))
                val tlsProtocols = runCatching {
                    (PmpIdentityStore.sslContext(PmpIdentityStore.loadOrCreate()) { true }
                        .socketFactory.createSocket() as? SSLSocket)
                        ?.supportedProtocols?.joinToString(",")
                }.getOrNull()
                note("系统支持的 TLS：" + (tlsProtocols ?: "未知"))
                if (tlsProtocols != null && !tlsProtocols.contains("TLSv1.3")) {
                    note("警告：本设备不支持 TLS 1.3，无法与电脑端同步（需 Android 10 及以上）")
                }
                val identity = PmpIdentityStore.loadOrCreate()
                val ctx: SSLContext = PmpIdentityStore.sslContext(identity) { cert ->
                    val fp = PmpIdentityStore.fullFingerprint(cert).lowercase()
                    if (store.peerTrusted(fp)) {
                        true
                    } else {
                        val ok = confirmPeer(fp)
                        if (ok) store.trustPeer(fp)
                        ok
                    }
                }
                val socket = if (listen) acceptOnce(ctx) else connectOnce(ctx)
                if (socket == null) {
                    fail("监听窗口内没有对端连接。请让电脑端在 60 秒内连接本机 IP，并确认防火墙已放行。")
                    return@execute
                }
                handle(socket)
            } catch (e: Exception) {
                fail(classify(e))
            }
        }
    }

    private fun acceptOnce(ctx: SSLContext): SSLSocket? {
        val ips = pmpLocalIpv4Addresses()
        note("正在端口 $port 监听单个局域网对端（60 秒）…")
        if (ips.isNotEmpty()) note("本机局域网 IP：${ips.joinToString("，")}（让电脑端连接此地址）")
        val factory = ctx.serverSocketFactory
        // Bind an unbound server socket first so we can enable address reuse and
        // survive a previous listener that is still in TIME_WAIT.
        val server = factory.createServerSocket() as SSLServerSocket
        server.reuseAddress = true
        server.needClientAuth = true
        try {
            server.bind(InetSocketAddress(port), 1)
        } catch (e: Exception) {
            server.close()
            throw IllegalStateException("端口 $port 无法监听（可能被占用）：${e.message}", e)
        }
        server.soTimeout = ACCEPT_TIMEOUT_MS
        val raw = try {
            server.accept()
        } catch (e: SocketTimeoutException) {
            server.close()
            return null
        } catch (e: Exception) {
            server.close()
            throw IllegalStateException("监听出错：${e.javaClass.simpleName}: ${e.message}", e)
        }
        server.close() // single connection only
        val ssl = raw as SSLSocket
        ssl.soTimeout = IO_TIMEOUT_MS
        note("来自 ${ssl.inetAddress.hostAddress}:${ssl.port} 的 TCP 连接已建立，开始 TLS 1.3 握手…")
        forceTls13(ssl)
        try {
            ssl.startHandshake()
        } catch (e: SSLHandshakeException) {
            throw IllegalStateException("TLS 握手失败（证书/信任或 TLS 版本）：${e.message}", e)
        } catch (e: SSLException) {
            throw IllegalStateException("握手期间 TLS 错误：${e.message}", e)
        }
        return ssl
    }

    private fun connectOnce(ctx: SSLContext): SSLSocket {
        note("正在通过 TLS 1.3 连接 $host:$port …")
        pmpLocalIpv4Addresses().takeIf { it.isNotEmpty() }?.let {
            note("本机局域网 IP：${it.joinToString("，")}")
        }
        val raw = Socket()
        try {
            raw.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        } catch (e: Exception) {
            raw.close()
            throw e
        }
        note("已与 ${raw.inetAddress.hostAddress}:$port 建立 TCP 连接，开始 TLS 1.3 握手…")
        val ssl = ctx.socketFactory.createSocket(raw, host, port, true) as SSLSocket
        ssl.soTimeout = IO_TIMEOUT_MS
        forceTls13(ssl)
        try {
            ssl.startHandshake()
        } catch (e: SSLHandshakeException) {
            throw IllegalStateException(
                "TLS 握手失败。请检查对端 IP/端口、两端在同一 Wi-Fi（无 AP 隔离/VPN），" +
                "并在两端确认证书指纹。${e.message}", e)
        } catch (e: SSLException) {
            throw IllegalStateException("握手期间 TLS 错误：${e.message}", e)
        }
        return ssl
    }

    private fun forceTls13(s: SSLSocket) {
        try {
            s.enabledProtocols = arrayOf("TLSv1.3")
        } catch (e: Exception) {
            throw IllegalStateException("TLS 1.3 需要 Android 10 或更高版本：${e.message}")
        }
    }

    private fun isLan(addr: InetAddress): Boolean {
        if (addr.isLoopbackAddress || addr.isLinkLocalAddress) return true
        if (addr.isSiteLocalAddress) return true // 10/8, 172.16/12, 192.168/16
        val b = addr.address
        // IPv6 unique local fc00::/7
        return b.size == 16 && (b[0] == 0xfc.toByte() || b[0] == 0xfd.toByte())
    }

    private fun handle(socket: SSLSocket) {
        socket.use { s ->
            if (!isLan(s.inetAddress)) {
                fail("对端地址 ${s.inetAddress.hostAddress} 不在局域网内，已拒绝。"); return
            }
            val proto = s.session.protocol
            if (proto != "TLSv1.3") {
                fail("协商结果为 $proto，不是 TLS 1.3，已中止。"); return
            }
            val certs = s.session.peerCertificates
            val peerCert = certs?.firstOrNull() as? java.security.cert.X509Certificate
                ?: run { fail("双向 TLS 失败：对端未提供证书。"); return }
            val fp = PmpIdentityStore.fullFingerprint(peerCert).lowercase()
            report.peerFingerprint = fp
            report.peerNode = fp.take(16)
            note("已与对端 ${report.peerNode} 建立 TLS 1.3 加密通道")

            val writer = PrintWriter(s.getOutputStream(), true)
            val reader = BufferedReader(InputStreamReader(s.getInputStream()))

            val local = store.buildLocalState()
            val selfNode = store.selfNodeId()
            val dbId = store.dbId()

            fun send(o: JSONObject) {
                writer.println(o.toString())
                writer.flush()
            }
            fun manifestJson(): JSONObject {
                val live = JSONArray()
                for ((uuid, snap) in local.snaps) {
                    val vc = local.live[uuid] ?: VClock()
                    live.put(JSONObject().put("uuid", uuid).put("vclock", vc.toJson()).put("hash", snap.contentHash))
                }
                val tombs = PmpSyncCore.tombsToJson(local.tombs)
                return JSONObject().put("type", "MANIFEST").put("node", selfNode).put("dbId", dbId)
                    .put("live", live).put("tombs", tombs)
            }
            send(JSONObject().put("type", "HELLO").put("node", selfNode).put("dbId", dbId))
            send(manifestJson())

            val remote = State()
            var remoteManifest: JSONObject? = null
            var expected = 0
            var applied = false
            var peerApplied = false

            fun computeWants(m: JSONObject): List<String> {
                val wants = ArrayList<String>()
                val arr = m.optJSONArray("live") ?: JSONArray()
                for (i in 0 until arr.length()) {
                    val item = arr.getJSONObject(i)
                    val uuid = item.optString("uuid")
                    val hash = item.optString("hash")
                    if (!local.live.containsKey(uuid) ||
                        (local.snaps[uuid]?.contentHash ?: "") != hash
                    ) {
                        wants.add(uuid)
                    }
                }
                return wants
            }

            fun sendEntries(uuids: List<String>) {
                val items = JSONArray()
                for (u in uuids) {
                    local.snaps[u]?.let { items.put(it.toJson()) }
                }
                send(JSONObject().put("type", "ENTRIES").put("items", items))
            }

            fun applyMergeAndReply() {
                if (applied) return
                store.onPeerNode(report.peerNode)
                val actions = PmpSyncCore.planMerge(local, remote, policy)
                val counts = store.apply(actions, remote)
                val upserted = counts[0]; val deleted = counts[1]; val copies = counts[2]
                report.upserted = upserted; report.deleted = deleted; report.conflictCopies = copies
                applied = true
                send(JSONObject().put("type", "APPLIED").put("upserted", upserted)
                    .put("deleted", deleted).put("copies", copies))
                note("本机已合并：更新 $upserted 条，删除 $deleted 条，冲突副本 $copies 条。")
                if (peerApplied) {
                    send(JSONObject().put("type", "BYE"))
                    finishOk("双向同步完成。")
                }
            }

            while (true) {
                val line = reader.readLine() ?: break
                if (line.isBlank()) continue
                val msg = runCatching { JSONObject(line) }.getOrNull() ?: continue
                when (msg.optString("type")) {
                    "HELLO" -> report.peerNode = msg.optString("node", report.peerNode)
                    "MANIFEST" -> {
                        remoteManifest = msg
                        val arr = msg.optJSONArray("live") ?: JSONArray()
                        for (i in 0 until arr.length()) {
                            val it = arr.getJSONObject(i)
                            remote.live[it.optString("uuid")] = VClock.fromJson(it.opt("vclock"))
                        }
                        remote.tombs.putAll(PmpSyncCore.tombsFromJson(msg.optJSONArray("tombs")))
                        val wants = computeWants(msg)
                        expected = wants.size
                        val wa = JSONArray()
                        for (u in wants) wa.put(u)
                        send(JSONObject().put("type", "WANT").put("uuids", wa))
                        if (wants.isEmpty()) applyMergeAndReply()
                    }
                    "WANT" -> {
                        val uuids = ArrayList<String>()
                        val arr = msg.optJSONArray("uuids") ?: JSONArray()
                        for (i in 0 until arr.length()) uuids.add(arr.getString(i))
                        sendEntries(uuids)
                    }
                    "ENTRIES" -> {
                        val arr = msg.optJSONArray("items") ?: JSONArray()
                        for (i in 0 until arr.length()) {
                            val snap = Snapshot.fromJson(arr.getJSONObject(i))
                            if (snap.uuid.isNotEmpty()) remote.snaps[snap.uuid] = snap
                        }
                        if (remote.snaps.size >= expected) applyMergeAndReply()
                    }
                    "APPLIED" -> {
                        peerApplied = true
                        note("对端已应用变更（更新 ${msg.optInt("upserted")}，" +
                                "删除 ${msg.optInt("deleted")}，冲突副本 ${msg.optInt("copies")}）")
                        if (applied) {
                            send(JSONObject().put("type", "BYE"))
                            finishOk("双向同步完成。")
                        }
                    }
                    "BYE" -> if (applied) finishOk("双向同步完成。")
                }
                if (finished.get()) break
            }
            if (!finished.get() && applied) finishOk("同步完成，对端已断开。")
            else if (!finished.get()) fail("同步在应用变更之前结束（协议未完成）。")
        }
    }

    private fun finishOk(message: String) {
        if (finished.getAndSet(true)) return
        report.ok = true; report.message = message
        note(message)
        onDone(report)
        PmpAuditLog.record(PmpAuditLog.EV_SYNC, PmpAuditLog.OC_SUCCESS,
            PmpAuditLog.FLD_NONE, PmpAuditLog.TGT_LAN_PEER,
            "peer=${report.peerNode} up=${report.upserted} del=${report.deleted} copies=${report.conflictCopies}")
    }

    private fun fail(message: String) {
        if (finished.getAndSet(true)) return
        report.ok = false; report.message = message
        note("同步失败：$message")
        onDone(report)
        PmpAuditLog.record(PmpAuditLog.EV_SYNC_FAILED, PmpAuditLog.OC_FAILURE,
            PmpAuditLog.FLD_NONE, PmpAuditLog.TGT_LAN_PEER,
            (traceTail() + " || " + message).take(600))
    }
}
