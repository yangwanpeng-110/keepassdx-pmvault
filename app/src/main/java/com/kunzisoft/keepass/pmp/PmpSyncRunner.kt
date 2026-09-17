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
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

const val SYNC_DEFAULT_PORT = 19532
private const val ACCEPT_TIMEOUT_MS = 30_000
private const val CONNECT_TIMEOUT_MS = 15_000

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

    fun start() {
        executor.execute {
            try {
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
                    fail("No peer connected within the listening window.")
                    return@execute
                }
                handle(socket)
            } catch (e: Exception) {
                fail(e.message ?: "Sync error")
            }
        }
    }

    private fun acceptOnce(ctx: SSLContext): SSLSocket? {
        onLog("Listening for a single LAN peer on port $port (30 s)…")
        val factory = ctx.serverSocketFactory
        val server = factory.createServerSocket(port, 1) as SSLServerSocket
        server.needClientAuth = true
        server.soTimeout = ACCEPT_TIMEOUT_MS
        val raw = try {
            server.accept()
        } catch (e: Exception) {
            server.close()
            return null
        }
        server.close() // single connection only
        val ssl = raw as SSLSocket
        ssl.soTimeout = ACCEPT_TIMEOUT_MS
        ssl.startHandshake()
        return ssl
    }

    private fun connectOnce(ctx: SSLContext): SSLSocket {
        onLog("Connecting to $host:$port over TLS 1.3…")
        val raw = Socket()
        raw.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        val ssl = ctx.socketFactory.createSocket(raw, host, port, true) as SSLSocket
        ssl.soTimeout = CONNECT_TIMEOUT_MS
        ssl.startHandshake()
        return ssl
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
                fail("Peer address is not on the local network."); return
            }
            val proto = s.session.protocol
            if (proto != "TLSv1.3") {
                fail("Negotiated protocol is $proto, not TLS 1.3; aborting."); return
            }
            val certs = s.session.peerCertificates
            val peerCert = certs?.firstOrNull() as? java.security.cert.X509Certificate
                ?: run { fail("Mutual TLS failed: no peer certificate."); return }
            val fp = PmpIdentityStore.fullFingerprint(peerCert).lowercase()
            report.peerFingerprint = fp
            report.peerNode = fp.take(16)
            onLog("TLS 1.3 secured with peer ${report.peerNode}")

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
                val actions = PmpSyncCore.planMerge(local, remote, policy)
                val counts = store.apply(actions, remote)
                val upserted = counts[0]; val deleted = counts[1]; val copies = counts[2]
                report.upserted = upserted; report.deleted = deleted; report.conflictCopies = copies
                applied = true
                PmpAuditLog.record(PmpAuditLog.EV_SYNC, PmpAuditLog.OC_SUCCESS,
                    PmpAuditLog.FLD_NONE, PmpAuditLog.TGT_LAN_PEER)
                send(JSONObject().put("type", "APPLIED").put("upserted", upserted)
                    .put("deleted", deleted).put("copies", copies))
                onLog("Merged: $upserted updated, $deleted deleted, $copies conflict copies.")
                if (peerApplied) {
                    send(JSONObject().put("type", "BYE"))
                    finishOk("Two-way sync completed.")
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
                        onLog("Peer applied changes (upsert ${msg.optInt("upserted")}, " +
                                "delete ${msg.optInt("deleted")}, copies ${msg.optInt("copies")})")
                        if (applied) {
                            send(JSONObject().put("type", "BYE"))
                            finishOk("Two-way sync completed.")
                        }
                    }
                    "BYE" -> if (applied) finishOk("Two-way sync completed.")
                }
                if (finished.get()) break
            }
            if (!finished.get() && applied) finishOk("Sync completed; peer disconnected.")
            else if (!finished.get()) fail("Sync ended before changes were applied.")
        }
    }

    private fun finishOk(message: String) {
        if (finished.getAndSet(true)) return
        report.ok = true; report.message = message
        onLog(message)
        onDone(report)
        PmpAuditLog.record(PmpAuditLog.EV_SYNC, PmpAuditLog.OC_SUCCESS,
            PmpAuditLog.FLD_NONE, PmpAuditLog.TGT_LAN_PEER)
    }

    private fun fail(message: String) {
        if (finished.getAndSet(true)) return
        report.ok = false; report.message = message
        onLog("Sync failed: $message")
        onDone(report)
        PmpAuditLog.record(PmpAuditLog.EV_SYNC_FAILED, PmpAuditLog.OC_FAILURE,
            PmpAuditLog.FLD_NONE, PmpAuditLog.TGT_LAN_PEER)
    }
}
