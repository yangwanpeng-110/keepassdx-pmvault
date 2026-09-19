/*
 * PmVault extensions for KeePassDX - data-level sync store.
 *
 * PmpSyncRunner speaks TLS/protocol/merge against this interface. To stay
 * independent from KeePassDX internal node/database classes (and keep the
 * network core deterministic and unit-testable), entries cross the boundary as
 * plain PmpEntryData DTOs. A thin bridge in the open-database layer maps
 * EntryKDBX <-> PmpEntryData (documented in docs/PMP_SYNC_ANDROID.md); this
 * in-memory implementation is also used by the on-device loopback self-test.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

data class PmpEntryData(
    var uuid: String,
    val fields: LinkedHashMap<String, String> = LinkedHashMap(),
    var vclockJson: String = "",
    var lastHash: String = "",
    var deleted: Boolean = false,
    var tombVclockJson: String = "",
    var origin: String = ""
)

/** Fingerprint pin list, persisted per database in app-private storage. */
object PmpPeerTrust {
    private fun file(fileUri: String?) =
        File(PmVault.dir("sync"), "${PmVault.dbId(fileUri).take(16)}.peers.json")

    fun isTrusted(fileUri: String?, fp: String): Boolean {
        val f = file(fileUri)
        if (!f.exists()) return false
        return runCatching {
            val arr = JSONArray(f.readText())
            (0 until arr.length()).any { arr.getString(it).equals(fp, true) }
        }.getOrDefault(false)
    }

    fun trust(fileUri: String?, fp: String) {
        val f = file(fileUri)
        val arr = if (f.exists()) runCatching { JSONArray(f.readText()) }.getOrDefault(JSONArray())
        else JSONArray()
        if ((0 until arr.length()).none { arr.getString(it).equals(fp, true) }) {
            arr.put(fp.lowercase())
            f.writeText(arr.toString())
        }
    }
}

class PmpInMemoryStore(
    private val entries: MutableList<PmpEntryData>,
    private val fileUri: String,
    private val selfNode: String,
    private val confirmPeer: (String) -> Boolean
) : PmpSyncStore {

    override fun selfNodeId() = selfNode
    override fun dbId() = PmVault.dbId(fileUri)

    override fun buildLocalState(): State {
        val state = State()
        for (e in entries) {
            if (e.deleted) {
                if (e.tombVclockJson.isNotEmpty()) {
                    state.tombs[e.uuid] = VClock.fromJson(JSONObject(e.tombVclockJson))
                }
                continue
            }
            val fields = JSONObject()
            for ((k, v) in e.fields) fields.put(k, v)
            val snap = Snapshot(e.uuid, fields = fields)
            snap.computeHash()
            if (e.origin.isEmpty()) e.origin = ORIGIN_MOBILE
            snap.origin = e.origin
            var vc = VClock.fromJson(runCatching { JSONObject(e.vclockJson) }.getOrNull())
            if (vc.isEmpty()) vc.tick(selfNode)
            if (e.lastHash != snap.contentHash) vc.tick(selfNode)
            e.vclockJson = vc.toJson().toString()
            e.lastHash = snap.contentHash
            state.live[e.uuid] = vc
            state.snaps[e.uuid] = snap
        }
        return state
    }

    override fun apply(actions: List<Action>, remote: State): IntArray {
        var upserted = 0; var deleted = 0; var copies = 0
        for (a in actions) {
            when (a.kind) {
                ACT_UPSERT -> {
                    val snap = a.snap
                    var e = entries.firstOrNull { it.uuid == a.localUuid }
                    if (e == null) {
                        e = PmpEntryData(a.localUuid)
                        entries.add(e)
                    }
                    e.deleted = false
                    e.fields.clear()
                    val keys = snap.fields.keys()
                    while (keys.hasNext()) {
                        val k = keys.next()
                        e.fields[k] = snap.fields.optString(k)
                    }
                    e.origin = snap.origin.ifEmpty { ORIGIN_DESKTOP }
                    val vc = VClock.merge(
                        VClock.fromJson(runCatching { JSONObject(e.vclockJson) }.getOrNull()),
                        snap.vclock
                    )
                    vc.tick(selfNode)
                    e.vclockJson = vc.toJson().toString()
                    e.lastHash = snap.computeHash()
                    upserted++
                }
                ACT_CONFLICT_COPY -> {
                    val snap = a.snap
                    val copy = PmpEntryData(UUID.randomUUID().toString().replace("-", ""))
                    val keys = snap.fields.keys()
                    while (keys.hasNext()) {
                        val k = keys.next()
                        var v = snap.fields.optString(k)
                        if (k == "Title") v = "$v (conflict copy ${selfNode.take(6)})"
                        copy.fields[k] = v
                    }
                    copy.origin = snap.origin.ifEmpty { ORIGIN_DESKTOP }
                    val vc = snap.vclock.copy()
                    vc.tick(selfNode)
                    copy.vclockJson = vc.toJson().toString()
                    val s = Snapshot(copy.uuid, fields = JSONObject(copy.fields))
                    copy.lastHash = s.computeHash()
                    entries.add(copy)
                    copies++
                }
                ACT_DELETE -> {
                    val e = entries.firstOrNull { it.uuid == a.localUuid }
                    if (e != null) {
                        val vc = VClock.merge(
                            VClock.fromJson(runCatching { JSONObject(e.vclockJson) }.getOrNull()),
                            remote.tombs[a.localUuid] ?: VClock()
                        )
                        vc.tick(selfNode)
                        e.deleted = true
                        e.tombVclockJson = vc.toJson().toString()
                        deleted++
                    }
                }
            }
        }
        return intArrayOf(upserted, deleted, copies)
    }

    override fun peerTrusted(fingerprint: String) =
        PmpPeerTrust.isTrusted(fileUri, fingerprint)

    override fun trustPeer(fingerprint: String) =
        PmpPeerTrust.trust(fileUri, fingerprint)

    fun confirm(fp: String) = confirmPeer(fp)
}
