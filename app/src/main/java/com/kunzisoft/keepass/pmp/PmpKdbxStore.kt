/*
 * PmVault extensions for KeePassDX - real KDBX-backed sync store.
 *
 * Maps the open database (the global Database singleton) to the PmpSyncStore
 * interface used by PmpSyncRunner. This is the Android mirror of the desktop
 * PmpSync.cpp buildLocalState()/applyMerge(), so a Windows KeePassXC-based peer
 * and this client merge identically and interoperate over the LAN.
 *
 * Protocol conformance (must stay in lock-step with the desktop):
 *  - UUIDs are exchanged as standard lowercase hyphenated strings
 *    (java.util.UUID.toString()), NOT KeePassDX's uppercase 32-hex NodeIdUUID.
 *  - contentHash is over entry attributes only (sorted keys, key\0value\0,
 *    UTF-8, SHA-256) and never includes the creating-device origin.
 *  - New and conflict-copy entries are attached to the root group.
 *  - Only the Password attribute is protected; custom data keys PM:* are the
 *    sync bookkeeping (PM:VClock / PM:LastSyncHash / PM:Origin per entry,
 *    PM:Tombstones in database metadata) and are never synced as attributes.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import com.kunzisoft.keepass.database.element.CustomDataItem
import com.kunzisoft.keepass.database.element.Database
import com.kunzisoft.keepass.database.element.Entry
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.node.NodeHandler
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.security.ProtectedString
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

class PmpKdbxStore(
    private val db: Database,
    private val fileUri: String
) : PmpSyncStore {

    companion object {
        const val K_VCLOCK = "PM:VClock"
        const val K_LASTHASH = "PM:LastSyncHash"
        const val K_ORIGIN = "PM:Origin"
        const val K_TOMBS = "PM:Tombstones"
        private const val PASSWORD_KEY = "Password"
        private const val TITLE_KEY = "Title"
        private const val CONFLICT_PREFIX = " (conflict copy "
    }

    private val selfNode: String by lazy { PmpIdentityStore.loadOrCreate().nodeId }
    private var peerNode: String = ""

    override fun onPeerNode(node: String) {
        if (node.isNotEmpty()) peerNode = node
    }

    override fun selfNodeId(): String = selfNode
    override fun dbId(): String = PmVault.dbId(fileUri)

    private fun uuidOf(entry: Entry): String =
        (entry.nodeId as NodeIdUUID).id.toString()

    private fun findEntry(uuid: String): Entry? {
        val target = runCatching { UUID.fromString(uuid) }.getOrNull() ?: return null
        var found: Entry? = null
        db.rootGroup?.doForEachChild(object : NodeHandler<Entry>() {
            override fun operate(node: Entry): Boolean {
                val nid = node.nodeId as? NodeIdUUID
                if (nid != null && nid.id == target) {
                    found = node
                    return false // stop iteration
                }
                return true
            }
        }, null)
        return found
    }

    private fun customValue(kx: EntryKDBX, key: String): String? =
        kx.customData.get(key)?.value

    private fun writeEntryMeta(kx: EntryKDBX, vc: VClock, hash: String, origin: String) {
        kx.customData.put(CustomDataItem(K_VCLOCK, vc.toJson().toString()))
        kx.customData.put(CustomDataItem(K_LASTHASH, hash))
        kx.customData.put(CustomDataItem(K_ORIGIN, origin))
    }

    override fun buildLocalState(): State {
        val state = State()
        val root = db.rootGroup ?: return state
        root.doForEachChild(object : NodeHandler<Entry>() {
            override fun operate(entry: Entry): Boolean {
                val kx = entry.entryKDBX ?: return true
                val fields = JSONObject()
                for (f in kx.getFields()) {
                    // PM:* bookkeeping lives in CustomData, never in synced attributes.
                    if (f.name.startsWith("PM:")) continue
                    fields.put(f.name, f.protectedValue.toString())
                }
                val snap = Snapshot(uuidOf(entry), fields = fields)
                snap.computeHash()
                var origin = customValue(kx, K_ORIGIN).orEmpty()
                if (origin.isEmpty()) origin = ORIGIN_MOBILE
                snap.origin = origin

                var vc = VClock.fromJson(
                    runCatching { JSONObject(customValue(kx, K_VCLOCK) ?: "") }.getOrNull()
                )
                if (vc.isEmpty()) vc.tick(selfNode)
                if (customValue(kx, K_LASTHASH) != snap.contentHash) vc.tick(selfNode)

                writeEntryMeta(kx, vc, snap.contentHash, origin)
                state.live[snap.uuid] = vc
                state.snaps[snap.uuid] = snap
                return true
            }
        }, null)

        val tombsRaw = db.metaCustomData?.get(K_TOMBS)?.value
        state.tombs.putAll(
            PmpSyncCore.tombsFromJson(runCatching { JSONArray(tombsRaw) }.getOrNull())
        )
        return state
    }

    private fun putFields(kx: EntryKDBX, fields: JSONObject) {
        val keys = fields.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            kx.putField(k, ProtectedString(k == PASSWORD_KEY, fields.optString(k)))
        }
    }

    override fun apply(actions: List<Action>, remote: State): IntArray {
        var upserted = 0
        var deleted = 0
        var copies = 0
        val root = db.rootGroup ?: return intArrayOf(0, 0, 0)
        val meta = db.metaCustomData
        val tombs = PmpSyncCore.tombsFromJson(
            runCatching { JSONArray(meta?.get(K_TOMBS)?.value ?: "") }.getOrNull()
        )
        var changed = false

        for (a in actions) {
            when (a.kind) {
                ACT_UPSERT -> {
                    val snap = a.snap
                    val existing = findEntry(a.localUuid)
                    val created = existing == null
                    val entry = existing ?: db.createEntry() ?: continue
                    if (existing == null) {
                        entry.nodeId = NodeIdUUID(UUID.fromString(a.localUuid))
                    }
                    val kx = entry.entryKDBX ?: continue
                    putFields(kx, snap.fields)
                    val origin = snap.origin.ifEmpty { ORIGIN_DESKTOP }
                    val vc = VClock.merge(
                        VClock.fromJson(
                            runCatching { JSONObject(customValue(kx, K_VCLOCK) ?: "") }.getOrNull()
                        ),
                        snap.vclock
                    )
                    vc.tick(selfNode)
                    writeEntryMeta(kx, vc, snap.computeHash(), origin)
                    if (created) db.addEntryTo(entry, root) else db.updateEntry(entry)
                    upserted++
                    changed = true
                }
                ACT_CONFLICT_COPY -> {
                    val snap = a.snap
                    val entry = db.createEntry() ?: continue
                    val kx = entry.entryKDBX ?: continue
                    val adjusted = JSONObject()
                    val tag = peerNode.ifEmpty { selfNode }.take(6)
                    val keys = snap.fields.keys()
                    while (keys.hasNext()) {
                        val k = keys.next()
                        var v = snap.fields.optString(k)
                        if (k == TITLE_KEY) v = "$v$CONFLICT_PREFIX$tag)"
                        adjusted.put(k, v)
                        kx.putField(k, ProtectedString(k == PASSWORD_KEY, v))
                    }
                    val origin = snap.origin.ifEmpty { ORIGIN_DESKTOP }
                    val copySnap = Snapshot(fields = adjusted)
                    val vc = snap.vclock.copy()
                    vc.tick(selfNode)
                    writeEntryMeta(kx, vc, copySnap.computeHash(), origin)
                    db.addEntryTo(entry, root)
                    copies++
                    changed = true
                }
                ACT_DELETE -> {
                    val entry = findEntry(a.localUuid)
                    if (entry != null) {
                        val kx = entry.entryKDBX
                        val localVc = VClock.fromJson(
                            runCatching {
                                JSONObject(if (kx != null) customValue(kx, K_VCLOCK) ?: "" else "")
                            }.getOrNull()
                        )
                        val vc = VClock.merge(localVc, remote.tombs[a.localUuid] ?: VClock())
                        vc.tick(selfNode)
                        tombs[a.localUuid] = vc
                        db.deleteEntry(entry)
                        deleted++
                        changed = true
                    }
                }
            }
        }

        if (changed && meta != null) {
            val arr = JSONArray()
            for ((u, vc) in tombs) arr.put(Tombstone(u, vc).toJson())
            meta.put(CustomDataItem(K_TOMBS, arr.toString()))
        }
        return intArrayOf(upserted, deleted, copies)
    }

    override fun peerTrusted(fingerprint: String): Boolean =
        PmpPeerTrust.isTrusted(fileUri, fingerprint)

    override fun trustPeer(fingerprint: String) {
        PmpPeerTrust.trust(fileUri, fingerprint)
    }
}
