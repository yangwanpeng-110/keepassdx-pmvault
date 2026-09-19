/*
 * PmVault extensions for KeePassDX - LAN sync data model and conflict
 * resolution. This is a line-by-line port of the desktop PmpSyncTypes.h so both
 * platforms resolve conflicts identically.
 *
 * Pure Kotlin (org.json only), no Android/KeePassDX dependencies.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import org.json.JSONArray
import org.json.JSONObject

class VClock(val ticks: HashMap<String, Long> = HashMap()) {

    fun isEmpty() = ticks.isEmpty()

    fun tick(node: String) {
        ticks[node] = (ticks[node] ?: 0L) + 1L
    }

    fun copy() = VClock(HashMap(ticks))

    fun toJson(): JSONObject {
        val o = JSONObject()
        for ((k, v) in ticks) o.put(k, v)
        return o
    }

    companion object {
        fun fromJson(v: Any?): VClock {
            val c = VClock()
            val o = v as? JSONObject ?: return c
            val keys = o.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                c.ticks[k] = o.getLong(k)
            }
            return c
        }

        fun merge(a: VClock, b: VClock): VClock {
            val out = a.copy()
            for ((k, v) in b.ticks) {
                out.ticks[k] = maxOf(out.ticks[k] ?: 0L, v)
            }
            return out
        }

        const val CLK_EQUAL = 0
        const val CLK_BEFORE = 1 // a happens before b
        const val CLK_AFTER = 2
        const val CLK_CONCURRENT = 3

        fun compare(a: VClock, b: VClock): Int {
            var aLess = false
            var bLess = false
            val nodes = HashSet<String>().apply {
                addAll(a.ticks.keys); addAll(b.ticks.keys)
            }
            for (n in nodes) {
                val av = a.ticks[n] ?: 0L
                val bv = b.ticks[n] ?: 0L
                if (av < bv) aLess = true
                else if (av > bv) bLess = true
            }
            return when {
                !aLess && !bLess -> CLK_EQUAL
                aLess && !bLess -> CLK_BEFORE
                bLess && !aLess -> CLK_AFTER
                else -> CLK_CONCURRENT
            }
        }
    }
}

class Snapshot(
    var uuid: String = "",
    var vclock: VClock = VClock(),
    var fields: JSONObject = JSONObject(),
    var contentHash: String = "",
    var origin: String = ""
) {
    fun computeHash(): String {
        val keys = ArrayList<String>().apply {
            val it = fields.keys()
            while (it.hasNext()) add(it.next())
        }.sorted()
        val canon = java.io.ByteArrayOutputStream()
        for (k in keys) {
            canon.write(k.toByteArray(Charsets.UTF_8)); canon.write(0)
            canon.write(fields.optString(k).toByteArray(Charsets.UTF_8)); canon.write(0)
        }
        contentHash = PmpCrypto.toHex(PmpCrypto.sha256(canon.toByteArray()))
        return contentHash
    }

    fun toJson(): JSONObject = JSONObject()
        .put("uuid", uuid)
        .put("vclock", vclock.toJson())
        .put("fields", fields)
        .put("hash", contentHash)
        .put("origin", origin)

    companion object {
        fun fromJson(o: JSONObject) = Snapshot(
            uuid = o.optString("uuid"),
            vclock = VClock.fromJson(o.opt("vclock")),
            fields = o.optJSONObject("fields") ?: JSONObject(),
            contentHash = o.optString("hash"),
            origin = o.optString("origin")
        )
    }
}

class Tombstone(var uuid: String = "", var vclock: VClock = VClock()) {
    fun toJson() = JSONObject().put("uuid", uuid).put("vclock", vclock.toJson())
    companion object {
        fun fromJson(o: JSONObject) =
            Tombstone(o.optString("uuid"), VClock.fromJson(o.opt("vclock")))
    }
}

const val POLICY_KEEP_BOTH = 0
const val POLICY_DELETE_WINS = 1

// Creating-device markers carried in Snapshot.origin (never part of contentHash).
const val ORIGIN_DESKTOP = "desktop"
const val ORIGIN_MOBILE = "mobile"

const val ACT_IGNORE = 0
const val ACT_UPSERT = 1
const val ACT_DELETE = 2
const val ACT_CONFLICT_COPY = 3

class Action(var kind: Int = ACT_IGNORE, var snap: Snapshot = Snapshot(), var localUuid: String = "")

class State(
    val live: HashMap<String, VClock> = HashMap(),
    val tombs: HashMap<String, VClock> = HashMap(),
    val snaps: HashMap<String, Snapshot> = HashMap()
)

object PmpSyncCore {
    /** Deterministic merge plan telling the local database what to do. */
    fun planMerge(local: State, remote: State, policy: Int): List<Action> {
        val actions = ArrayList<Action>()
        val uuids = HashSet<String>().apply {
            addAll(remote.live.keys); addAll(remote.tombs.keys)
        }
        for (uuid in uuids) {
            val rLive = remote.live.containsKey(uuid)
            val lLive = local.live.containsKey(uuid)
            val lTomb = local.tombs.containsKey(uuid)

            if (rLive) {
                val rv = remote.live[uuid]!!
                val rsnap = remote.snaps[uuid] ?: Snapshot(uuid = uuid)
                if (!lLive && !lTomb) {
                    actions.add(Action(ACT_UPSERT, rsnap, uuid))
                } else if (lLive) {
                    when (VClock.compare(local.live[uuid]!!, rv)) {
                        VClock.CLK_AFTER, VClock.CLK_EQUAL -> { /* local newer/equal */ }
                        VClock.CLK_BEFORE -> actions.add(Action(ACT_UPSERT, rsnap, uuid))
                        VClock.CLK_CONCURRENT -> {
                            val localHash = local.snaps[uuid]?.contentHash ?: ""
                            if (rsnap.contentHash.isNotEmpty() && localHash != rsnap.contentHash) {
                                actions.add(Action(ACT_CONFLICT_COPY, rsnap, uuid))
                            }
                        }
                    }
                } else if (lTomb) {
                    when (VClock.compare(local.tombs[uuid]!!, rv)) {
                        VClock.CLK_BEFORE -> actions.add(Action(ACT_UPSERT, rsnap, uuid))
                        VClock.CLK_CONCURRENT -> {
                            if (policy == POLICY_KEEP_BOTH) {
                                actions.add(Action(ACT_CONFLICT_COPY, rsnap, uuid))
                            } // DeleteWins: stay deleted
                        }
                        else -> {}
                    }
                }
            } else if (remote.tombs.containsKey(uuid)) {
                val rv = remote.tombs[uuid]!!
                if (lLive) {
                    when (VClock.compare(local.live[uuid]!!, rv)) {
                        VClock.CLK_BEFORE -> actions.add(Action(ACT_DELETE, localUuid = uuid))
                        VClock.CLK_CONCURRENT -> {
                            if (policy == POLICY_DELETE_WINS) {
                                actions.add(Action(ACT_DELETE, localUuid = uuid))
                            } // KeepBoth: keep the locally edited entry
                        }
                        else -> {}
                    }
                }
            }
        }
        return actions
    }

    fun tombsToJson(tombs: Map<String, VClock>): JSONArray {
        val arr = JSONArray()
        for ((uuid, vc) in tombs) arr.put(Tombstone(uuid, vc).toJson())
        return arr
    }

    fun tombsFromJson(arr: JSONArray?): HashMap<String, VClock> {
        val out = HashMap<String, VClock>()
        if (arr == null) return out
        for (i in 0 until arr.length()) {
            val t = Tombstone.fromJson(arr.optJSONObject(i) ?: continue)
            out[t.uuid] = t.vclock
        }
        return out
    }
}
