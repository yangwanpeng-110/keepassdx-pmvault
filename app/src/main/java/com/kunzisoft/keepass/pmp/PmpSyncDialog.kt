/*
 * PmVault extensions for KeePassDX - LAN mutual-TLS sync dialog.
 *
 * Launched from the open-database screen (GroupActivity overflow menu). It runs
 * PmpSyncRunner against the real PmpKdbxStore (the global open Database), shows
 * live progress, asks before trusting a never-seen peer certificate fingerprint
 * (pinning, no CA), and persists merged changes through the host activity's
 * saveDatabase() once the two-way exchange succeeds.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import android.app.Activity
import android.os.Bundle
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.kunzisoft.keepass.activities.legacy.DatabaseLockActivity
import com.kunzisoft.keepass.database.ContextualDatabase
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean

class PmpSyncDialog : DialogFragment() {

    private var logView: TextView? = null
    private var scroll: ScrollView? = null
    private var configContainer: LinearLayout? = null
    private var progressContainer: LinearLayout? = null
    private var startButton: Button? = null
    private var dialog: AlertDialog? = null
    private val running = AtomicBoolean(false)

    private fun dp(v: Int): Int =
        (v * resources.displayMetrics.density + 0.5f).toInt()

    private fun label(text: String): TextView =
        TextView(requireContext()).apply {
            this.text = text
            setPadding(0, dp(8), 0, dp(2))
        }

    override fun onCreateDialog(savedInstanceState: Bundle?): AlertDialog {
        val ctx = requireContext()
        val root = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), dp(4))
        }

        // ---- configuration ----
        val config = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
        val modeGroup = RadioGroup(ctx)
        val rbListen = RadioButton(ctx).apply {
            id = View.generateViewId()
            text = "等待电脑连接（在本机监听）"
            isChecked = true
        }
        val rbConnect = RadioButton(ctx).apply {
            id = View.generateViewId()
            text = "连接到电脑（输入电脑 IP）"
        }
        modeGroup.addView(rbListen)
        modeGroup.addView(rbConnect)
        config.addView(modeGroup)

        config.addView(label("电脑 IP 地址（连接模式）"))
        val ipEdit = EditText(ctx).apply {
            hint = "例如 192.168.1.20"
            inputType = InputType.TYPE_CLASS_PHONE
            isEnabled = false
        }
        config.addView(ipEdit)

        config.addView(label("端口"))
        val portEdit = EditText(ctx).apply {
            setText(SYNC_DEFAULT_PORT.toString())
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        config.addView(portEdit)

        modeGroup.setOnCheckedChangeListener { _, checkedId ->
            ipEdit.isEnabled = checkedId == rbConnect.id
        }

        startButton = Button(ctx).apply {
            text = "开始同步"
            setOnClickListener {
                val listen = modeGroup.checkedRadioButtonId == rbListen.id
                val host = ipEdit.text.toString().trim()
                val port = portEdit.text.toString().trim().toIntOrNull() ?: SYNC_DEFAULT_PORT
                if (!listen && host.isEmpty()) {
                    ipEdit.error = "请输入电脑的局域网 IP 地址"
                    return@setOnClickListener
                }
                beginSync(listen, host, port)
            }
        }
        config.addView(startButton)
        root.addView(config)

        // ---- progress ----
        val progress = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        val sv = ScrollView(ctx)
        val tv = TextView(ctx).apply {
            textSize = 12f
            gravity = Gravity.START
            setTextIsSelectable(true)
            text = ""
            val pad = dp(8)
            setPadding(pad, pad, pad, pad)
        }
        sv.addView(tv)
        val ph = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp(220)
        )
        progress.addView(sv, ph)
        root.addView(progress)

        logView = tv
        scroll = sv
        configContainer = config
        progressContainer = progress

        val d = MaterialAlertDialogBuilder(ctx)
            .setTitle("局域网同步（双向 · TLS 1.3）")
            .setView(root)
            .setNegativeButton("关闭", null)
            .setCancelable(false)
            .create()
        dialog = d
        return d
    }

    private fun appendLog(line: String) {
        val act = activity ?: return
        act.runOnUiThread {
            val tv = logView ?: return@runOnUiThread
            tv.append(line + "\n")
            scroll?.post { scroll?.fullScroll(View.FOCUS_DOWN) }
        }
    }

    /** Block the network/handshake thread until the user accepts or rejects the peer. */
    private fun askTrustPeer(fp: String): Boolean {
        val act = activity ?: return false
        val decision = AtomicBoolean(false)
        val latch = CountDownLatch(1)
        act.runOnUiThread {
            if (!isAdded) {
                latch.countDown(); return@runOnUiThread
            }
            MaterialAlertDialogBuilder(requireContext())
                .setTitle("是否信任该电脑？")
                .setMessage(
                    "首次与该设备同步，请核对电脑端显示的指纹是否一致：\n\n" +
                        fp + "\n\n" +
                        "两端一致时点“信任”，否则点“拒绝”。信任记录仅保存在本机。"
                )
                .setCancelable(false)
                .setPositiveButton("信任") { _, _ -> decision.set(true); latch.countDown() }
                .setNegativeButton("拒绝") { _, _ -> decision.set(false); latch.countDown() }
                .show()
        }
        latch.await()
        return decision.get()
    }

    private fun setCloseEnabled(enabled: Boolean) {
        val act = activity ?: return
        act.runOnUiThread {
            dialog?.getButton(AlertDialog.BUTTON_NEGATIVE)?.isEnabled = enabled
        }
    }

    private fun beginSync(listen: Boolean, host: String, port: Int) {
        if (!running.compareAndSet(false, true)) return
        configContainer?.visibility = View.GONE
        progressContainer?.visibility = View.VISIBLE
        startButton?.isEnabled = false
        setCloseEnabled(false)

        val database = ContextualDatabase.getInstance()
        val fileUri = database.fileUri?.toString() ?: ""
        val store = PmpKdbxStore(database, fileUri)

        val runner = PmpSyncRunner(
            store,
            listen,
            host,
            port,
            POLICY_KEEP_BOTH,
            confirmPeer = { fp -> askTrustPeer(fp) },
            onLog = { line -> appendLog(line) },
            onDone = { report -> onFinished(report) }
        )
        appendLog(if (listen) "本机进入监听，等待电脑发起同步…" else "正在连接电脑 $host:$port …")
        runner.start()
    }

    private fun onFinished(report: SyncReport) {
        val act = activity ?: return
        act.runOnUiThread {
            if (!isAdded) return@runOnUiThread
            if (report.ok) {
                val changes = report.upserted + report.deleted + report.conflictCopies
                appendLog(
                    "同步完成：更新 ${report.upserted}，删除 ${report.deleted}，" +
                        "冲突副本 ${report.conflictCopies}。"
                )
                if (changes > 0) {
                    appendLog("正在保存数据库…")
                    (act as? DatabaseLockActivity)?.saveDatabase()
                }
            } else {
                appendLog("同步失败：${report.message}")
            }
            running.set(false)
            setCloseEnabled(true)
        }
    }

    companion object {
        const val TAG = "PmpSyncDialog"
        fun show(fm: androidx.fragment.app.FragmentManager) {
            PmpSyncDialog().show(fm, TAG)
        }
    }
}
