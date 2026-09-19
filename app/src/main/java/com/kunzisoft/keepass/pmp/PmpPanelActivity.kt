/*
 * PmVault extensions for KeePassDX - local tools panel.
 *
 * Provides a self-contained screen (code-built UI, no resource changes) for:
 *   - enrolling / removing the TOTP second factor for a database,
 *   - verifying and browsing the encrypted audit chain,
 *   - a loopback self-test of the mutual-TLS-1.3 sync engine.
 *
 * It is registered as a separate launcher icon ("PmVault 工具"). The second
 * factor gate itself is enforced automatically in MainCredentialActivity.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import java.util.Date
import java.util.UUID

class PmpPanelActivity : AppCompatActivity() {

    private lateinit var uriEdit: EditText
    private lateinit var status: TextView
    private lateinit var syncLog: TextView
    private val ui = Handler(Looper.getMainLooper())

    private fun uri() = uriEdit.text?.toString()?.trim().orEmpty()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        PmVault.init(applicationContext)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 40, 36, 40)
        }
        val scroll = ScrollView(this)
        fun section(title: String) {
            root.addView(TextView(this).apply {
                text = title
                textSize = 17f
                setPadding(0, 28, 0, 12)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            })
        }
        fun button(label: String, onClick: () -> Unit) {
            root.addView(Button(this).apply {
                text = label
                setOnClickListener { onClick() }
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { topMargin = 12 }
            })
        }

        root.addView(TextView(this).apply {
            text = "PmVault 工具"
            textSize = 22f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })

        section("数据库文件 URI")
        uriEdit = EditText(this).apply {
            setText(PmVault.getLastDatabaseUri() ?: "")
            hint = "content://…/database.kdbx"
        }
        root.addView(uriEdit)

        section("第二因素（TOTP 解锁）")
        status = TextView(this).apply { textSize = 13f }
        root.addView(status)
        button("刷新状态") { refreshStatus() }
        button("启用第二因素") { enroll() }
        button("移除第二因素") { remove() }

        section("加密审计日志")
        button("校验完整性") { verifyAudit() }
        button("查看最近记录") { showRecords() }

        section("局域网同步（TLS 1.3 双向证书）")
        root.addView(TextView(this).apply {
            text = "默认关闭 · 端口 19532 · 单次监听 30 秒 · 冲突默认双方保留。\n" +
                    "TLS 1.3 需要 Android 10 及以上，下方按钮在本机对证书、协议" +
                    "与合并引擎进行环回自测。"
            textSize = 12f
        })
        button("运行本机环回自测") { loopbackSelfTest() }
        syncLog = TextView(this).apply { textSize = 12f; setPadding(0, 12, 0, 0) }
        root.addView(syncLog)

        scroll.addView(root)
        setContentView(scroll)
        refreshStatus()
    }

    private fun refreshStatus() {
        val enrolled = PmpSecondFactor.isEnrolled(uri())
        status.text = "第二因素：" + if (enrolled) "已启用" else "未启用"
    }

    private fun enroll() {
        val label = uri().substringAfterLast('/').substringBefore('?').ifEmpty { "database" }
        val start = PmpSecondFactor.beginEnroll(uri(), label)
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            hint = "6 位验证码"
        }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 32, 48, 0)
            addView(TextView(this@PmpPanelActivity).apply {
                text = "1) 将以下密钥添加到验证器应用：\n\n" +
                        "密钥：${start.secretB32}\n\n${start.otpauthUri}\n\n" +
                        "2) 输入当前 6 位验证码完成确认。"
                textSize = 12f
            })
            addView(input)
        }
        AlertDialog.Builder(this)
            .setTitle("启用第二因素")
            .setView(container)
            .setPositiveButton("确认") { _, _ ->
                val (ok, err) = PmpSecondFactor.confirmEnroll(uri(), input.text.toString())
                toast(if (ok) "第二因素已启用。" else err)
                refreshStatus()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun remove() {
        if (!PmpSecondFactor.isEnrolled(uri())) {
            toast("尚未启用第二因素。"); return
        }
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            hint = "当前 6 位验证码"
        }
        AlertDialog.Builder(this)
            .setTitle("移除第二因素")
            .setMessage("请输入当前验证码以确认移除。")
            .setView(input)
            .setPositiveButton("移除") { _, _ ->
                val (result, _) = PmpSecondFactor.verifyInteractive(uri(), input.text.toString())
                if (result == PmpSecondFactor.OK) {
                    PmpSecondFactor.removeEnrollment(uri())
                    toast("第二因素已移除。")
                } else {
                    toast("验证码不正确，未授权移除。")
                }
                refreshStatus()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun verifyAudit() {
        PmpAuditLog.bindDatabase(uri())
        val r = PmpAuditLog.verify(uri())
        AlertDialog.Builder(this)
            .setTitle("审计完整性校验")
            .setMessage("${r.message}\n\n哈希链正常：${r.chainOk}\n锚点正常：${r.anchorOk}\n" +
                    "已截断：${r.truncated}\n可读记录：${r.readableCount}/${r.totalCount}")
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun showRecords() {
        PmpAuditLog.bindDatabase(uri())
        val records = PmpAuditLog.readAll(uri(), 200).takeLast(120).asReversed()
        val body = if (records.isEmpty()) {
            "该数据库暂无审计记录。"
        } else {
            records.joinToString("\n") { r ->
                val t = Date(r.ts).toString()
                val field = PmpAuditLog.fieldName(r.field).let { if (it.isEmpty()) "" else " · $it" }
                val target = PmpAuditLog.targetName(r.target).let { if (it.isEmpty()) "" else " · $it" }
                "#${r.seq} $t  ${PmpAuditLog.eventName(r.event)} [${PmpAuditLog.outcomeName(r.outcome)}]$field$target"
            }
        }
        val tv = TextView(this).apply { setTextIsSelectable(true); text = body; textSize = 12f }
        val pad = 48
        AlertDialog.Builder(this)
            .setTitle("最近审计记录（最多 120 条）")
            .setView(tv)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun appendLog(line: String) {
        ui.post {
            syncLog.text = syncLog.text.toString() + line + "\n"
        }
    }

    private fun loopbackSelfTest() {
        syncLog.text = ""
        val identity = PmpIdentityStore.loadOrCreate()
        val fileUri = uri().ifEmpty { "loopback-self-test" }
        val local = mutableListOf<PmpEntryData>()
        val remote = mutableListOf(
            PmpEntryData(UUID.randomUUID().toString().replace("-", "")).apply {
                fields["Title"] = "From peer"
                fields["UserName"] = "alice"
                fields["Password"] = "secret"
            }
        )
        val storeA = PmpInMemoryStore(local, fileUri, identity.nodeId) { fp ->
            appendLog("Trusting peer ${fp.take(16)} (loopback)"); true
        }
        val storeB = PmpInMemoryStore(remote, fileUri, identity.nodeId) { true }

        PmpSyncRunner(storeA, true, "", SYNC_DEFAULT_PORT, POLICY_KEEP_BOTH,
            { true },
            { line -> appendLog("A: $line") },
            { r -> appendLog("A result: ok=${r.ok} upserted=${r.upserted} - ${r.message}") }).start()

        ui.postDelayed({
            PmpSyncRunner(storeB, false, "127.0.0.1", SYNC_DEFAULT_PORT, POLICY_KEEP_BOTH,
                { true },
                { line -> appendLog("B: $line") },
                { r -> appendLog("B result: ok=${r.ok} upserted=${r.upserted} - ${r.message}") }).start()
        }, 900)
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
}
