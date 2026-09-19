/*
 * PmVault extensions for KeePassDX - local tools panel.
 *
 * Provides a self-contained screen (code-built UI, no resource changes) for:
 *   - enrolling / removing the TOTP second factor for a database,
 *   - verifying and browsing the encrypted audit chain,
 *   - a loopback self-test of the mutual-TLS-1.3 sync engine.
 *
 * It is registered as a separate launcher icon ("PmVault tools"). The second
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
            text = "PmVault tools"
            textSize = 22f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })

        section("Database file URI")
        uriEdit = EditText(this).apply {
            setText(PmVault.getLastDatabaseUri() ?: "")
            hint = "content://…/database.kdbx"
        }
        root.addView(uriEdit)

        section("Second factor (TOTP unlock)")
        status = TextView(this).apply { textSize = 13f }
        root.addView(status)
        button("Refresh status") { refreshStatus() }
        button("Enable second factor") { enroll() }
        button("Remove second factor") { remove() }

        section("Encrypted audit log")
        button("Verify integrity") { verifyAudit() }
        button("Show recent records") { showRecords() }

        section("LAN sync (TLS 1.3, mutual certificates)")
        root.addView(TextView(this).apply {
            text = "Default off · port 19532 · single 30 s listen · KeepBoth conflicts.\n" +
                    "TLS 1.3 requires Android 10+. The button below runs a loopback " +
                    "self-test of the certificate, protocol and merge engine on this device."
            textSize = 12f
        })
        button("Run loopback self-test") { loopbackSelfTest() }
        syncLog = TextView(this).apply { textSize = 12f; setPadding(0, 12, 0, 0) }
        root.addView(syncLog)

        scroll.addView(root)
        setContentView(scroll)
        refreshStatus()
    }

    private fun refreshStatus() {
        val enrolled = PmpSecondFactor.isEnrolled(uri())
        status.text = "Second factor: " + if (enrolled) "ENROLLED" else "not enrolled"
    }

    private fun enroll() {
        val label = uri().substringAfterLast('/').substringBefore('?').ifEmpty { "database" }
        val start = PmpSecondFactor.beginEnroll(uri(), label)
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            hint = "6-digit code"
        }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 32, 48, 0)
            addView(TextView(this@PmpPanelActivity).apply {
                text = "1) Add this secret to your authenticator app:\n\n" +
                        "Secret: ${start.secretB32}\n\n${start.otpauthUri}\n\n" +
                        "2) Enter the current 6-digit code to confirm."
                textSize = 12f
            })
            addView(input)
        }
        AlertDialog.Builder(this)
            .setTitle("Enable second factor")
            .setView(container)
            .setPositiveButton("Confirm") { _, _ ->
                val (ok, err) = PmpSecondFactor.confirmEnroll(uri(), input.text.toString())
                toast(if (ok) "Second factor enabled." else err)
                refreshStatus()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun remove() {
        if (!PmpSecondFactor.isEnrolled(uri())) {
            toast("Not enrolled."); return
        }
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            hint = "current 6-digit code"
        }
        AlertDialog.Builder(this)
            .setTitle("Remove second factor")
            .setMessage("Enter a current code to confirm removal.")
            .setView(input)
            .setPositiveButton("Remove") { _, _ ->
                val (result, _) = PmpSecondFactor.verifyInteractive(uri(), input.text.toString())
                if (result == PmpSecondFactor.OK) {
                    PmpSecondFactor.removeEnrollment(uri())
                    toast("Second factor removed.")
                } else {
                    toast("Removal not authorised.")
                }
                refreshStatus()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun verifyAudit() {
        PmpAuditLog.bindDatabase(uri())
        val r = PmpAuditLog.verify(uri())
        AlertDialog.Builder(this)
            .setTitle("Audit integrity")
            .setMessage("${r.message}\n\nChain OK: ${r.chainOk}\nAnchor OK: ${r.anchorOk}\n" +
                    "Truncated: ${r.truncated}\nReadable: ${r.readableCount}/${r.totalCount}")
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun showRecords() {
        PmpAuditLog.bindDatabase(uri())
        val records = PmpAuditLog.readAll(uri(), 200).takeLast(120).asReversed()
        val body = if (records.isEmpty()) {
            "No records for this database yet."
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
            .setTitle("Recent audit records")
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
