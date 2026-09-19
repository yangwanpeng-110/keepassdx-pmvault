/*
 * PmVault extensions for KeePassDX - second factor (TOTP) management.
 *
 * Reached from the open-database overflow menu for the CURRENTLY OPEN database.
 * Enrollment shows ONLY a scannable QR code (otpauth:// URI) plus a 6-digit
 * confirmation field. The 160-bit base32 seed is never displayed as text.
 * Removal requires a current valid code.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.kunzisoft.keepass.database.ContextualDatabase

class PmpSecondFactorDialog : DialogFragment() {

    private fun dp(v: Int): Int =
        (v * resources.displayMetrics.density + 0.5f).toInt()

    private fun fileUri(): String =
        ContextualDatabase.getInstance().fileUri?.toString() ?: ""

    /** Renders the otpauth URI as a black-on-white QR bitmap (zxing core only). */
    private fun qrBitmap(content: String, px: Int): Bitmap? = try {
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, px, px)
        val bmp = Bitmap.createBitmap(px, px, Bitmap.Config.ARGB_8888)
        for (x in 0 until px) {
            for (y in 0 until px) {
                bmp.setPixel(x, y, if (matrix.get(x, y)) Color.BLACK else Color.WHITE)
            }
        }
        bmp
    } catch (e: Exception) {
        null
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): AlertDialog {
        val ctx = requireContext()
        val uri = fileUri()
        val enrolled = PmpSecondFactor.isEnrolled(uri)

        val root = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), dp(4))
        }

        val builder = MaterialAlertDialogBuilder(ctx)
            .setNegativeButton("关闭", null)

        if (uri.isEmpty()) {
            root.addView(TextView(ctx).apply { text = "请先打开一个数据库。" })
            return builder.setTitle("第二因素（TOTP）").setView(root).create()
        }

        if (enrolled) {
            builder.setTitle("第二因素（TOTP）")
            root.addView(TextView(ctx).apply {
                text = "当前数据库已启用第二因素（TOTP）。\n解锁时除主密码外，还需输入验证器中的 6 位验证码。"
                setPadding(0, dp(8), 0, dp(8))
            })
            builder.setPositiveButton("移除第二因素") { _, _ -> promptRemove(uri) }
            builder.setView(root)
            return builder.create()
        }

        // ---- enrollment: QR code + confirmation field only, no seed text ----
        val label = uri.substringAfterLast('/').substringBefore('?').ifEmpty { "database" }
        val start = PmpSecondFactor.beginEnroll(uri, label)

        builder.setTitle("启用第二因素（TOTP）")
        val intro = TextView(ctx).apply {
            text = "1. 使用 Google 验证器、微软 Authenticator 等扫描下方二维码。\n" +
                "2. 在验证器中读取当前 6 位验证码并填入下方，点“确认启用”。"
            setPadding(0, dp(4), 0, dp(8))
        }
        root.addView(intro)

        val qrImage = ImageView(ctx).apply {
            scaleType = ImageView.ScaleType.FIT_CENTER
            val bmp = qrBitmap(start.otpauthUri, 560)
            if (bmp != null) setImageBitmap(bmp)
            val size = dp(220)
            layoutParams = LinearLayout.LayoutParams(size, size).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            }
            setBackgroundColor(Color.WHITE)
        }
        root.addView(qrImage)

        if (qrImage.drawable == null) {
            root.addView(TextView(ctx).apply {
                text = "二维码生成失败，请改用“PmVault 工具”手动录入。"
                setPadding(0, dp(8), 0, 0)
            })
        }

        val codeInput = EditText(ctx).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            hint = "输入 6 位验证码"
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            )
            lp.topMargin = dp(12)
            layoutParams = lp
        }
        root.addView(codeInput)

        builder.setView(root)
        // Custom click handler: keep the dialog open on failure.
        builder.setPositiveButton("确认启用", null)
        val dialog = builder.create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val code = codeInput.text.toString()
                val (ok, err) = PmpSecondFactor.confirmEnroll(uri, code)
                if (ok) {
                    Toast.makeText(ctx, "第二因素已启用。", Toast.LENGTH_LONG).show()
                    dialog.dismiss()
                } else {
                    codeInput.error = err
                    codeInput.text?.clear()
                }
            }
        }
        return dialog
    }

    private fun promptRemove(uri: String) {
        val ctx = requireContext()
        val input = EditText(ctx).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            hint = "输入当前 6 位验证码"
        }
        val container = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), dp(4))
            addView(TextView(ctx).apply { text = "移除第二因素需要验证当前验证码。" })
            addView(input)
        }
        MaterialAlertDialogBuilder(ctx)
            .setTitle("移除第二因素")
            .setView(container)
            .setPositiveButton("移除", null)
            .setNegativeButton("取消", null)
            .create().also { d ->
                d.setOnShowListener {
                    d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        val (result, _) =
                            PmpSecondFactor.verifyInteractive(uri, input.text.toString())
                        if (result == PmpSecondFactor.OK) {
                            PmpSecondFactor.removeEnrollment(uri)
                            Toast.makeText(ctx, "第二因素已移除。", Toast.LENGTH_LONG).show()
                            d.dismiss()
                            this.dialog?.dismiss()
                        } else {
                            input.error = "验证码不正确，请重试。"
                            input.text?.clear()
                        }
                    }
                }
                d.show()
            }
    }

    companion object {
        const val TAG = "PmpSecondFactorDialog"
        fun show(fm: androidx.fragment.app.FragmentManager) {
            PmpSecondFactorDialog().show(fm, TAG)
        }
    }
}
