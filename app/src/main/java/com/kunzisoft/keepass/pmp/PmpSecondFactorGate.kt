/*
 * PmVault extensions for KeePassDX - second-factor unlock dialog.
 * Shown after the master credential succeeds, only for enrolled databases.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import android.app.Activity
import android.app.AlertDialog
import android.text.InputType
import android.widget.EditText

object PmpSecondFactorGate {
    fun prompt(
        activity: Activity,
        fileUri: String?,
        onSuccess: () -> Unit,
        onFail: () -> Unit
    ) {
        val input = EditText(activity).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            hint = "000000"
        }
        val dialog = AlertDialog.Builder(activity)
            .setTitle("第二因素（TOTP）")
            .setMessage("请输入验证器应用中显示的 6 位验证码。")
            .setView(input)
            .setCancelable(false)
            .setPositiveButton("解锁", null)
            .setNegativeButton("取消") { _, _ -> onFail() }
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val (result, message) = PmpSecondFactor.verifyInteractive(fileUri, input.text.toString())
                when (result) {
                    PmpSecondFactor.OK -> {
                        dialog.dismiss()
                        onSuccess()
                    }
                    PmpSecondFactor.NOT_ENROLLED -> {
                        // Enrollment disappeared: do not block unlock.
                        dialog.dismiss()
                        onSuccess()
                    }
                    else -> {
                        input.error = message
                        input.text?.clear()
                    }
                }
            }
        }
        dialog.show()
    }
}
