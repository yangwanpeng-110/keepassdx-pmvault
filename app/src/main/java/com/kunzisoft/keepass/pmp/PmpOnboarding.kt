/*
 * PmVault extensions for KeePassDX - first-run security onboarding.
 *
 * Shown once, right after a brand-new database created via the PmVault default
 * location is opened: asks whether to enable the TOTP second factor (QR enroll
 * dialog, no seed text) and then whether to enable fingerprint/face device
 * unlock. Mirrors the desktop create-database guidance.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import android.content.Intent
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentManager
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.kunzisoft.keepass.database.ContextualDatabase
import com.kunzisoft.keepass.settings.DeviceUnlockSettingsActivity

object PmpOnboarding {

    /** Runs the onboarding only for a freshly created database; otherwise no-op. */
    fun run(activity: AppCompatActivity) {
        val uri = ContextualDatabase.getInstance().fileUri?.toString() ?: return
        if (!PmVault.consumePendingOnboarding(uri)) return
        askTwoFactor(activity)
    }

    private fun askTwoFactor(activity: AppCompatActivity) {
        if (activity.isFinishing || activity.isDestroyed) return
        MaterialAlertDialogBuilder(activity)
            .setTitle("开启第二因素")
            .setMessage(
                "是否为该数据库开启第二因素（TOTP）？\n\n" +
                    "开启后，解锁时除主密码外，还需输入 Google 验证器等应用中的 6 位验证码。"
            )
            .setCancelable(false)
            .setPositiveButton("开启") { _, _ ->
                val fm = activity.supportFragmentManager
                // After the QR enroll dialog closes, continue to biometric setup.
                val cb = object : FragmentManager.FragmentLifecycleCallbacks() {
                    override fun onFragmentViewDestroyed(fm: FragmentManager, f: Fragment) {
                        if (f is PmpSecondFactorDialog) {
                            fm.unregisterFragmentLifecycleCallbacks(this)
                            askBiometric(activity)
                        }
                    }
                }
                fm.registerFragmentLifecycleCallbacks(cb, false)
                PmpSecondFactorDialog.show(fm)
            }
            .setNegativeButton("跳过") { _, _ -> askBiometric(activity) }
            .show()
    }

    private fun askBiometric(activity: AppCompatActivity) {
        if (activity.isFinishing || activity.isDestroyed) return
        MaterialAlertDialogBuilder(activity)
            .setTitle("指纹 / 人脸解锁")
            .setMessage("是否开启指纹或人脸快速解锁（设备解锁）？\n将打开设备解锁设置页。")
            .setCancelable(false)
            .setPositiveButton("去开启") { _, _ ->
                runCatching {
                    activity.startActivity(
                        Intent(activity, DeviceUnlockSettingsActivity::class.java)
                    )
                }
            }
            .setNegativeButton("以后再说", null)
            .show()
    }
}
