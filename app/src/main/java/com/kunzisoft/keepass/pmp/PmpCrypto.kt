/*
 * PmVault extensions for KeePassDX - cryptographic primitives (JCA).
 *
 * AES-256-GCM sealed record layout matches the desktop implementation:
 *   nonce(12) || ciphertext || tag(16)
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later, same as KeePassDX.
 */
package com.kunzisoft.keepass.pmp

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.Destroyable

object PmpCrypto {
    private val rng = SecureRandom()

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun sha256(msg: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(msg)

    fun hmacSha256(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg)
    }

    // HKDF-SHA256 (RFC 5869).
    fun hkdf(secret: ByteArray, salt: ByteArray, info: ByteArray, len: Int = 32): ByteArray {
        val prk = hmacSha256(salt.ifEmpty { ByteArray(32) }, secret)
        val out = ByteArray(len)
        var t = ByteArray(0)
        var pos = 0
        var i = 1
        while (pos < len) {
            t = hmacSha256(prk, t + info + byteArrayOf(i.toByte()))
            val take = minOf(t.size, len - pos)
            System.arraycopy(t, 0, out, pos, take)
            pos += take
            i++
        }
        return out
    }

    fun aesGcmSeal(key: ByteArray, plain: ByteArray, aad: ByteArray): ByteArray {
        val nonce = randomBytes(12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        val ct = c.doFinal(plain) // ciphertext || 16-byte tag
        return nonce + ct
    }

    /** Returns null on any decryption / authentication failure (never throws). */
    fun aesGcmOpen(key: ByteArray, sealed: ByteArray, aad: ByteArray): ByteArray? {
        if (sealed.size < 12 + 16 || key.size != 32) return null
        return try {
            val nonce = sealed.copyOfRange(0, 12)
            val body = sealed.copyOfRange(12, sealed.size)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            c.updateAAD(aad)
            c.doFinal(body)
        } catch (e: Exception) {
            null
        }
    }

    fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
    fun fromHex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    fun toB64(b: ByteArray): String = Base64.encodeToString(b, Base64.NO_WRAP)
    fun fromB64(s: String): ByteArray = Base64.decode(s, Base64.DEFAULT)

    // RFC 4648 Base32 (used by TOTP otpauth secrets).
    private const val B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    fun base32Encode(data: ByteArray): String {
        var buffer = 0
        var bits = 0
        val sb = StringBuilder()
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                val idx = (buffer shr (bits - 5)) and 0x1f
                sb.append(B32[idx])
                bits -= 5
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (bits > 0) sb.append(B32[(buffer shl (5 - bits)) and 0x1f])
        while (sb.length % 8 != 0) sb.append('=')
        return sb.toString()
    }

    fun base32Decode(input: String): ByteArray? {
        val s = input.trim().uppercase().replace("=", "").replace(" ", "")
        if (s.any { B32.indexOf(it) < 0 }) return null
        var buffer = 0
        var bits = 0
        val out = java.io.ByteArrayOutputStream()
        for (ch in s) {
            buffer = (buffer shl 5) or B32.indexOf(ch)
            bits += 5
            if (bits >= 8) {
                out.write((buffer shr (bits - 8)) and 0xff)
                bits -= 8
                buffer = buffer and ((1 shl bits) - 1)
            }
        }
        return out.toByteArray()
    }
}
