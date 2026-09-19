/*
 * PmVault extensions for KeePassDX - per-device TLS identity.
 *
 * An ECDSA P-256 self-signed certificate (CN=PmVault, digitalSignature +
 * keyAgreement, SHA-256) generated with BouncyCastle. The private key and
 * certificate are sealed with AES-GCM under a device-derived key and stored
 * OUTSIDE the database; they are never synced. The node id is the first 16 hex
 * chars of the certificate SHA-256 fingerprint, matching the desktop format.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
package com.kunzisoft.keepass.pmp

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509ExtendedTrustManager
import java.net.Socket
import java.security.cert.CertificateException
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaContentSignerBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.asn1.x500.X500Name
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

data class PmpIdentity(
    val nodeId: String,
    val certPem: String,
    val keyPem: String,
    val cert: X509Certificate,
    val key: PrivateKey
)

object PmpIdentityStore {
    private const val ID_AAD = "PmVault/sync-identity/v1"
    private const val FILE = "identity.enc"

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private fun path() = File(PmVault.dir("sync"), FILE)
    private fun key() = PmVault.deriveKey("sync-identity")

    private fun pem(type: String, der: ByteArray): String {
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP).chunked(64).joinToString("\n")
        return "-----BEGIN $type-----\n$b64\n-----END $type-----\n"
    }

    private fun fingerprint(certDer: ByteArray): String =
        PmpCrypto.toHex(MessageDigest.getInstance("SHA-256").digest(certDer))

    @Synchronized
    fun loadOrCreate(): PmpIdentity {
        val f = path()
        if (f.exists()) {
            runCatching {
                val sealed = PmpCrypto.fromB64(f.readText().trim())
                val plain = PmpCrypto.aesGcmOpen(key(), sealed, ID_AAD.toByteArray())
                if (plain != null) {
                    val o = JSONObject(String(plain, Charsets.UTF_8))
                    val certPem = o.getString("cert")
                    val keyPem = o.getString("key")
                    val cert = parseCert(certPem)
                    val priv = parseKey(keyPem)
                    val id = PmpIdentity(o.getString("node"), certPem, keyPem, cert, priv)
                    if (id.nodeId.isNotEmpty()) return id
                }
            }
        }
        val id = generate()
        val o = JSONObject().put("node", id.nodeId).put("cert", id.certPem).put("key", id.keyPem)
        val sealed = PmpCrypto.aesGcmSeal(key(), o.toString().toByteArray(), ID_AAD.toByteArray())
        f.writeText(PmpCrypto.toB64(sealed))
        return id
    }

    private fun parseCert(pemStr: String): X509Certificate {
        val der = Base64.decode(
            pemStr.lineSequence().filter { !it.startsWith("-----") }.joinToString(""),
            Base64.DEFAULT
        )
        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    private fun parseKey(pemStr: String): PrivateKey {
        val der = Base64.decode(
            pemStr.lineSequence().filter { !it.startsWith("-----") }.joinToString(""),
            Base64.DEFAULT
        )
        return KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der))
    }

    private fun generate(): PmpIdentity {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val kp = kpg.generateKeyPair()

        val now = Date()
        val notAfter = Date(now.time + 365L * 86400_000L) // 1 year, matches desktop default
        val name = X500Name("CN=PmVault")
        val serial = BigInteger(64, SecureRandom())
        val builder = JcaX509v3CertificateBuilder(name, serial, now, notAfter, name, kp.public)
        builder.addExtension(
            Extension.keyUsage, true,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyAgreement)
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(kp.private)
        val holder = builder.build(signer)
        val certDer = holder.encoded
        val certPem = pem("CERTIFICATE", certDer)
        val keyPem = pem("PRIVATE KEY", kp.private.encoded)
        val nodeId = fingerprint(certDer).take(16)
        return PmpIdentity(nodeId, certPem, keyPem, parseCert(certPem), kp.private)
    }

    fun fullFingerprint(cert: X509Certificate): String = fingerprint(cert.encoded)

    /**
     * Build a TLS 1.3 context presenting [id] and trusting a peer only when
     * [decidePeer] returns true for its certificate (fingerprint pinning; the
     * system CA store is never consulted).
     */
    fun sslContext(id: PmpIdentity, decidePeer: (X509Certificate) -> Boolean): SSLContext {
        val km = object : X509ExtendedKeyManager() {
            override fun getClientAliases(keyType: String?, issuers: Array<out java.security.Principal>?) = arrayOf("pmvault")
            override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out java.security.Principal>?, socket: Socket?) = "pmvault"
            override fun getServerAliases(keyType: String?, issuers: Array<out java.security.Principal>?) = arrayOf("pmvault")
            override fun chooseServerAlias(keyType: String?, issuers: Array<out java.security.Principal>?, socket: Socket?) = "pmvault"
            override fun getCertificateChain(alias: String?) = arrayOf(id.cert)
            override fun getPrivateKey(alias: String?) = id.key
        }
        val tm = object : X509ExtendedTrustManager() {
            private fun check(chain: Array<out X509Certificate>?) {
                val peer = chain?.firstOrNull()
                    ?: throw CertificateException("No peer certificate (mutual TLS required)")
                if (!decidePeer(peer)) {
                    throw CertificateException("Peer certificate fingerprint not trusted")
                }
            }
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = check(chain)
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = check(chain)
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = check(chain)
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = check(chain)
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = check(chain)
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = check(chain)
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        // Fall back to 1.2+ only where the platform lacks a 1.3 constant.
        val ctx = runCatching { SSLContext.getInstance("TLSv1.3") }
            .getOrDefault(SSLContext.getInstance("TLSv1.2"))
        ctx.init(arrayOf<KeyManager>(km), arrayOf<TrustManager>(tm), SecureRandom())
        return ctx
    }
}
