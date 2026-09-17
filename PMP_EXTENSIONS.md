# PmVault extensions for KeePassDX

This is a fork of **KeePassDX 4.5.4** adding the same three PmVault features as
the KeePassXC fork, licensed under the same **GPL-3.0-or-later**. All PmVault
code is in the new package
[`app/src/main/java/com/kunzisoft/keepass/pmp/`](app/src/main/java/com/kunzisoft/keepass/pmp)
and uses only the Android JCA + BouncyCastle (already used by the project).
Biometric unlock (BiometricPrompt) and Android Autofill are inherited unchanged
from KeePassDX; Android has no desktop-style Auto-Type and uses copy only.

## Files

| File | Role |
| --- | --- |
| `pmp/PmpCrypto.kt` | AES-256-GCM, HMAC-SHA256/1, HKDF, Base32/hex/Base64 (JCA). |
| `pmp/PmVault.kt` | Facade, per-device 0600 key, on-disk layout, database id. |
| `pmp/PmpAuditLog.kt` | Encrypted hash-chain audit log, **same on-disk format as the desktop client**. |
| `pmp/PmpSecondFactor.kt` | RFC 6238 TOTP gate: seed vault, replay/back-off/lock-out policy. |
| `pmp/PmpSecondFactorGate.kt` | Unlock dialog shown after the master credential succeeds. |
| `pmp/PmpSyncCore.kt` | Vector clocks, snapshots, tombstones, deterministic merge (port of `PmpSyncTypes.h`). |
| `pmp/PmpIdentity.kt` | ECDSA P-256 self-signed identity, fingerprint pinning, TLS 1.3 `SSLContext`. |
| `pmp/PmpSyncRunner.kt` | Mutual-TLS-1.3 LAN sync protocol (`HELLO…BYE`). |
| `pmp/PmpInMemoryStore.kt` | Data-level `PmpSyncStore` + peer trust; used by the loop-back self-test. |
| `pmp/PmpPanelActivity.kt` | “PmVault tools” screen: enrol/remove 2FA, verify/browse audit, sync self-test. |

## What is wired end-to-end

* **Second-factor unlock** — `MainCredentialActivity` `OpenGroup` branch calls
  the gate for enrolled databases (keyed by the database file URI); success
  proceeds to `GroupActivity`, failure stays on the credential screen and is
  audited.
* **Copy audit** — the single low-level `Context.copyToClipboard(...)` in
  `timeout/ClipboardHelper.kt` records an `EvCopy` event with the field *type*
  only (never the value).
* **Encrypted audit log** — identical record/chain/anchor format and event
  enumeration as the desktop client, stored in app-private `files/pmp/audit`,
  never synced.
* **Enrolment / audit tools** — the separate “PmVault tools” launcher icon
  (`PmpPanelActivity`, registered in `AndroidManifest.xml`) enrols or removes
  the second factor for a database and verifies/browses its audit chain.

## LAN sync status

The cryptographic and protocol core is complete and platform-independent:
mutual TLS 1.3 with client certificates, SHA-256 fingerprint pinning, the
`HELLO → MANIFEST → WANT → ENTRIES → APPLIED → BYE` exchange, vector-clock
merge and tombstones. The panel’s **loop-back self-test** exercises the full
certificate/TLS/protocol/merge path on-device (two peers over 127.0.0.1).

To keep the network core deterministic (and independently testable) it talks to
a small `PmpSyncStore` interface with plain `PmpEntryData` DTOs rather than
KeePassDX node classes. Persisting a merge into a live KeePassDX database is a
thin bridge that maps `EntryKDBX ⇄ PmpEntryData` (uuid, standard/custom string
attributes, and the `PM:VClock` / `PM:LastSyncHash` entry CustomData, with
tombstones in database CustomData `PM:Tombstones`), then calls the existing
save task. That bridge is the one integration point to finish against the
KeePassDX database layer; the merge result itself is already computed by
`PmpSyncCore` / `PmpSyncRunner`.

TLS 1.3 is available on **Android 10+** (Conscrypt); older versions cannot
negotiate 1.3 and the connection is refused by design. Defaults match the
desktop client (off, port 19532, 30 s listen, KeepBoth).

## Building

Use `.github/workflows/pmp-android.yml` (push a `v*` tag or run manually); it
runs `./gradlew :app:assembleLibreDebug` and uploads
`PmVault-android-debug.apk`. The open `libre` flavor is built to avoid
proprietary dependencies.

The cloud environment used to develop this fork has no Android SDK, so the
Android code is compiled for the first time by that CI workflow; the desktop
fork was fully compiled, linked and smoke-tested on Linux.
