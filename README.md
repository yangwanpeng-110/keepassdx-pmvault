# PmVault（Android 端）

> PmVault 是在开源 Android 密码管理器 **KeePassDX** 基础上自研扩展的跨平台密码管理器移动端。
> 本仓库为 KeePassDX 的下游 fork（GPL-3.0-or-later），**不直接复用任何第三方专有源代码**，
> 在保留 KeePassDX 标准 KDBX4 / Autofill / 魔术键盘能力的同时，新增第二因素、生物识别解锁、
> 局域网端到端同步、加密审计日志与“密码变更主动更新”等能力。上游版权与许可证声明见文末。

## 与 KeePassDX 的关系

- 数据库格式：标准 **KDBX4**（兼容 .kdb/.kdbx 1–4，AES/Twofish/ChaCha20/Argon2），与 KeePassXC / KeePass / KeeWeb 互通。
- 所有 PmVault **自定义配置保存在 KDBX 的 CustomData 扩展字段**中，随数据库加密、备份，**不上云**。
- 自有功能集中在 `app/.../pmp/` 等 `Pmp` 前缀模块；上游可持续合并升级。

## PmVault 新增 / 调整能力

- **解锁方式**
  - 建库引导会依次询问：设置**主密码（必填，不可为空）**、可选**密钥文件（辅助）**、是否开启 **TOTP 第二因素**、是否开启**生物识别（指纹/人脸 BiometricPrompt）解锁**。
  - 生物识别解锁可免输主密码快速解锁；**已移除“设备凭据解锁”和实体硬件密钥（YubiKey）入口**，仅保留生物识别。
- **标准 Android Autofill**
  - 启用系统自动填充服务后，登录页在键盘上方提示匹配条目；支持通行密钥（Passkeys）与魔术键盘。
  - **类 Edge 密码更新提示**：在注册/改密页提交时，若同一网址下已存在“相同用户名、不同密码”的条目，
    会主动询问**更新该条目密码 / 另存为新条目 / 取消**；更新会直接打开该条目确认页，避免产生重复条目。
  - 表单填充相关设置项的 ⓘ 说明改为**应用内解释弹窗**（含子域匹配、魔术键盘、剪贴板、自动填充、通行密钥），不再跳转外部网页。
- **局域网双向同步（mTLS 1.3）**：与 PmVault 桌面端在同一 Wi‑Fi 下双向合并；仅信任证书 SHA-256 指纹、
  强制 TLS 1.3 与双向证书、仅允许局域网地址；向量时钟合并、冲突保留副本、删除经墓碑传播；
  **同步完成后发系统通知**（含更新/删除/冲突副本计数）。
  - **内置条目模板仅保留在本机、不参与同步**（模板在数据库中默认可见可用）。
- **本地加密审计日志**：记录解锁、第二因素、复制、填充、同步等事件与计数，**绝不记录明文密码、TOTP 等敏感信息**。
- **其它**：数据库默认存放在系统规定的第三方应用数据目录，支持新建/打开/删除数据库（删除会同步删除源文件）；
  移除回收站（删除即永久删除）；返回即锁定等行为按 PmVault 策略固定。

## 构建

- 推荐使用 GitHub Actions 工作流 `.github/workflows/pmp-android.yml`（Ubuntu + JDK17，
  执行 `:app:assembleLibreDebug`）产出可直接安装的 debug APK。
- 本地构建沿用 KeePassDX 的 Gradle/Android SDK 要求。

## 配套桌面端

PmVault 桌面端（基于 KeePassXC 的姊妹 fork）提供浏览器扩展（Edge/Chrome）自动填充与密码更新、
桌面 Auto‑Type、以及与本端一致的局域网 mTLS 同步。

---

# Android KeePassDX（上游项目）

<img alt="KeePassDX Icon" src="https://raw.githubusercontent.com/Kunzisoft/KeePassDX/master/art/icon.png"> **Lightweight password safe and manager for Android**, KeePassDX allows editing encrypted data in a single file in KeePass format and fill in the forms in a secure way.

<img alt="KeePassDX Screenshot" src="https://raw.githubusercontent.com/Kunzisoft/KeePassDX/master/art/screen.jpg" width="220">

### Features

 - **Passkeys** for authentication and **local storage of private keys**.
 - **Biometric recognition** for fast unlocking (fingerprint / face unlock / …).
 - **One-Time Password** management (HOTP / TOTP) for two-factor authentication (2FA).
 - **Autofill** for easy form filling with passwords.
 - **Magikeyboard** to efficiently fill in any field.
 - Create **encrypted database files**.
 - Organisation of credentials by **entry** and in **group** trees.
 - Allows opening and **copying URI / URL fields quickly**.
 - Dynamic **templates**  for each type of entry.
 - **History** of each entry.
 - Precise management of **settings**.
 - Material design with **themes**.
 - Support for **.kdb** and **.kdbx** files (version 1 to 4) with AES - Twofish - ChaCha20 - Argon2 algorithm.
 - **Compatible** with the majority of alternative programs (KeePass, KeePassXC, KeeWeb, …).
 - Code written in **native languages** (Kotlin / Java / JNI / C).

KeePassDX is **open source** and **ad-free**.

## What is KeePassDX?

An alternative to remembering an endless list of passwords manually. This is made more difficult by **using different passwords for each account**. If you use one password everywhere and security fails only one of those places, it grants access to your e-mail account, website, etc, and you may not know about it or notice, before bad things happen.

KeePassDX is a **local password and passkey manager for Android**, which helps you **manage your passwords in a secure way**. You can put all your passwords in one database, locked with a **master key** and/or a **keyfile**. You **only have to remember one single master password and/or select the keyfile** to unlock the whole database. The databases are encrypted using the best and **most secure encryption algorithms** currently known.

## Small print?

KeePassDX is under **open source GPL3 license**, meaning you can use, study, change and share it at will. Copyleft ensures it stays that way.
From the full source, anyone can build, fork, and check whether for example the encryption algorithms are implemented correctly.
There is **no advertising**.

Do not worry, **the main features remain completely free**, no security features are reserved for a specific version; encryption and data protection are strictly the same for all users.

KeePassDX is developed and maintained on a volunteer basis, so if you find the application useful and would like to support its development, there are several options available.

## Contribution

* Add features by making a **[pull request](https://help.github.com/articles/about-pull-requests/)**.
* Help to **[translate](https://hosted.weblate.org/projects/keepass-dx/strings/)** KeePassDX to your language on [Weblate](https://hosted.weblate.org/projects/keepass-dx/).
* **[Donate](https://www.keepassdx.com/#donation)** to encourage and finance design, deployment, ticket tracking, bug fixing, addition of new features, development and maintenance. You will then have access to a support version, KeePassDX Pro. (づ•ᴗ•)づ♡

*Note : The support version provides access to optional visual styles that are accessible after a contribution (and a thank-you message ≽^•⩊•^≼) to encourage the work of this open source project!
It does not improve safety and provides no functional advantage.
If you contribute and do not have access to the styles, do not hesitate to contact the author at [contact@keepassdx.com](contact@keepassdx.com).*

## Download

*[F-Droid](https://f-droid.org/packages/com.kunzisoft.keepass.libre/) is the recommended way of installing, a libre software project that verifies all the libraries and app code is libre software.*

| Source | Status | [Version](https://github.com/Kunzisoft/KeePassDX/wiki/FAQ#why-a-libre-and-free-version) |
|--------|--------|---------|
| [Google Play](https://play.google.com/store/apps/details?id=com.kunzisoft.keepass.free) | ![Google Play Release](https://img.shields.io/endpoint?color=blue&logo=google-play&logoColor=green&url=https%3A%2F%2Fplay.cuzi.workers.dev%2Fplay%3Fi%3Dcom.kunzisoft.keepass.free%26gl%3DUS%26hl%3Den%26l%3DGoogle%2520Play%26m%3D%24version) | Free + [Pro](https://play.google.com/store/apps/details?id=com.kunzisoft.keepass.pro) |
| [F-Droid](https://f-droid.org/en/packages/com.kunzisoft.keepass.libre/) | ![F-Droid Version](https://img.shields.io/f-droid/v/com.kunzisoft.keepass.libre?logo=F-Droid&label=F-Droid) | Libre |
| [IzzyOnDroid](https://apt.izzysoft.de/fdroid/index/apk/com.kunzisoft.keepass.free) | ![IzzyOnDroid Version](https://img.shields.io/endpoint?&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAMAAABg3Am1AAADAFBMVEUA0////wAA0v8A0v8A0////wD//wAFz/QA0/8A0/8A0/8A0/8A0v///wAA0/8A0/8A0/8A0/8A0//8/gEA0/8A0/8B0/4A0/8A0/8A0/+j5QGAwwIA0//C9yEA0/8A0/8A0/8A0/8A0/8A0/+n4SAA0/8A0/8A0/+o6gCw3lKt7QCv5SC+422b3wC19AC36zAA0/+d1yMA0/8A0/+W2gEA0/+w8ACz8gCKzgG7+QC+9CFLfwkA0/8A0////wAA0/8A0/8A0/8A0/+f2xym3iuHxCGq5BoA1P+m2joI0vONyiCz3mLO7oYA0/8M1Piq3Ei78CbB8EPe8LLj9Ly751G77zWQ1AC96UYC0fi37CL//wAA0/8A0////wD//wCp3jcA0/+j3SGj2i/I72Sx4zHE8FLB8zak1kYeycDI6nRl3qEA0/7V7psA0v6WzTa95mGi2RvB5XkPy9zH5YJ3uwGV1yxVihRLiwdxtQ1ZkAf//wD//wD//wD//wD//wCn5gf//wD//wD//wD//wD//wAA0/+h4A3R6p8A0/+X1w565OD6/ARg237n9csz2vPz+gNt37V/vifO8HW68B/L6ZOCwxXY8KRQsWRzhExAtG/E612a1Rd/pTBpmR9qjysduKVhmxF9mTY51aUozK+CsDSA52T//wD//wAA0////wD//wBJ1JRRxFWjzlxDyXRc0pGT1wCG0CWB3VGUzSTh8h6c0TSr5CCJ5FFxvl6s4H3m8xML0/DA5CvK51EX1N+Y2gSt4Dag3ChE3fax2ki68yO57NF10FRZnUPl88eJxhuCxgCz5EOLwEGf1DFutmahzGW98x0W1PGk3R154MHE6bOn69qv3gy92oG90o+Hn07B7rhCmiyMwECv1nO+0pQfwrCo57xF2daXsVhKrEdenQAduaee1Bsjr42z5D9RoCXy+QNovXpy2Z5MtWDO/TiSukaF3UtE1K6j3B4YwLc5wXlzpyIK0u5zy3uJqg4pu5RTpkZmpVKyAP8A0wBHcExHcEyBUSeEAAABAHRSTlP///9F9wjAAxD7FCEGzBjd08QyEL39abMd6///8P/ZWAnipIv/cC6B//7////////L/1Dz/0D///////86/vYnquY3/v///5T//v///17///////////////84S3QNB/8L/////////////7r/////NP////9l/////wPD4yis/x7Ym2lWSP+em////0n////////v///////////////////7//7pdGN3Urr6/+v/6aT////+//H/o2P/1v+7r7jp4PM/3p4g////g///K///481LxO///v////9w////8v/////9/p3J///a+P9v/5KR/+n///+p/xf//8P//wAAe7FyaAAABCZJREFUSMdj+E8iYKBUgwIHnwQ3N7cEHxcH+///VayoAE0Dh41qR7aBnCIQ8MsJKHH9/99czYYMWlA0cIkJGjMgAKfq//9RNYzIgLcBWYOTiCgDMhDn+B9bh6LebiWyH6L5UZQzONoAHWSHoqEpDkkDsyKqelv1//9rG1HUN9YihZK9AKp6BkG+/6xNqA5ajhSsCkrIipmYGGRa//9vQXVQXSySBnkWJOUMfn5Myuz/G3hR1NdEIUUchwiy+bkTsg4dbW/fu6W/e1c3XMMy5JiOZkFxUFZo74mgKTqaKXu0+2HqVwkja3BH9kFu361JwcHTfPJD4mdfe8ULAdVRyGlJAcVFfg+CQOozZ4XrJ85+JgwBsVXIGriQw5Tp4ZScezd8JiWnBupru30qwJZa+ZAjmWlC8fUZM4qB6kPnLNSPLMWqQQ5ZQ5aOzs1HmamBaQHzFs6y+qAmJCTE8f9/QgKSBg4DJPWc6zVDQkIC09JkZSPD38kukpExFpT4z6uYI/QwCOOCCK/izvu5CWl6AcEWMnKWml7LWbKZfH9/99UkknQHhGsynDz+65eWXv3/JmJrq5eXienVlRUfH/z8VvCf45soKQIH1yDEQsszrp6gwq9C73T87xcXadKl5TkFev4A/2tygmSBqYXqAYJmK+ZuoJydDR1vP09DA0NOy2kpdML81+U/heCpH1JU3jig7lJ5nKOT4i/t6ZHkqGzs4lJmIVHfrj+JR4HqLQSD0yDkCNEpGNn5ix9D02/eJdElTZdKV2TpNOhkwt8YUlNUgimgV0dLMBvf1gz1MolPd5FRcVNSkpDQ8owJeBCDyIhrIDnOD5QcuIU+3/2QKSs9laQ+noNLS0zLWdtqyP7mBAFAw88TwsJgMuJYweBGjYngtWbmeuZOW+bvNQToUFOAlFqOBk4Ov3/L7Z60/aN0p1tUhpa5nqWlub7C3p2I9QzyAghlUvczOz/1fhzPT3XSIfpSmmYAdVbmm1gV0dSz8DSilpUQsqCddIWIA3meuZaJqdMJZEzl6gRqgZIWZAxUdoizERXN8yi5MltcZTChzMaRQM3JNUWHS8rL/+yaPGvMmvr5ywoGoxtkDWwQ+Pb89ycBeWfGSJeL/la+RS1eOPnRtbQKgMRjZg+t8x6PkP273nWQAoFOPAgaeAThKXAmXMrK39Kmr5fsuBlBqoXfJGLe3VbmHjG9Mczi9T//3h7vygXtcDlQtJg44iQiIjIBRbGPO7gghPJy0ZIxT2HOLIUgwxQzsgYrUR250HSIMaJLidhgKY+mw+pflBDrX8E7OGBjPCAPc76gQFSTqAIiYrb/8dRP4CyosJ/rmwU5XIxHMilt4QBJwsSkBMClxOQULBlkRRxEONmR2kJcDGgADX2/+xO/5iqjExqmLyrWpcPFRta1BfAwCtyN3XpuJ4RgAAAABJRU5ErkJggg==&url=https://apt.izzysoft.de/fdroid/api/v1/shield/com.kunzisoft.keepass.free&label=IzzyOnDroid) | Free & [Libre](https://apt.izzysoft.de/fdroid/index/apk/com.kunzisoft.keepass.libre) |
| [GitHub](https://github.com/Kunzisoft/KeePassDX/releases) / [Obtainium](https://github.com/ImranR98/Obtainium) | ![GitHub Release](https://img.shields.io/github/v/release/Kunzisoft/KeePassDX?include_prereleases&logo=GitHub&label=GitHub) | Free & Libre |

## Package authenticity from GitHub
- Download the app from [GitHub releases](https://github.com/Kunzisoft/KeePassDX/releases/latest)
- Install [`apksigner`](https://developer.android.com/tools/apksigner) from [Android Studio](https://developer.android.com/studio)
- Open the directory where you saved the downloaded file in the Terminal
- Make sure that you have `apksigner` installed by running:
```shell
apksigner --version
```
- Depending on the APK file you downloaded, run:

```shell
apksigner verify --verbose --print-certs -min-sdk-version 24 KeePassDX-*.apk
```

You should get this output :
```shell
Verified using v2 scheme (APK Signature Scheme v2): true
...
Number of signers: 1
Signer #1 certificate SHA-256 digest: 7d55b8af210381aabf960f07e17cf7857b6d2a642ca2da6bf0bdf1b200362f04
...
Signer #1 public key SHA-256 digest: 5d261d3176db1e077b80112824d9390167f3be0561827e42112ed6b71192db81
```
If it's the case, this means that the APK was well built by the author of KeePassDX.

## Frequently Asked Questions

Other questions? You can read the [FAQ](https://github.com/Kunzisoft/KeePassDX/wiki/FAQ)

## Other devices

- [KeePass](https://keepass.info/) (https://keepass.info/) is the original and official project for the desktop, with technical documentation for standardized database files. It is updated regularly with active maintenance (written in C#).

- [KeePassXC](https://keepassxc.org/) (https://keepassxc.org/) is an alternative integration of KeePass written in C++.

- [KeeWeb](https://keeweb.info/) (https://keeweb.info/) is a web version that is also compatible with KeePass files.

## License

  Copyright © 2026 Jeremy Jamet / [Kunzisoft](https://www.kunzisoft.com).

  This file is part of KeePassDX.

  [KeePassDX](https://www.keepassdx.com) is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  KeePassDX is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with KeePassDX.  If not, see <http://www.gnu.org/licenses/>.

  *This project is a fork of [KeePassDroid](https://github.com/bpellin/keepassdroid) by bpellin.*
