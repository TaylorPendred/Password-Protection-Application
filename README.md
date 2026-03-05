<div align="center">

# 🚔 PASSWORD POLICE

### *Your passwords have the right to remain encrypted.*


**[⬇️ Download Latest Release](../../releases/latest)**

</div>

---

<div align="center">

## 🏆 Your Vault. Your Machine. Your Rules.

*No cloud. No subscriptions. No accounts. No excuses.*

</div>

---

## ⚡ What is Password Police?

Password Police is a **fully local** desktop password manager. Every password you store is encrypted directly on your computer using **AES-256-GCM** — the same standard used by governments and banks. Nothing ever touches the internet. No one can access your data but you.

---

## 🎮 Features

| 🔐 | **AES-256-GCM Encryption** | Military-grade. Every entry encrypted on save. |
|---|---|---|
| 📋 | **One-Click Copy** | Username or password to clipboard instantly. |
| 🚀 | **One-Click Login** | Opens the site and copies your password simultaneously. |
| ⏱️ | **Auto-Lock** | Vault locks after 60 seconds of inactivity. |
| 🛡️ | **Brute-Force Protection** | 5 wrong attempts = 24-hour lockout. No exceptions. |
| 📧 | **Email Recovery** | Optional recovery code if you forget your master password. |
| 🔍 | **Instant Search** | Filter across titles, URLs and notes in real time. |
| ♾️ | **Unlimited Entries** | No caps. No tiers. No paywalls. |

---

## 🚨 Brute-Force Mode

> Try to crack the vault and you'll meet our security consultant.

5 failed attempts triggers a **24-hour lockout** — complete with a live countdown and a very unhappy Tung Tung Tung Sahur staring you down.

Good luck.

---

## 📥 Installation

```
1. Download Password Police Setup.exe from the link above
2. Double-click the installer
3. Open Password Police from your Start Menu
```

No accounts. No internet. No setup headaches.

> **macOS / Linux?** Grab the `.dmg` or `.AppImage` from the releases page.

---

## 🔑 First Time Setup

When you launch for the first time, you'll create your **master password** — the single key to your entire vault.

```
✅ Choose something strong
✅ Store it somewhere safe  
✅ Optionally add a recovery email address
```

> ⚠️ There is no "forgot password" backdoor. That's the point. The recovery email option exists for this exact reason — set it up during onboarding.

---

## 🔒 Security Model

```
Your passwords  →  AES-256-GCM encryption  →  Stored locally on your machine
                                                         ↑
                                              That's where it ends.
                                          No servers. No sync. No cloud.
```

- Master password is **never stored in plaintext** — only a derived verification hash
- Fresh random salt and IV generated on every save
- PBKDF2 key derivation at 100,000 iterations
- Vault decrypted in memory only — cleared on lock or timeout
- contextIsolation enforced — renderer cannot access system APIs

---

## 🗺️ Roadmap

- [x] AES-256-GCM encrypted vault
- [x] Brute-force lockout with visual deterrent
- [x] Email-based master password recovery
- [x] One-click login and clipboard copy
- [x] Auto-lock with inactivity timer
- [ ] Built-in password generator
- [ ] Clipboard auto-clear (30s)
- [ ] Password audit and breach detection
- [ ] Encrypted vault backup and export
- [ ] Biometric unlock (Touch ID / Windows Hello)
- [ ] System tray mode

---

## 🛠️ Built With

![Electron](https://img.shields.io/badge/Electron-29-47848F?style=flat-square&logo=electron)
![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-F7DF1E?style=flat-square&logo=javascript)
![Web Crypto API](https://img.shields.io/badge/Web%20Crypto%20API-AES--256-green?style=flat-square)
![electron-store](https://img.shields.io/badge/electron--store-8-blue?style=flat-square)

---

<div align="center">

*Built local. Stays local. Always.*

**🚔 Password Police — protecting your credentials since 2026**

</div>
