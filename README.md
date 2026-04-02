# WireSeal

WireGuard server automation with zero plaintext secrets on disk. Manages key generation,
client lifecycle, firewall rules, and optional dynamic DNS — all protected by a dual-layer
AES-256-GCM / ChaCha20-Poly1305 encrypted vault. If the vault file is stolen without the
passphrase, no cryptographic material is exposed.

[![CI](https://github.com/prashanth-7861/WireSeal/actions/workflows/build.yml/badge.svg)](https://github.com/prashanth-7861/WireSeal/actions/workflows/build.yml)
[![Python](https://img.shields.io/badge/python-3.12%20%E2%80%93%203.14-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [One-liner install (recommended)](#one-liner-install-recommended)
  - [Pre-built binaries](#pre-built-binaries)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Windows](#windows)
  - [From Source](#from-source)
- [Quick Start](#quick-start)
- [Adding Clients](#adding-clients)
- [File Access over VPN (SFTP)](#file-access-over-vpn-sftp)
- [Commands Reference](#commands-reference)
- [Web Dashboard (GUI)](#web-dashboard-gui)
- [Server Hardening (Linux)](#server-hardening-linux)
- [Security Model](#security-model)
- [Threat Model](#threat-model)
- [Security Limitations](#security-limitations)
- [Verifying a Release](#verifying-a-release)
- [Contributing](#contributing)
- [Author](#author)

---

## Features

### Vault & Encryption
- **Zero plaintext secrets on disk** — all WireGuard private keys and PSKs live only inside
  the encrypted vault; config files never contain raw key material
- **Dual-layer AEAD vault** (FORMAT_VERSION 2):
  - Argon2id KDF: `time_cost=10`, `memory_cost=256 MiB`, `parallelism=4`
  - HKDF-SHA512 key separation — two independent 256-bit subkeys
  - **Layer 1 (inner): ChaCha20-Poly1305** — stream cipher, quantum-resistant family
  - **Layer 2 (outer): AES-256-GCM-SIV** — nonce-misuse resistant
  - Both layers authenticated with the full 76-byte header as AAD
- **Per-peer pre-shared keys** (os.urandom(32)) for additional post-quantum resistance
- **Atomic writes** — every vault and config update uses `os.replace()`, never partially written

### Network & Automation
- **Firewall automation** — nftables + NAT masquerade (Linux), pf anchor (macOS),
  netsh advfirewall (Windows); IP forwarding enabled automatically
- **Auto-detect optimal MTU** — reads outbound interface MTU, subtracts WireGuard overhead
- **Automated network setup** — IP forwarding, firewalld port opening, and OpenSSH server
  configured automatically during `wireseal init`
- **Optional DuckDNS** dynamic DNS with 2-of-3 IP consensus

### Production Hardening
- **API rate limiting** — sliding-window throttle on unlock endpoints (5 attempts per
  5-minute window); returns 429 when exceeded
- **PIN quick unlock** — set a short PIN after the initial passphrase unlock; vault
  reopens instantly without retyping the full passphrase. Auto-wiped after 5 wrong attempts
- **Session timeout** — auto-locks the vault after 15 minutes of inactivity
- **Graceful shutdown** — SIGTERM/SIGHUP + atexit wipe the passphrase from memory on exit
- **Health endpoint** — `GET /api/health` (no auth) for Docker HEALTHCHECK and monitoring
- **Audit log rotation** — thread-safe rotation at 10 MiB with up to 5 archived files
- **Vault backup & restore** — `wireseal backup-vault` / `restore-vault` with passphrase
  verification and atomic writes
- **Key rotation API** — rotate client keypair+PSK or the server keypair via API or CLI;
  validates, writes atomically, and hot-reloads WireGuard

### Dashboard & Monitoring
- **Web dashboard (GUI)** — native desktop window (pywebview) or browser-based
- **Real-time status** — API server and WireGuard tunnel indicators in the sidebar
- **Client management** — add, remove, rotate keys, view QR codes, download `.conf` files
- **Live peers table** with connection status, handshake times, and transfer stats
- **PIN management** — set, remove, and use PIN from the lock screen and sidebar
- **Enhanced audit log** — Events, Sessions, and File Activity (SFTP) tabs
- **System tray icon** — Open Dashboard, Stop Server, peer count, and Quit

### General
- **QR code output** — terminal QR codes (auto-clears after 60 s) or PNG download
- **Cross-platform** — Linux x86_64/ARM64, macOS arm64, Windows x86_64
- **Raspberry Pi support** — tested on Pi 5 with KDE Plasma/Wayland; GUI runs as regular
  user, only WireGuard commands elevated via sudoers rule
- **Headless mode** — auto-detects missing display, binds to `0.0.0.0` for LAN access
- **Supply chain security** — all dependencies pinned with SHA-256 hashes; `pip-audit`
  runs on every CI push

---

## Installation

### One-liner install (recommended)

**Linux** (Arch / Manjaro / Debian / Ubuntu / Fedora / RHEL):

```bash
curl -LO https://github.com/prashanth-7861/WireSeal/releases/latest/download/wireseal-linux.sh
chmod +x wireseal-linux.sh
sudo ./wireseal-linux.sh
```

**macOS** (requires [Homebrew](https://brew.sh)):

```bash
curl -LO https://github.com/prashanth-7861/WireSeal/releases/latest/download/wireseal-macos.sh
chmod +x wireseal-macos.sh
./wireseal-macos.sh
```

**Windows** (run in Administrator PowerShell):

```powershell
Invoke-WebRequest -Uri https://github.com/prashanth-7861/WireSeal/releases/latest/download/wireseal-windows.ps1 -OutFile wireseal-windows.ps1
.\wireseal-windows.ps1
```

Each script installs WireGuard, Python, all dependencies, configures the firewall,
enables IP forwarding, and creates `wireseal` + `wireseal-gui` system commands.

---

### Pre-built binaries

Download standalone binaries from the
[Releases page](https://github.com/prashanth-7861/WireSeal/releases/latest) — no Python required.

| Platform | Binary | Usage |
|---|---|---|
| **Linux x86_64** | `WireSeal` (GUI) / `wireseal-cli` (CLI) | `chmod +x WireSeal && sudo ./WireSeal` |
| **Windows x86_64** | `WireSeal.exe` (GUI) / `wireseal-cli.exe` (CLI) | Run as Administrator |

Every release asset is accompanied by a `sha256sums.txt` checksum file.

---

### Linux

**GUI dependencies** (required for the native desktop window):

```bash
# Arch / Manjaro
sudo pacman -S gobject-introspection webkit2gtk

# Debian / Ubuntu
sudo apt install libgirepository-1.0-1 libwebkit2gtk-4.1-0 gir1.2-webkit2-4.1 gir1.2-gtk-3.0

# Fedora / RHEL
sudo dnf install gobject-introspection webkit2gtk4.1
```

Without these, WireSeal falls back to opening the dashboard in your system browser.

**From source:**

```bash
git clone https://github.com/prashanth-7861/WireSeal.git
cd WireSeal
sudo bash scripts/install-linux.sh
```

---

### macOS

Requires [Homebrew](https://brew.sh) and macOS 12+:

```bash
git clone https://github.com/prashanth-7861/WireSeal.git
cd WireSeal
bash scripts/install-macos.sh
```

---

### Windows

From an **Administrator** PowerShell prompt:

```powershell
git clone https://github.com/prashanth-7861/WireSeal.git
cd WireSeal
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\install-windows.ps1
```

Open a **new** Administrator terminal after install for PATH changes to take effect.

---

### From Source

Any platform with Python 3.12–3.14 and WireGuard installed:

```bash
git clone https://github.com/prashanth-7861/WireSeal.git
cd WireSeal
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -r requirements-dev.txt
pip install -e .
pytest -m "not integration" -q
wireseal --help
```

---

## Quick Start

```bash
# Initialize the server (creates ~/.wireseal/vault.enc, generates keys, writes wg0.conf)
sudo wireseal init --subnet 10.0.0.1/24 --port 51820

# Add a client
sudo wireseal add-client alice

# Show QR code for the client to scan
sudo wireseal show-qr alice

# Check connected peers and transfer stats
sudo wireseal status

# Remove a client (revokes keys, reloads WireGuard immediately)
sudo wireseal remove-client alice
```

You will be prompted for a vault passphrase on first `init`. The passphrase never appears
on the command line or in any log.

---

## Adding Clients

```bash
# Add clients (name after the device)
sudo wireseal add-client alice-phone
sudo wireseal add-client bob-laptop

# QR code — best for mobile (auto-clears after 60 s)
sudo wireseal show-qr alice-phone

# Export .conf file — best for desktops
sudo wireseal export bob-laptop --output /tmp/bob-laptop.conf
```

### Import by platform

| Platform | App | How to import |
|---|---|---|
| **iPhone / iPad** | [WireGuard for iOS](https://apps.apple.com/app/wireguard/id1441195209) | **+** → **Create from QR code** |
| **Android** | [WireGuard for Android](https://play.google.com/store/apps/details?id=com.wireguard.android) | **+** → **Scan from QR code** or import `.conf` |
| **Windows** | [WireGuard for Windows](https://www.wireguard.com/install/) | **Add Tunnel** → **Import tunnel(s) from file** |
| **macOS** | [WireGuard on Mac App Store](https://apps.apple.com/app/wireguard/id1451685025) | **Import Tunnel(s) from File** |
| **Linux** | `wireguard-tools` | `sudo cp client.conf /etc/wireguard/wg0.conf && sudo wg-quick up wg0` |

### Tips

- **One client per device** — separate clients for proper key isolation
- **Delete exported files** after importing: `rm /tmp/client.conf`
- **Revoke lost devices**: `sudo wireseal remove-client device-name`

---

## File Access over VPN (SFTP)

WireSeal auto-installs OpenSSH during `wireseal init`. Once connected to the VPN, use any
SFTP client to access the server:

- **Host:** `10.0.0.1` (server VPN IP) · **Port:** `22`
- Apps: Documents by Readdle (iOS), Termius, FileZilla, or `sftp user@10.0.0.1`

File operations are logged and visible in the dashboard's **Audit Log → File Activity** tab.

---

## Commands Reference

| Command | Description |
|---|---|
| `init` | Initialize vault, generate server keypair, write server config, start WireGuard, configure firewall/SSH/hardening |
| `serve` | Launch the web dashboard (native window or browser on port 8080) |
| `status` | Show connected peers, transfer stats, and interface state |
| `verify` | Check SHA-256 of deployed config files against vault (tamper detection) |
| `lock` | Wipe in-memory vault state and end the session |
| `change-passphrase` | Re-encrypt the vault under a new passphrase |
| `terminate` | Bring down the WireGuard interface and disconnect all peers |
| `fresh-start` | **Destructive.** Wipe all data (vault, keys, configs) and optionally re-init |
| `update-endpoint` | Auto-detect or manually set the server's public IP/endpoint |
| `add-client` | Generate client keypair + PSK, assign IP from pool, write peer config |
| `remove-client` | Revoke client keys, remove peer, reload WireGuard live |
| `list-clients` | Print all client names and their assigned IPs |
| `show-qr` | Render client config as a terminal QR code (auto-clears after 60 s) |
| `export` | Export client config to a file (0600 permissions) |
| `rotate-keys` | Rotate keypair + PSK for a specific client |
| `rotate-server-keys` | Rotate the server keypair and update all client configs |
| `backup-vault` | Back up the encrypted vault to a destination path |
| `restore-vault` | Restore the vault from a backup file (with passphrase verification) |
| `update-dns` | Push the current public IP to DuckDNS (2-of-3 resolver consensus) |
| `audit-log` | Display recent audit log entries (no passphrase required) |

> **Forgot your passphrase?** There is no recovery. Run `sudo wireseal fresh-start` to wipe everything and re-initialise.

---

## Web Dashboard (GUI)

```bash
wireseal serve          # opens native window on port 8080
sudo -E wireseal-gui    # Raspberry Pi / KDE Plasma / Wayland
```

| Platform | GUI Backend | Size |
|----------|------------|------|
| **Windows** | pywebview + Edge WebView2 | ~24 MB |
| **Linux** | pywebview + WebKitGTK | ~18 MB |
| **macOS** | pywebview + WKWebView | ~15 MB |

The WireGuard tunnel runs as a **background system service** — closing the dashboard does
not disconnect clients.

---

## Server Hardening (Linux)

Runs automatically during `wireseal init` and can be retriggered from the **Security** page.

| Layer | Protection |
|---|---|
| **SSH** | Root login disabled, max 3 auth attempts, 30 s grace time, empty passwords blocked |
| **Kernel** | rp_filter, syncookies, ICMP redirect rejection, core dumps disabled |
| **Fail2ban** | 5 failed SSH attempts → 1-hour IP ban |
| **Auto-updates** | unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora/RHEL) |
| **Firewall** | nftables deny-by-default with rate limiting |

The **Security** page shows a real-time security score, per-check pass/fail with fix
suggestions, and a live open ports audit.

> Server hardening is Linux-only. The Security page on Windows/macOS shows a notice.

---

## Security Model

**Vault encryption (dual-layer AEAD):**
- Argon2id KDF → HKDF-SHA512 key separation into two independent 256-bit subkeys
- Layer 1: ChaCha20-Poly1305 (quantum-resistant family)
- Layer 2: AES-256-GCM-SIV (nonce-misuse resistant)
- Full 76-byte header used as AAD on both layers — any tampering invalidates both tags

**Key handling:**
- Keys held in `bytearray`, zero-wiped immediately after use
- `SecretBytes` blocks `pickle`, `repr`, `str`, `__hash__`, `__eq__`
- `mlock` + `MADV_DONTDUMP` on secret buffers (best-effort)

**Process hardening:**
- `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` (Linux), `PT_DENY_ATTACH` (macOS)

**API security:**
- Unlock endpoints rate-limited: 5 failures per 5-minute sliding window
- PIN: PBKDF2-HMAC-SHA256 (600k iterations) + AES-GCM; auto-wiped after 5 wrong attempts
- 15-minute inactivity auto-lock
- SIGTERM/SIGHUP/atexit wipe passphrase from memory

**Audit log:**
- Append-only NDJSON, mode 640; no key material ever logged
- Thread-safe rotation at 10 MiB, up to 5 archived files

**Supply chain:**
- All dependencies pinned with SHA-256 hashes; `pip-audit` on every CI push

---

## Threat Model

| Threat | Protected? |
|---|---|
| Vault file at rest (no passphrase) | **Yes** — dual-layer AEAD |
| WireGuard private keys | **Yes** — vault only, never on disk in plaintext |
| Pre-shared keys | **Yes** — vault only |
| DuckDNS token | **Yes** — vault only |
| Core dump extraction | **Yes** — RLIMIT_CORE=0, MADV_DONTDUMP, PR_SET_DUMPABLE=0 |
| Debugger attachment | **Yes** — PR_SET_DUMPABLE=0 (Linux), PT_DENY_ATTACH (macOS) |
| Memory forensics after exit | **Partial** — zero-random-zero wipe + mlock; CPython may retain headers briefly |
| Root access | **No** — root bypasses all userspace protections |

---

## Security Limitations

**Windows AV false positive:** PyInstaller's self-extracting format may trigger Windows
Defender heuristics. Verify the SHA-256 checksum before use. Build from source if AV
scanning is a hard requirement.

**mlock best-effort:** May fail without `CAP_IPC_LOCK`; key material could appear in swap.

**Python memory management:** CPython may retain object headers briefly after `SecretBytes.wipe()`.

---

## Verifying a Release

```bash
curl -LO https://github.com/prashanth-7861/WireSeal/releases/latest/download/WireSeal-linux-x86_64
curl -LO https://github.com/prashanth-7861/WireSeal/releases/latest/download/sha256sums.txt
sha256sum -c sha256sums.txt --ignore-missing
chmod +x WireSeal-linux-x86_64
sudo mv WireSeal-linux-x86_64 /usr/local/bin/wireseal
```

---

## Contributing

Submit pull requests against `main`. All commits must pass:

```bash
pytest -m "not integration" -q
```

**Security issues:** Do not open a public issue. Send a private report with reproduction
steps and affected version. Public disclosure is coordinated after a fix is available.

---

## Author

**Prashanth Mudigonda**

- GitHub: [prashanth-7861](https://github.com/prashanth-7861)
- Portfolio: [prashanth-mudigonda.vercel.app](https://prashanth-mudigonda.vercel.app/)

---

*Licensed under [MIT](LICENSE)*
