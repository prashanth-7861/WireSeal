# WireSeal

WireGuard server automation with zero plaintext secrets on disk. Manages key generation,
client lifecycle, firewall rules, and optional dynamic DNS — all protected by an AES-256-GCM
encrypted vault. If the vault file is stolen without the passphrase, no cryptographic material
is exposed.

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
  - [From Source (any platform)](#from-source)
- [Quick Start](#quick-start)
- [Adding Clients](#adding-clients)
- [File Access over VPN (SFTP)](#file-access-over-vpn-sftp)
- [Commands Reference](#commands-reference)
- [Web Dashboard (GUI)](#web-dashboard-gui)
- [Server Hardening (Linux)](#server-hardening-linux)
- [Security Model](#security-model)
- [Security Limitations](#security-limitations)
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
  - **Layer 2 (outer): AES-256-GCM-SIV** — nonce-misuse resistant; even a repeated nonce
    cannot reveal plaintext
  - Both layers authenticated with the full 76-byte header as AAD
- **Per-peer pre-shared keys** (os.urandom(32)) for additional post-quantum resistance
- **Atomic writes** — every vault and config update uses `os.replace()`, never partially written

### Network & Automation
- **Firewall automation** — nftables + NAT masquerade (Linux), pf anchor (macOS),
  netsh advfirewall (Windows); IP forwarding enabled automatically
- **Auto-detect optimal MTU** — reads outbound interface MTU and subtracts WireGuard
  overhead (80 bytes) for best throughput without fragmentation
- **Automated network setup** — IP forwarding, firewalld port opening, and OpenSSH server
  installation are configured automatically during `wireseal init`
- **Optional DuckDNS** dynamic DNS with 2-of-3 IP consensus

### Server Hardening (Linux)
- **One-click hardening** via the dashboard or `wireseal init`:
  - **SSH hardening** — root login disabled, max 3 auth attempts, 30s login grace time,
    empty passwords blocked, X11/agent forwarding off
  - **Kernel security** — anti-IP-spoofing (rp_filter), SYN flood protection (syncookies),
    ICMP redirect prevention, core dump disabled, kernel pointer restriction
  - **Fail2ban** — auto-installed and configured; 5 failed SSH attempts triggers a 1-hour ban
  - **Automatic security updates** — unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora/RHEL)
- **Security score dashboard** — real-time percentage of checks passing with per-check
  pass/fail and fix suggestions
- **Open ports audit** — lists all listening services with Expected/Review badges

### Dashboard & Monitoring
- **Web dashboard (GUI)** — native desktop window (pywebview) or browser-based
- **Real-time status** — API server and WireGuard tunnel indicators in the sidebar
- **Client management** — add, remove, view QR codes, download `.conf` files
- **Live peers table** with connection status, handshake times, and transfer stats
- **Enhanced audit log** with three tabs:
  - **Events** — timestamped security event history
  - **Sessions** — unlock/lock session pairs with duration and event breakdown
  - **File Activity** — SFTP operations (read, write, rename, remove, mkdir, etc.)
    tracked via verbose SSH logging
- **Stop Server** button on Dashboard to bring down the WireGuard tunnel
- **Fresh Start** option on the welcome screen to wipe and reinitialize

### File Access over VPN
- **SFTP/SSH access** — OpenSSH server auto-installed during init; VPN clients can
  access server files using any SFTP client (Documents by Readdle, Termius, etc.)
- **File activity tracking** — SFTP operations logged and displayed in the Audit Log

### General
- **QR code output** — display client configs as terminal QR codes (PNG or SVG fallback)
- **Append-only NDJSON audit log** — timestamped, no key material ever logged
- **Cross-platform** — Linux x86_64, macOS arm64, Windows x86_64
- **Supply chain security** — all dependencies pinned with SHA-256 hashes; `pip-audit`
  runs on every CI push

---

## Prerequisites — Public IP and Open Port

> **Required before adding clients from outside your home network.**

WireSeal sets up the WireGuard server on your machine, but for devices on
other networks (mobile data, other WiFi) to reach it, two things must be true:

### 1. Your machine needs a reachable public IP

```bash
# Find your current public IP
curl ifconfig.me
```

If this changes periodically (most home ISPs including AT&T), either:
- Use DuckDNS (free dynamic DNS) — pass `--duckdns-domain yourname` to `init`
- Or run `sudo wireseal update-endpoint` each time your IP changes

### 2. Port 51820 UDP must be forwarded through your router

Log into your router admin panel (usually `http://192.168.1.1` or
`http://192.168.1.254` for AT&T) and add a port forwarding rule:

| Setting | Value |
|---|---|
| Protocol | **UDP** |
| External port | **51820** |
| Internal IP | Your machine's local IP (`ip addr show \| grep "inet "`) |
| Internal port | **51820** |

> **AT&T routers:** Settings → Firewall → NAT/Gaming (or "Applications, Pinholes
> and DMZ") → Add a custom rule with the values above.

### 3. OS firewall must allow WireGuard traffic

The install scripts and `wireseal init` configure this automatically, but if you
need to do it manually:

**Linux (firewalld):**

```bash
sudo firewall-cmd --add-port=51820/udp --permanent
sudo firewall-cmd --reload
```

**Linux (nftables / iptables):**

```bash
# nftables (configured automatically by WireSeal)
sudo nft add rule inet filter input udp dport 51820 accept

# iptables (legacy)
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

**Windows (Windows Firewall):**

```powershell
# PowerShell (Administrator)
New-NetFirewallRule -Name "WireSeal-WG" -DisplayName "WireSeal WireGuard" `
    -Direction Inbound -Protocol UDP -LocalPort 51820 -Action Allow
```

Or: Windows Security → Firewall → Advanced Settings → Inbound Rules → New Rule →
Port → UDP 51820 → Allow.

**macOS (pf firewall):**

```bash
# Add to /etc/pf.conf
echo "pass in on en0 proto udp from any to any port 51820" | sudo tee -a /etc/pf.conf
sudo pfctl -f /etc/pf.conf
```

> **Note:** The one-liner install scripts and `wireseal init` handle all firewall
> rules, IP forwarding, and NAT masquerade **automatically** — no manual
> configuration needed in most cases.

---

## Installation

### One-liner install (recommended)

Copy-paste one command to download, install, and configure everything automatically.

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
See [Verifying a Release](#verifying-a-release).

---

### Linux

Supports Arch / Manjaro, Fedora / RHEL / Rocky / AlmaLinux, Debian / Ubuntu.

**Option A — one-liner** (recommended): see above.

**Option B — pre-built binary:** download from the
[Releases page](https://github.com/prashanth-7861/WireSeal/releases/latest).

**GUI dependencies (required for the native desktop window):**

```bash
# Arch / Manjaro
sudo pacman -S gobject-introspection webkit2gtk

# Debian / Ubuntu
sudo apt install libgirepository-1.0-1 libwebkit2gtk-4.1-0 gir1.2-webkit2-4.1 gir1.2-gtk-3.0

# Fedora / RHEL
sudo dnf install gobject-introspection webkit2gtk4.1
```

Without these system libraries, WireSeal falls back to opening the dashboard in your system browser.

**Option C — from cloned repo:**

```bash
git clone https://github.com/prashanth-7861/WireSeal.git
cd WireSeal
sudo bash scripts/install-linux.sh
```

The install script:
1. Installs `wireguard-tools`, `nftables`, and `openssh` via your package manager
2. Creates a Python virtual environment and installs all dependencies
3. Writes `/usr/local/bin/wireseal` and `/usr/local/bin/wireseal-gui` wrappers
4. Enables IP forwarding, opens firewalld port, starts SSH server
5. Runs the test suite to confirm the installation

---

### macOS

**Option A — one-liner** (recommended): see above.

**Option B — from cloned repo** (requires [Homebrew](https://brew.sh) and macOS 12+):

```bash
git clone https://github.com/prashanth-7861/WireSeal.git
cd WireSeal
bash scripts/install-macos.sh
```

The script:
1. Installs `wireguard-tools` and `wireguard-go` (userspace driver) via Homebrew
2. Creates `.venv` and installs all dependencies
3. Writes `/usr/local/bin/wireseal` (or `~/.local/bin/wireseal` if not writable)

> **Note:** For a GUI tunnel manager on macOS, install the
> [WireGuard app](https://apps.apple.com/app/wireguard/id1451685025) from the Mac App Store
> in addition to the CLI tools.

---

### Windows

**Option A — one-liner** (recommended): see above.

**Option B — pre-built binary:** download `WireSeal.exe` from the
[Releases page](https://github.com/prashanth-7861/WireSeal/releases/latest).
Run as Administrator.

**Option C — from cloned repo** (run from an **Administrator** PowerShell prompt):

```powershell
git clone https://github.com/prashanth-7861/WireSeal.git
cd WireSeal

Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\install-windows.ps1
```

The script:
1. Installs **WireGuard for Windows** (wintun driver) and **Git** via `winget`
2. Installs Python 3.13 via `winget` if no compatible version is found
3. Creates `.venv` and installs all dependencies
4. Writes `wireseal.cmd` and `wireseal-gui.cmd` to `C:\Program Files\WireSeal\bin`
5. Opens **UDP 51820** in Windows Firewall and enables IP forwarding
6. Adds the install directory to the system `PATH`

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
pip install -r requirements-dev.txt
pip install -e .

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pip install -e .

# Verify
pytest -m "not integration" -q
wireseal --help
```

---

## Quick Start

```bash
# 1. Initialize the server (creates ~/.wireseal/vault.enc, generates keys, writes wg0.conf)
sudo wireseal init --subnet 10.0.0.1/24 --port 51820 --interface wg0

# 2. Add a client
sudo wireseal add-client alice

# 3. Show the QR code so the client can scan it
sudo wireseal show-qr alice

# 4. Check connected peers and transfer stats
sudo wireseal status

# 5. Remove a client (revokes keys, reloads WireGuard immediately)
sudo wireseal remove-client alice
```

You will be prompted for a vault passphrase on the first `init`. All subsequent commands
that need key material will prompt for the same passphrase. The passphrase never appears
on the command line or in any log.

---

## Adding Clients

WireSeal generates standard WireGuard `.conf` files that work with any WireGuard client app.

### On the server

```bash
# Add a client (name it after the device for easy management)
sudo wireseal add-client alice-phone
sudo wireseal add-client bob-laptop
sudo wireseal add-client home-tablet

# Show QR code (best for mobile devices — auto-clears after 60s)
sudo wireseal show-qr alice-phone

# Export config file (best for desktops — transfer via USB, email, AirDrop, etc.)
sudo wireseal export bob-laptop --output /tmp/bob-laptop.conf
```

### Client setup by platform

| Platform | App | How to import |
|---|---|---|
| **iPhone / iPad** | [WireGuard for iOS](https://apps.apple.com/app/wireguard/id1441195209) | Tap **+** → **Create from QR code** → scan the terminal QR |
| **Android** | [WireGuard for Android](https://play.google.com/store/apps/details?id=com.wireguard.android) | Tap **+** → **Scan from QR code**, or import `.conf` file |
| **Windows** | [WireGuard for Windows](https://www.wireguard.com/install/) | **Add Tunnel** → **Import tunnel(s) from file** → select `.conf` |
| **macOS** | [WireGuard on Mac App Store](https://apps.apple.com/app/wireguard/id1451685025) | **Import Tunnel(s) from File** or drag `.conf` onto the app |
| **Linux** | `wireguard-tools` (CLI) | `sudo cp client.conf /etc/wireguard/wg0.conf && sudo wg-quick up wg0` |

### iPhone / iPad (detailed)

1. Install **WireGuard** from the App Store
2. Tap **+** → **Create from QR code**
3. Scan the QR code displayed in the terminal
4. Name the tunnel (e.g. "Home VPN") → **Save**
5. Toggle the tunnel on

### Android (detailed)

1. Install **WireGuard** from Google Play
2. Tap **+** → **Scan from QR code** (or **Import from file**)
3. Scan the QR code or select the `.conf` file
4. Name the tunnel → **Save**
5. Toggle on

### Windows / macOS (detailed)

1. Install the WireGuard desktop app
2. Export the config: `sudo wireseal export client-name --output /tmp/client.conf`
3. Transfer the `.conf` file to the client machine (USB, AirDrop, secure file transfer)
4. Open WireGuard → **Add Tunnel** → import the `.conf` file
5. Click **Activate**

### Linux client (detailed)

```bash
# Copy the exported config to the client machine
scp user@server:/tmp/client.conf /etc/wireguard/wg0.conf

# Start the tunnel
sudo wg-quick up wg0

# (Optional) Enable on boot
sudo systemctl enable wg-quick@wg0
```

### Verify connection

On the **server**, check that the client has connected:

```bash
sudo wireseal status
# or directly:
sudo wg show
```

A successful connection shows a recent "latest handshake" timestamp and non-zero transfer bytes.

### Tips

- **One client per device** — create a separate client for each device for proper key isolation
- **Naming convention** — use descriptive names like `alice-iphone`, `bob-laptop`, `tablet-home`
- **Delete exported files** — remove `.conf` files after importing: `rm /tmp/client.conf`
- **QR for mobile, file for desktop** — QR codes are fastest for phones; `.conf` files are easier for computers
- **Revoke lost devices** — if a device is lost: `sudo wireseal remove-client device-name`

---

## File Access over VPN (SFTP)

WireSeal automatically installs and configures OpenSSH during `wireseal init`, enabling
file access from VPN clients to the server via SFTP.

**From iPhone/iPad (Documents by Readdle):**

1. Connect to the VPN using the WireGuard app
2. Open **Documents by Readdle** → **Connect to Server**
3. Choose **SFTP** and enter:
   - Host: `10.0.0.1` (server VPN IP)
   - Port: `22`
   - Username/password: your Linux user credentials
4. Browse and manage files on the server

**From any SFTP client:** use `sftp user@10.0.0.1` or connect with Termius, FileZilla, etc.

File operations (read, write, rename, remove, mkdir, permissions changes) are logged via
verbose SFTP logging and displayed in the dashboard's **Audit Log → File Activity** tab.

---

## Commands Reference

| Command | Description |
|---|---|
| `init` | Initialize vault, generate server keypair, write server config, start WireGuard, configure firewall/SSH/hardening |
| `serve` | Launch the web dashboard (native window or browser on port 8080) |
| `status` | Show connected peers, transfer stats, and interface state |
| `verify` | Check SHA-256 of deployed config files against vault (tamper detection) |
| `lock` | Wipe in-memory vault state and end the session |
| `change-passphrase` | Re-encrypt the vault under a new passphrase (requires current passphrase) |
| `terminate` | Bring down the WireGuard interface and disconnect all peers (no passphrase needed) |
| `fresh-start` | **Destructive.** Wipe all data (vault, keys, configs) and optionally re-init |
| `update-endpoint` | Auto-detect or manually set the server's public IP/endpoint |
| `add-client` | Generate client keypair + PSK, assign IP from pool, write peer config |
| `remove-client` | Revoke client keys, remove peer, reload WireGuard live |
| `list-clients` | Print all client names and their assigned IPs |
| `show-qr` | Render client config as a terminal QR code (auto-clears after 60 s) |
| `export` | Export client config to stdout or a file (600 permissions) |
| `update-dns` | Push the current public IP to DuckDNS using 2-of-3 resolver consensus |
| `rotate-keys` | Rotate keypair + PSK for a specific client |
| `rotate-server-keys` | Rotate the server keypair and update all client configs |
| `audit-log` | Display recent audit log entries (no passphrase required) |

---

## Session Management

```bash
# Stop WireGuard — disconnects all peers, keeps vault and configs intact
sudo wireseal terminate

# Stop a specific interface (default: wg0)
sudo wireseal terminate --interface wg1

# Change the vault passphrase (requires knowing the current passphrase)
sudo wireseal change-passphrase

# Wipe everything and start fresh — DESTROYS ALL KEYS AND CLIENT CONFIGS
sudo wireseal fresh-start                          # prompts "Type CONFIRM"

# Wipe and immediately re-initialise with a new vault
sudo wireseal fresh-start --reinit --subnet 10.0.0.1/24 --port 51820

# Restart the tunnel after terminate (standard WireGuard command)
sudo wg-quick up wg0
```

> **Forgot your passphrase?** There is no recovery — the vault is encrypted
> with AES-256-GCM and the key is derived solely from your passphrase. If you
> lose it, run `sudo wireseal fresh-start` to wipe everything and re-initialise.

---

## Security Model

All WireGuard private keys and pre-shared keys are stored as `SecretBytes` objects in memory
and serialized only inside the AES-256-GCM vault.

**Vault encryption (FORMAT_VERSION 2 — dual-layer AEAD):**
- Key derivation: Argon2id — `time_cost=10`, `memory_cost=262144 KiB` (256 MiB),
  `parallelism=4`, 256-bit random salt → 32-byte master key
- Key separation: HKDF-SHA512 expands the master key into two independent 256-bit
  subkeys using distinct domain labels — neither subkey leaks information about the other
- Layer 1 (inner): ChaCha20-Poly1305 with fresh 96-bit nonce — stream cipher,
  quantum-resistant family, authenticated
- Layer 2 (outer): AES-256-GCM-SIV with fresh 96-bit nonce — nonce-misuse resistant;
  if a nonce is ever reused, content is still protected (only message equality leaks)
- Both layers use the full 76-byte header as AEAD additional data (AAD) —
  any header modification invalidates both authentication tags simultaneously
- An attacker must break **both** cipher families to read vault contents

**Key handling:**
- All derived keys are held in mutable `bytearray` objects and zero-wiped immediately after use
- `SecretBytes` blocks `pickle`, `repr`, `str`, `__hash__`, and `__eq__` to prevent accidental leaks
- `mlock` is called on key buffers (best-effort; may fail without `CAP_IPC_LOCK`)

**Passphrase input:**
- `click.prompt(hide_input=True)` only — never a CLI flag, never an environment variable (CLI-02)

**Audit log:**
- Append-only NDJSON, mode 640 on Unix / SYSTEM-only ACL on Windows
- No passphrase, private key, or PSK material ever logged (AUDIT-01)
- Newline characters in action/error fields are sanitized to prevent log injection

**Supply chain:**
- All Python dependencies are pinned with SHA-256 hashes in `requirements-dev.txt`
- `pip-audit` runs on every CI push to scan for known CVEs

---

## Threat Model

| | Protected? |
|---|---|
| Vault file at rest (disk stolen, no passphrase) | Yes |
| WireGuard private keys | Yes — vault only |
| Pre-shared keys | Yes — vault only |
| DuckDNS token | Yes — vault only |
| Memory forensics after wireseal exits | No — best-effort wipe only |
| Kernel keyring / ptrace by root | No — out of scope |
| Config files readable by root (`/etc/wireguard/*.conf`) | No — root-owned by design |

---

## Security Limitations

**Windows AV false positive:** The PyInstaller bootloader in the standalone binary may
trigger Windows Defender heuristics. This is a known false positive from PyInstaller's
self-extracting format, not malicious code. Verify the Sigstore signature and SHA-256
checksum before use. If AV scanning is a hard requirement, build from source with `pip install`.

**mlock best-effort:** `mlock` prevents key material from being swapped to disk. It may
fail silently without `CAP_IPC_LOCK` (Linux). On systems where it fails, key material may
appear in swap.

**Python memory management:** CPython does not guarantee immediate memory reclamation.
`SecretBytes.wipe()` zeroes the underlying bytearray before releasing the reference, but
Python may retain object headers briefly after wipe.

---

## Verifying a Release

```bash
# Download binary and checksum file
curl -LO https://github.com/prashanth-7861/WireSeal/releases/latest/download/wireseal-linux-x86_64
curl -LO https://github.com/prashanth-7861/WireSeal/releases/latest/download/sha256sums.txt

# Verify SHA-256
sha256sum -c sha256sums.txt --ignore-missing

# Verify Sigstore signature (keyless — no stored private key)
# Install cosign: https://docs.sigstore.dev/cosign/installation/
cosign verify-blob \
  --certificate wireseal-linux-x86_64.sigstore.json \
  --certificate-identity-regexp "https://github.com/prashanth-7861/WireSeal" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  wireseal-linux-x86_64

# Install
chmod +x wireseal-linux-x86_64
sudo mv wireseal-linux-x86_64 /usr/local/bin/wireseal
```

---

## Web Dashboard (GUI)

WireSeal includes a native desktop GUI built with React + pywebview. Run it with:

```bash
# Launch the dashboard (opens a native window on port 8080)
wireseal serve

# Or use the standalone WireSeal.exe on Windows (no Python needed)
```

The dashboard provides:

- **Welcome screen** with animated branding, vault passphrase setup, and Fresh Start option
- **Real-time status** showing API server (Online/Offline) and WireGuard tunnel (Running/Stopped) indicators in the sidebar
- **Dashboard** with server overview and Stop Server button
- **Client management** — add, remove, view QR codes, and download `.conf` files for mobile clients
- **Live peers table** with connection status, handshake times, and transfer stats
- **Audit log** with three tabs: Events, Sessions, and File Activity (SFTP tracking)
- **Security dashboard** — security score, defense status cards (firewall, fail2ban, SSH,
  kernel, IP forwarding, auto-updates), individual security checks, and open ports audit
- **Settings** for passphrase changes, endpoint updates, and server termination

The WireGuard tunnel runs as a **background system service** — you can close the dashboard
and the VPN keeps running. Reopen the dashboard at any time to manage clients or check status.

| Platform | GUI Backend | Size |
|----------|------------|------|
| **Windows** | pywebview + Edge WebView2 (pre-installed on Win10/11) | ~24 MB |
| **Linux** | pywebview + WebKitGTK (system package) | ~18 MB |
| **macOS** | pywebview + WKWebView (built into macOS) | ~15 MB |

---

## Server Hardening (Linux)

WireSeal includes automated server hardening that runs during `wireseal init` and can
be triggered anytime from the Security dashboard's **Harden Server** button.

### What gets hardened

| Layer | Protection | Details |
|---|---|---|
| **SSH** | Brute force prevention | Root login disabled, max 3 auth attempts, 30s grace time, empty passwords blocked |
| **Kernel** | Network attack prevention | IP spoofing (rp_filter), SYN flood (syncookies), ICMP redirect rejection, core dumps disabled |
| **Fail2ban** | Intrusion detection | 5 failed SSH attempts → 1-hour IP ban, WireGuard port monitoring |
| **Auto-updates** | Patch management | unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora/RHEL) |
| **Firewall** | Traffic filtering | nftables deny-by-default with rate limiting; firewalld port opening for WireGuard UDP |

### Security dashboard

The **Security** page in the web dashboard provides:

- **Security score** — percentage of checks passing (color-coded: green/yellow/red)
- **Defense status cards** — Firewall, Fail2ban, SSH Hardened, Kernel Hardened, IP Forwarding, Auto Updates
- **Individual checks** — pass/fail with fix suggestions for each hardening measure
- **Open ports audit** — lists all listening services with Expected/Review badges to spot rogue processes
- **Fail2ban stats** — currently banned IPs displayed in real-time

> **Note:** Server hardening features are currently Linux-only. On Windows/macOS the
> Security page shows a message indicating that hardening requires a Linux deployment.

---

## Contributing

Submit pull requests against `main`. All commits must pass:

```bash
pytest -m "not integration" -q
```

Integration tests (`pytest -m integration`) require a Docker daemon and run automatically
on merge to `main` in CI.

**Security issues:** Do not open a public GitHub issue for security vulnerabilities.
Send a private report to the maintainers with a minimal reproduction and the affected
version. Public disclosure is coordinated after a fix is available.

---

## Author

**Prashanth Mudigonda**

- GitHub: [prashanth-7861](https://github.com/prashanth-7861)
- Portfolio: [prashanth-mudigonda.vercel.app](https://prashanth-mudigonda.vercel.app/)

---

*Licensed under [MIT](LICENSE)*
