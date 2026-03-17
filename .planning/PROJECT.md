# wg-automate — WireGuard Server Automation CLI

## What This Is

`wg-automate` is a cross-platform (Linux, macOS, Windows) CLI tool for one-command WireGuard VPN server setup and management. It handles key generation, encrypted state storage, firewall hardening, Dynamic DNS, client provisioning, and QR code generation — all with a security-first, zero-trust design where private keys never touch disk unencrypted and every action is auditable.

## Core Value

**Zero plaintext secrets on disk, ever** — if the vault is compromised without the passphrase, no key material is exposed. All other features serve this guarantee.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] One-command server setup on Linux, macOS, and Windows
- [ ] Encrypted vault (AES-256-GCM + Argon2id KDF) for all key material and tokens
- [ ] Automatic Curve25519 key pair generation (no subprocess — no key in `ps aux`)
- [ ] Per-peer pre-shared keys (PSK) for post-quantum resistance
- [ ] QR code generation in memory, terminal-only by default (never saved to disk)
- [ ] DuckDNS integration with multi-source consensus public IP detection
- [ ] Platform firewall hardening: deny-by-default on Linux (nftables/iptables), macOS (pfctl), Windows (netsh)
- [ ] Client config export with 600 permissions and key-exposure warnings
- [ ] Append-only audit log (no secrets ever logged)
- [ ] Pre-apply config validator (key format, IP conflicts, INI injection prevention)
- [ ] Config integrity tracking (SHA-256 hash stored in vault, verified before reload)
- [ ] 14-command CLI: init, add-client, remove-client, list-clients, show-qr, rotate-keys, rotate-server-keys, update-dns, status, export, audit-log, verify, lock
- [ ] Idempotent and re-runnable — every action logged, safe to re-run
- [ ] Security-focused test suite (unit + Docker integration tests)
- [ ] PyInstaller standalone binaries (Linux, macOS, Windows) with GPG-signed releases

### Out of Scope

- IPv6 dual-stack — deferred to future enhancement; IPv4 is sufficient for v1
- TOTP for vault unlock — complexity; passphrase is sufficient for v1
- Automatic key rotation scheduler — manual rotation commands cover v1 needs
- Per-client AllowedIPs firewall (mesh/ACL) — advanced topology, future enhancement
- Prometheus metrics export — observability is future enhancement
- Cloudflare/PowerDNS alternative — DuckDNS only for v1
- Hardware key support (YubiKey/FIDO2) — future enhancement
- Containerized server (Docker secrets) — future enhancement
- Peer-to-peer mesh topology — server-client model only for v1

## Context

This project implements a security-hardened WireGuard automation tool. The threat model is explicit: key theft from disk, MitM on DNS, unauthorized client connections, leaked configs, brute force, privilege escalation, stale revoked clients, physical access, DNS rebinding, and supply chain attacks. Every mitigation is designed into the architecture.

**Tech stack (fixed):** Python 3.10+, click, Jinja2 (StrictUndefined + autoescape), argon2-cffi, cryptography (X25519PrivateKey), qrcode (pure Python), requests (verify=True always), pytest, PyInstaller.

**Platform target:** Linux (systemd + nftables/iptables), macOS (launchd + pfctl), Windows (service + netsh + DPAPI).

**State storage:** `~/.wg-automate/vault.enc` (600), `~/.wg-automate/` dir (700). All writes are atomic (write to `.tmp`, fsync, rename — no partial writes).

## Constraints

- **Security**: Private keys must never appear in process arguments, env vars visible to other processes, or plaintext files — enforced by design, not convention
- **Tech stack**: Python 3.10+ only — cross-platform, mature crypto, no C memory bugs; stack is fixed per plan
- **Dependencies**: Pinned with SHA-256 hashes (`pip install --require-hashes`) — supply chain protection
- **Privileges**: Setup requires root/admin; runtime drops privileges where possible
- **No telemetry**: The tool contacts only 4 external endpoints (DuckDNS + 3 IP detection sources). Zero phoning home.
- **Fail closed**: Every ambiguous or error state locks down rather than leaving open holes
- **Atomic writes**: All config file writes are atomic (tmp + rename) — no partial state on crash

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Argon2id for KDF (256MB/4iter/4par) | Memory-hard, GPU/ASIC resistant, OWASP recommended — brute force must take >500ms | — Pending |
| AES-256-GCM authenticated encryption | Tamper detection built-in (GCM auth tag) — wrong passphrase or tampering rejected immediately | — Pending |
| X25519PrivateKey.generate() directly (no `wg genkey` subprocess) | Keys never appear in process arguments visible via `ps aux` | — Pending |
| Per-peer PSK on top of Curve25519 | Post-quantum resistance via symmetric layer; quantum computers break asymmetric, not symmetric | — Pending |
| nftables preferred over iptables on Linux | Modern, atomic rule replacement, better performance | — Pending |
| DPAPI for Windows token encryption | Windows-native, tied to machine + user account — no separate secret management | — Pending |
| Jinja2 StrictUndefined | Missing template variables cause hard failure — no silent empty strings in configs | — Pending |
| Multi-source consensus for public IP (2-of-3 required) | Single source failure doesn't cause DNS poisoning; all over HTTPS | — Pending |
| QR display terminal-only by default | Client private key in QR — never persisted unless explicit `--save-qr` flag with warnings | — Pending |
| Client names: alphanumeric + hyphens only, max 32 chars | Prevent path traversal and INI injection via client name | — Pending |

---
*Last updated: 2026-03-17 after initialization*
