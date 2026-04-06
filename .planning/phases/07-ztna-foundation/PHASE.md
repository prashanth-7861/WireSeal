---
phase: "07"
title: ZTNA Foundation
status: planning
---

# Phase 7: ZTNA Foundation

## Goal
Transform WireSeal from a single-admin passphrase-based VPN manager into a
self-sovereign, multi-admin remote access platform with hardware-free
cryptographic identity, ephemeral access control, and zero external
dependencies.

## Constraints (NON-NEGOTIABLE)
- No hardware requirements (no TPM, HSM, Secure Enclave)
- No external APIs, no cloud services of any kind
- Open-source — works on any hardware, any Linux/macOS/Windows
- Backward compatible: single-admin deployments unchanged
- User decides multi-admin at init or promoted later via settings

## Features

### 7.1 Multi-Admin Vault (LUKS-style Keyslots)
Currently: vault master key derived directly from passphrase via Argon2id.
New: vault master key is a random 32-byte key; each admin has a keyslot
(Argon2id-derived wrapping key that encrypts the master key).
- Single-admin: one keyslot, UX identical to today
- Multi-admin: multiple keyslots, each admin unlocks with own passphrase
- Commands: add-admin, remove-admin, list-admins, change-admin-passphrase
- Roles: owner (full + admin management), admin (full), read-only (view only)
- Audit log records which admin performed each action

### 7.2 TOTP 2FA (RFC 6238, stdlib-only)
Per-admin optional TOTP enrollment. No external library (pyotp forbidden).
- Enrollment: generates TOTP secret, shows QR code in dashboard
- Verification: passphrase + TOTP code on unlock (when enrolled)
- Implementation: hmac, struct, time, base64, hashlib — stdlib only
- Backup codes: 8 single-use recovery codes stored encrypted in vault
- Admin can disable their own TOTP; owner can reset another admin's TOTP

### 7.3 Ephemeral Keys with TTL
Client configs expire after user-defined TTL (default: 24h, configurable per-client).
- TTL metadata stored in vault per-client entry
- Background thread checks every 60s, removes expired peers from WireGuard
- Heartbeat endpoint: POST /api/heartbeat/<name> resets TTL
- Manual override: owner/admin can exempt a client from TTL (permanent=true)
- Audit log records expiry and heartbeat events

### 7.4 Split-DNS (dnsmasq)
wireseal serve writes dnsmasq config fragment and manages dnsmasq lifecycle.
- User defines internal name→IP mappings in settings
- DNS served only to connected VPN clients (via WireGuard interface)
- Graceful degradation if dnsmasq not installed (warn, continue)
- Platform: Linux primary, macOS via /etc/resolver/, Windows via netsh

### 7.5 Encrypted Local Backup
Vault backup on-change and on-schedule.
- Destinations: local filesystem, SSH/rsync, WebDAV (self-hosted only)
- No cloud APIs — user owns and controls the destination
- Versioned: keep last N backups, configurable
- CLI: wireseal backup <dest>, wireseal restore <src>
- Dashboard: backup status, last backup time, manual trigger

## Implementation Order
7.1 → 7.2 → 7.3 → 7.4 → 7.5
(7.1 must be first — all other features depend on the new vault schema)

## Success Criteria
1. Single-admin deployments experience zero UX change after upgrade
2. Multi-admin: each admin unlocks with own passphrase, audit log attributes actions
3. TOTP: enrollment produces scannable QR, verification rejects wrong codes, backup codes work once
4. Ephemeral: client auto-removed at TTL expiry, heartbeat resets TTL, permanent flag bypasses
5. Split-DNS: plex.home resolves for VPN clients, not for external traffic
6. Backup: vault round-trips backup→corrupt→restore→unlock successfully
