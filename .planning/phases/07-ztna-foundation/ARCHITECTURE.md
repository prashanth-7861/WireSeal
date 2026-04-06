---
phase: "07"
document: ARCHITECTURE
status: approved
---

# Phase 7 ZTNA Foundation — Implementation Architecture

Read SECURITY-SPEC.md before this document. Crypto decisions there are final.
This document is the implementation blueprint. Every section is precise and directly actionable.

---

## 1. File Map

### 7.1 Multi-Admin Vault (LUKS-style Keyslots)

**New files:**
- `src/wireseal/security/keyslot.py` — `Keyslot` dataclass, `KeyslotStore` class.
  - `create_keyslot(admin_id, passphrase, master_key) -> Keyslot`
  - `unlock_keyslot(slot, passphrase) -> bytearray`
  - `remove_keyslot(store, admin_id) -> KeyslotStore`
  - Argon2id params stored per-slot so they can differ between admins.

**Modified files:**
- `src/wireseal/security/vault.py` — Major refactor.
  - `_encrypt_vault` / `_decrypt_vault` accept 32-byte master key directly (not passphrase).
  - FORMAT_VERSION 3 binary layout with N keyslots in header.
  - New methods: `Vault.add_keyslot`, `Vault.remove_keyslot`, `Vault.list_keyslots`, `Vault.change_keyslot_passphrase`.
  - `VaultState.__init__` handles new top-level keys: `admins`, `dns_mappings`, `backup_config`.
  - `_migrate_v1_to_v2(data)` — schema migration, called automatically on open.
- `src/wireseal/security/exceptions.py` — Add `KeyslotNotFoundError`, `KeyslotExistsError`, `AdminRoleError`.
- `src/wireseal/api.py` — Add `_h_list_admins`, `_h_add_admin`, `_h_remove_admin`, `_h_change_admin_passphrase`. Modify `_h_unlock` to accept `admin_id`. Add `_session["admin_id"]` and `_session["admin_role"]`.
- `src/wireseal/main.py` — Add Click commands: `add-admin`, `remove-admin`, `list-admins`, `change-admin-passphrase`.

### 7.2 TOTP 2FA

**New files:**
- `src/wireseal/security/totp.py` — Pure stdlib RFC 6238 implementation.
  - `generate_totp_secret() -> bytes` (20-byte random)
  - `totp_uri(secret, admin_id, issuer) -> str` (otpauth:// URI)
  - `verify_totp(secret, code, window=1) -> bool` (checks T-1/T/T+1)
  - `generate_backup_codes(n=8) -> list[str]` (8-char alphanumeric uppercase)
  - `hash_backup_code(code) -> str` (SHA-256 hex, stored in vault)
  - `verify_backup_code(code, hashed_codes) -> str | None` (returns matched hash for removal)

**Modified files:**
- `src/wireseal/api.py` — Add: `_h_totp_enroll_begin`, `_h_totp_enroll_confirm`, `_h_totp_disable`, `_h_totp_reset`, `_h_totp_verify_backup`. Modify `_h_unlock` for TOTP enforcement. Add `_session["pending_totp"]` dict.
- `src/wireseal/main.py` — Add: `totp-enroll`, `totp-disable`.

### 7.3 Ephemeral Keys with TTL

**New files:**
- `src/wireseal/core/expiry.py` — `ExpiryWatcher(threading.Thread, daemon=True)`.
  - Polls every 60s.
  - Checks `ttl_expires_at` vs `time.time()` per client.
  - Removes expired peer: `wg set wg0 peer <pubkey> remove` + vault update + audit log.
  - Skips cycle when vault is locked.

**Modified files:**
- `src/wireseal/api.py` — Add: `_h_heartbeat`, `_h_set_client_ttl`. Modify `_h_add_client` for `ttl_seconds`. Modify `_h_list_clients` to include TTL fields. Start `ExpiryWatcher` in `serve()`. Add `_heartbeat_cooldown: dict[str, float]` module-level.
- `src/wireseal/main.py` — Add: `set-ttl`, `set-permanent`.

### 7.4 Split-DNS (dnsmasq)

**New files:**
- `src/wireseal/dns/__init__.py` — Empty package marker.
- `src/wireseal/dns/dnsmasq.py` — `DnsmasqManager` class.
  - `write_config(dns_mappings, wg_interface, wg_ip) -> Path`
  - `reload()` — SIGHUP to dnsmasq process
  - `is_available() -> bool`
  - Platform dispatch: Linux (`/etc/dnsmasq.d/`), macOS (`/etc/resolver/`), Windows (netsh).

**Modified files:**
- `src/wireseal/api.py` — Add: `_h_get_dns_mappings`, `_h_set_dns_mappings`, `_h_add_dns_mapping`, `_h_remove_dns_mapping`. Call `DnsmasqManager.write_config()` + `reload()` on vault start.
- `src/wireseal/main.py` — Add: `dns-add`, `dns-remove`, `dns-list`.

### 7.5 Encrypted Local Backup

**New files:**
- `src/wireseal/backup/__init__.py` — Empty package marker.
- `src/wireseal/backup/manager.py` — `BackupManager` class, `BackupEntry` dataclass.
  - Local path (shutil.copy2), SSH/rsync (subprocess), WebDAV (urllib.request PUT).
  - `create_backup(vault_path, dest_config) -> BackupEntry`
  - `restore_backup(src_path, vault_path, passphrase)` — verifies decryptable before replacing.
  - `list_backups(dest_config) -> list[BackupEntry]`
  - `prune_old(dest_config, keep_n)`

**Modified files:**
- `src/wireseal/api.py` — Add: `_h_backup_config_get`, `_h_backup_config_set`, `_h_backup_trigger`, `_h_backup_list`, `_h_backup_restore`.
- `src/wireseal/main.py` — Add: `backup`, `restore`.

---

## 2. Vault Schema Evolution

### Current (schema_version: 1)
```json
{
  "schema_version": 1,
  "server": { "private_key": "...", "public_key": "...", "ip": "10.0.0.1",
              "subnet": "10.0.0.0/24", "port": 51820, "endpoint": "..." },
  "clients": {
    "alice": { "private_key": "...", "public_key": "...", "psk": "...",
               "ip": "10.0.0.2", "config_hash": "..." }
  },
  "ip_pool": { "subnet": "10.0.0.0/24", "allocated": {"alice": "10.0.0.2"} },
  "integrity": { "server": "..." }
}
```

### New (schema_version: 2)
```json
{
  "schema_version": 2,
  "server": { "private_key": "...", "public_key": "...", "ip": "10.0.0.1",
              "subnet": "10.0.0.0/24", "port": 51820, "endpoint": "...",
              "duckdns_domain": null },
  "admins": {
    "owner": {
      "role":             "owner",
      "created_at":       "2026-04-02T00:00:00+00:00",
      "totp_secret_b32":  null,
      "totp_enrolled_at": null,
      "backup_codes":     [],
      "last_unlock":      null
    }
  },
  "clients": {
    "alice": {
      "private_key": "...", "public_key": "...", "psk": "...",
      "ip": "10.0.0.2", "config_hash": "...",
      "ttl_seconds":    86400,
      "ttl_expires_at": 1743638400.0,
      "permanent":      false
    }
  },
  "ip_pool": { "subnet": "10.0.0.0/24", "allocated": {"alice": "10.0.0.2"} },
  "integrity": { "server": "..." },
  "dns_mappings": { "plex.home": "10.0.0.10" },
  "backup_config": {
    "enabled": false, "destination": "local", "local_path": null,
    "ssh_host": null, "ssh_user": null, "ssh_path": null,
    "webdav_url": null, "webdav_user": null,
    "keep_n": 10, "last_backup_at": null
  }
}
```

### Migration: `_migrate_v1_to_v2(data) -> dict`
- Add `admins: {"owner": {role: "owner", totp_secret_b32: null, backup_codes: [], ...}}`
- Add `dns_mappings: {}`
- Add `backup_config` with all defaults
- For each client: add `ttl_seconds: null, ttl_expires_at: null, permanent: true` (existing = permanent)
- Set `schema_version: 2`
- Called automatically in `Vault.open()` before returning. Saves immediately after migration.

### Binary Format: FORMAT_VERSION 3 Keyslot Header
Each admin keyslot is 144 bytes (fixed):
```
[32 bytes]  Argon2id salt
[4 bytes]   memory_cost_kib (uint32 BE)
[4 bytes]   time_cost (uint32 BE)
[4 bytes]   parallelism (uint32 BE)
[12 bytes]  AES-256-GCM nonce for wrapping
[48 bytes]  wrapped_master_key (32 plaintext + 16 GCM tag)
[40 bytes]  admin_id UTF-8, null-padded
```
File header: `MAGIC(4) | FORMAT_VERSION=3(1) | keyslot_count(1) | N*144 bytes keyslots | ...payload`

Unlock: iterate keyslots, compare admin_id field (constant-time `hmac.compare_digest`), call Argon2id only on matching slot → unwrap master key → HKDF to derive ChaCha/AES subkeys.

Upgrade path: FORMAT_VERSION 2 → 3 happens only when `add_keyslot` is first called. The existing Argon2id output IS the FORMAT_VERSION 2 master key. Wrap it under a new keyslot for the owner.

---

## 3. API Endpoints

### New: /api/admins (7.1)
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /api/admins | unlocked | List admins (id, role, totp_enrolled, last_unlock) |
| POST | /api/admins | unlocked + owner | Add admin: `{admin_id, passphrase, role}` |
| DELETE | /api/admins/<id> | unlocked + owner | Remove admin (cannot remove last owner or self) |
| POST | /api/admins/<id>/change-passphrase | unlocked | Change passphrase: `{old_passphrase?, new_passphrase}` |

### Modified: /api/unlock (7.1)
- Request body: `{"passphrase": "...", "admin_id": "owner", "totp_code": "123456"}`
- `admin_id` defaults to `"owner"` (backward compat — existing clients unchanged)
- `totp_code` required only when that admin has TOTP enrolled
- Response adds: `"role": "owner"`

### Modified: /api/vault-info (7.1)
- Response adds: `"multi_admin": bool`, `"totp_required_for": ["owner"]`

### New: /api/totp/* (7.2)
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /api/totp/enroll/begin | unlocked | Returns `{otpauth_uri, secret_b32, qr_png_b64}`. Stores pending in session. |
| POST | /api/totp/enroll/confirm | unlocked | `{totp_code}` — verifies + saves. Returns `{ok, backup_codes: [...]}` |
| POST | /api/totp/disable | unlocked | `{admin_id?}` — owner or self only |
| POST | /api/totp/reset | unlocked + owner | `{admin_id}` — wipes another admin's TOTP |
| POST | /api/totp/verify-backup | none | `{admin_id, passphrase, backup_code}` — full unlock via backup code |

### New: /api/heartbeat/<name> (7.3)
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /api/heartbeat/<name> | none | Resets TTL. Rate-limited 1/30s per name. Source IP must be in VPN subnet. |

### New: /api/clients/<name>/ttl (7.3)
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /api/clients/<name>/ttl | unlocked | `{ttl_seconds: N}` or `{permanent: true}` |

### New: /api/dns (7.4)
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /api/dns | unlocked | Returns `{mappings, dnsmasq_available, dnsmasq_running}` |
| POST | /api/dns | unlocked | `{mappings: {...}}` — full replace, reloads dnsmasq |
| POST | /api/dns/<name> | unlocked | `{ip: "10.0.0.x"}` — add single mapping |
| DELETE | /api/dns/<name> | unlocked | Remove mapping |

### New: /api/backup/* (7.5)
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /api/backup/config | unlocked | Returns backup_config from vault |
| POST | /api/backup/config | unlocked | Saves backup_config |
| POST | /api/backup/trigger | unlocked | Runs backup now, returns path + size |
| GET | /api/backup/list | unlocked | Returns list of existing backups |
| POST | /api/backup/restore | unlocked | `{backup_path, passphrase}` — verify then replace |

---

## 4. Dashboard Pages and Components

### New Pages
- `Dashboard/src/app/pages/Admins.tsx` — Admin list + add/remove + TOTP toggle per admin. Role badges. Cannot remove self or last owner.
- `Dashboard/src/app/pages/Dns.tsx` — DNS mapping table + add/remove form. dnsmasq availability banner.
- `Dashboard/src/app/pages/Backup.tsx` — Backup config form + manual trigger + backup list table + restore modal.

### New Components
- `Dashboard/src/app/components/TotpEnrollDialog.tsx` — 3-step modal: QR display → code verify → backup codes display.
- `Dashboard/src/app/components/ClientTtlBadge.tsx` — Shows "Permanent" | "Expires in Xh Ym" | "Expired". Used in Clients table.
- `Dashboard/src/app/components/AdminRoleBadge.tsx` — Colored pill: owner (purple) / admin (blue) / read-only (gray).

### Modified Pages
- `Dashboard/src/app/pages/Settings.tsx` — Add TOTP section: current admin enroll/disable.
- `Dashboard/src/app/pages/Clients.tsx` — Add TTL column using `ClientTtlBadge`. Add "Set TTL" action per client.
- `Dashboard/src/app/routes.tsx` — Add `/admins`, `/dns`, `/backup` routes.
- `Dashboard/src/app/components/Layout.tsx` — Add nav links for Admins, DNS, Backup.

### Modified: Unlock Screen
- When `multi_admin: true`: show `admin_id` text input (default "owner").
- When `totp_required_for` includes the selected admin_id: show `totp_code` 6-digit input after passphrase.
- Fallback link: "Use backup code" → calls `/api/totp/verify-backup`.

### api.ts Additions
New types: `AdminInfo`, `TotpEnrollBeginResponse`, `DnsMappings`, `BackupConfig`, `BackupEntry`.
New methods: `listAdmins`, `addAdmin`, `removeAdmin`, `changeAdminPassphrase`,
`totpEnrollBegin`, `totpEnrollConfirm`, `totpDisable`, `totpReset`, `totpVerifyBackup`,
`heartbeat`, `setClientTtl`, `getDns`, `setDns`, `addDnsMapping`, `removeDnsMapping`,
`getBackupConfig`, `setBackupConfig`, `triggerBackup`, `listBackups`, `restoreBackup`.

---

## 5. CLI Commands

### 7.1 Admin Management
```
wireseal add-admin <admin_id> [--role admin|read-only]
  → Prompts owner passphrase + new admin passphrase + confirm.
  → Calls Vault.add_keyslot. Logs audit: add-admin.

wireseal remove-admin <admin_id>
  → Prompts owner passphrase. Confirms y/N. Rejects last owner.
  → Calls Vault.remove_keyslot. Logs audit: remove-admin.

wireseal list-admins
  → Prompts any admin passphrase. Prints: admin_id | role | totp_enrolled | last_unlock.

wireseal change-admin-passphrase [admin_id]
  → Defaults to "owner". Prompts old + new passphrase. Owner can change others.
  → Calls Vault.change_keyslot_passphrase. Logs audit.
```

### 7.2 TOTP
```
wireseal totp-enroll [admin_id]
  → Prompts admin passphrase. Prints otpauth:// URI + ASCII QR.
  → Prompts first TOTP code to confirm. Prints 8 backup codes. Logs audit: totp-enroll.

wireseal totp-disable [admin_id]
  → Prompts passphrase. Owner can disable others; non-owner self only.
  → Clears totp_secret_b32 + backup_codes. Logs audit: totp-disable.
```

### 7.3 TTL
```
wireseal set-ttl <name> <seconds>
  → seconds=0 → permanent=True. Else sets ttl_seconds + ttl_expires_at.

wireseal set-permanent <name>
  → Shortcut: set-ttl <name> 0.
```

### 7.4 DNS
```
wireseal dns-add <hostname> <ip>   → Validates both. Adds to vault. Reloads dnsmasq.
wireseal dns-remove <hostname>     → Removes from vault. Reloads dnsmasq.
wireseal dns-list                  → Prints hostname → IP table.
```

### 7.5 Backup
```
wireseal backup [--dest <path>]    → Creates timestamped backup. Prints path + size.
wireseal restore <src>             → Verifies decryptable first. Confirms y/N. Replaces vault.
```

---

## 6. Performance Considerations

### Unlock with Multiple Keyslots — O(1)
`admin_id` is sent in the unlock request. Keyslot array is iterated, admin_id compared with `hmac.compare_digest` (constant-time). Argon2id called ONLY on the matching slot. Unlock stays ~3s regardless of admin count. Wrong admin_id = instant rejection, no Argon2id.

### Argon2id Concurrency — Semaphore
`threading.Semaphore(1)` named `_argon2_semaphore` in `vault.py`. All Argon2id calls acquire it before hashing. Prevents OOM on Raspberry Pi when multiple unlocks or expiry watcher runs concurrently. Max queue: ~3s delay per queued call.

### ExpiryWatcher Thread Safety
- Does NOT hold `_lock` during Argon2id (~3s).
- Read `_session["vault"]` + `_session["passphrase"]` under `_lock` briefly (reference copy).
- Release `_lock` before Argon2id.
- Re-acquire `_lock` only for `vault.save()` + `_session["cache"]` update.
- Skip cycle entirely if `_session["vault"] is None` (locked).
- Skip cycle if no non-permanent clients exist (no vault.open() needed).

### WireGuard Peer Removal
`wg set wg0 peer <pubkey> remove` — single netlink call, sub-millisecond. Never uses `wg-quick down/up` for expiry.

### dnsmasq Config Writes
Written only on DNS mapping change (not on every WG reload). Atomic write (`atomic_write`). SIGHUP via `pkill -HUP dnsmasq` — non-blocking, failure logged as warning only.

---

## 7. Implementation Sub-Plans

### Wave 1
**07-01**: Schema Migration + Keyslot Core (vault.py + keyslot.py foundation)
- All other sub-plans depend on this.

### Wave 2
**07-02**: Multi-Admin API + CLI (depends on 07-01)

### Wave 3 (parallel)
**07-03**: TOTP 2FA (depends on 07-02)
**07-04**: Ephemeral Keys + TTL (depends on 07-01)
**07-05**: Split-DNS / dnsmasq (depends on 07-01)
**07-06**: Encrypted Local Backup (depends on 07-01)

### Wave 4
**07-07**: Integration, Hardening, Audit Completeness (depends on all)

---

## 8. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | Vault corruption during FORMAT_VERSION 2→3 upgrade | Low | Critical | `atomic_write` (tmp+fsync+os.replace). Old file never modified in-place. |
| 2 | Argon2id OOM on Raspberry Pi (concurrent calls) | Medium | High | `_argon2_semaphore(1)` serialises all Argon2id calls. |
| 3 | TOTP time skew locks out admins (no NTP) | Medium | Medium | `window=2` (±90s tolerance). Warn in logs when offset window used. |
| 4 | ExpiryWatcher SecretBytes leak across cycles | Low | Medium | Use `VaultState` as context manager. Verify wipe in `finally`. |
| 5 | dnsmasq config injection via hostname input | Medium | High | `re.fullmatch(r'^[a-z0-9][a-z0-9.-]{0,253}[a-z0-9]$', hostname)` strictly enforced. |
| 6 | Heartbeat endpoint DoS — continuous vault writes | Medium | Low-Med | Rate-limit 1/30s per name. Reject source IPs outside VPN subnet. |
| 7 | Backup restore overwrites live vault before verify | Low | Critical | Two-phase: decrypt in memory first; only replace file on success. |
| 8 | ExpiryWatcher + API handler concurrent vault writes | Medium | Medium | Both hold `_lock` (RLock) around vault.save(). Same lock = no deadlock. |

---

## Summary: New Files

**Python (6 new):**
- `src/wireseal/security/keyslot.py`
- `src/wireseal/security/totp.py`
- `src/wireseal/core/expiry.py`
- `src/wireseal/dns/__init__.py`
- `src/wireseal/dns/dnsmasq.py`
- `src/wireseal/backup/__init__.py`
- `src/wireseal/backup/manager.py`

**Python (4 modified):**
- `src/wireseal/security/vault.py` (major)
- `src/wireseal/security/exceptions.py` (minor)
- `src/wireseal/api.py` (major)
- `src/wireseal/main.py` (major)

**TypeScript/React (6 new):**
- `Dashboard/src/app/pages/Admins.tsx`
- `Dashboard/src/app/pages/Dns.tsx`
- `Dashboard/src/app/pages/Backup.tsx`
- `Dashboard/src/app/components/TotpEnrollDialog.tsx`
- `Dashboard/src/app/components/ClientTtlBadge.tsx`
- `Dashboard/src/app/components/AdminRoleBadge.tsx`

**TypeScript/React (4 modified):**
- `Dashboard/src/app/api.ts`
- `Dashboard/src/app/routes.tsx`
- `Dashboard/src/app/components/Layout.tsx`
- `Dashboard/src/app/pages/Settings.tsx`
- `Dashboard/src/app/pages/Clients.tsx`
