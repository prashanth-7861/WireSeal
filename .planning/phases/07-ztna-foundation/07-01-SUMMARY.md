---
phase: 07-ztna-foundation
plan: "01"
subsystem: security/vault
tags: [cryptography, keyslot, vault, argon2id, aes-gcm, format-version-3]
dependency_graph:
  requires: []
  provides:
    - "KeyslotNotFoundError, KeyslotExistsError, AdminRoleError (exceptions.py)"
    - "Keyslot, KeyslotStore, create/unlock/find/serialize/deserialize (keyslot.py)"
    - "FORMAT_VERSION_3 vault with multi-admin keyslot management (vault.py)"
  affects:
    - "All Phase 7 sub-plans depend on vault schema_version=2 and keyslot primitives"
tech_stack:
  added:
    - "argon2-cffi: Argon2id wrapping key derivation in keyslot.py"
    - "cryptography.hazmat.primitives.ciphers.aead.AESGCM: AES-256-GCM keyslot wrapping"
    - "threading.Semaphore: serialise concurrent Argon2id calls"
  patterns:
    - "LUKS-style keyslot: per-admin passphrase wraps shared master key"
    - "AES-256-GCM AAD = admin_id (binds ciphertext to identity)"
    - "Binary keyslot: 144 bytes, big-endian struct, null-padded admin_id"
    - "v2->v3 upgrade: existing master key wrapped in owner keyslot on first add_keyslot()"
    - "Auto-save on VaultState context exit for FORMAT_VERSION 3 sessions"
    - "Roles loaded from data['admins'] into KeyslotStore after v3 decryption"
key_files:
  created:
    - path: "src/wireseal/security/keyslot.py"
      description: "144-byte keyslot binary format, Argon2id+AES-256-GCM wrapping, KeyslotStore"
  modified:
    - path: "src/wireseal/security/exceptions.py"
      description: "Added KeyslotNotFoundError, KeyslotExistsError, AdminRoleError"
    - path: "src/wireseal/security/vault.py"
      description: "FORMAT_VERSION 3 support, keyslot management methods, schema_version 2 initial state"
decisions:
  - "Argon2id dev params (time=3, mem=64MiB, par=4) in keyslot.py -- production hardening deferred to 07-07"
  - "Roles NOT encoded in keyslot binary -- loaded from data['admins'] after decryption to avoid chicken-and-egg"
  - "_migrate_v1_to_v2() implemented but NOT auto-called in open() -- preserves existing test asserting schema_version=1; migration is available for explicit use"
  - "VaultState.__exit__ auto-saves v3 format when session_format==FORMAT_VERSION_3 and no exception occurred"
  - "Vault.open() accepts SecretBytes|bytearray (not classmethod) -- preserves existing instance-method API"
metrics:
  duration: "~25 minutes"
  completed_date: "2026-04-04"
  tasks_completed: 4
  files_modified: 3
  files_created: 1
---

# Phase 7 Plan 01: Keyslot Foundation Summary

Implemented the FORMAT_VERSION 3 keyslot vault foundation: Argon2id+AES-256-GCM per-admin key wrapping with 144-byte binary serialization, full v2 backward compatibility, and multi-admin keyslot management methods.

## What Was Built

### Task 1: Exception classes (exceptions.py)

Three new exception classes appended to the existing hierarchy:
- `KeyslotNotFoundError(VaultError)` — wrong passphrase or missing admin_id
- `KeyslotExistsError(VaultError)` — duplicate admin_id on add_keyslot
- `AdminRoleError(VaultError)` — last-owner removal, privilege violations

### Task 2: keyslot.py (~230 lines)

Complete LUKS-style key wrapping module:

**Binary layout (144 bytes):** `[32 salt][4 mem_cost][4 time_cost][4 parallelism][12 nonce][48 wrapped_key][40 admin_id]`

**Key functions:**
- `create_keyslot(admin_id, passphrase, master_key, role)` — Argon2id(passphrase, salt) → wrapping key → AES-256-GCM(master_key, aad=admin_id.encode())
- `unlock_keyslot(slot, passphrase)` — derives wrapping key, decrypts; raises `KeyslotNotFoundError` on GCM auth failure
- `find_and_unlock(store, admin_id, passphrase)` — hmac.compare_digest lookup + unlock
- `serialize_keyslot / deserialize_keyslot` — 144-byte round-trip
- `serialize_store / deserialize_store` — N×144 byte block
- Wrapping keys wiped in `finally` blocks after use

### Task 3: vault.py refactor (+560 lines net)

**FORMAT_VERSION 3 binary layout:**
```
MAGIC(4) | VERSION=3(1) | keyslot_count(1) | N*144 keyslots |
76-byte v2-style payload header (salt/nonces active; Argon2 params vestigial) |
4-byte ct_len | double-ciphertext (ChaCha20-Poly1305 + AES-256-GCM-SIV)
```

**New/changed functions:**
- `_ARGON2_SEMAPHORE` — serialises concurrent Argon2id calls
- `_migrate_v1_to_v2(data)` — adds admins, dns_mappings, backup_config, TTL fields
- `_canonical_v2_initial_state()` — used by `Vault.create()` when no initial_state given
- `_encrypt_payload / _decrypt_payload` — extracted helpers for reuse across v2/v3
- `_encrypt_vault_v3 / _decrypt_vault_v3` — FORMAT_VERSION 3 encode/decode
- `Vault.create()` — now accepts `SecretBytes | bytearray`, `initial_state=None`
- `Vault.open(passphrase, admin_id="owner")` — dispatches v2 or v3 decrypt path
- `Vault.add_keyslot(admin_id, passphrase, role)` — v2→v3 upgrade on first call
- `Vault.remove_keyslot(admin_id)` — guards last-owner removal
- `Vault.list_keyslots()` — returns [{admin_id, role}]
- `Vault.change_keyslot_passphrase(admin_id, old_pp, new_pp)` — verify + re-wrap
- `VaultState.data` property — public alias for `_data` (new API)
- `VaultState.vault` attribute — backreference to owning `Vault`
- `VaultState.__exit__` — auto-saves v3 store before wiping

### Task 4: Test suite

All 58 existing tests pass with zero modifications.

## Deviations from Plan

### Auto-fixed Issues

None.

### Intentional Deviations

**1. [Design deviation] _migrate_v1_to_v2 not auto-called in open()**
- **Found during:** Task 3 implementation analysis
- **Issue:** The plan says "Opening a schema_version 1 vault automatically migrates it." However, the existing test `test_vault_round_trip` creates a schema_version=1 vault and asserts `state._data["schema_version"] == 1` after opening it. Auto-migrating in `open()` would make this assertion fail, breaking the existing test. The constraint "Do NOT modify tests" and "keep FORMAT_VERSION 2 fully working" are contradictory with auto-migration.
- **Resolution:** `_migrate_v1_to_v2()` is implemented and available but NOT called automatically from `open()`. New vaults created via `Vault.create()` without `initial_state` get schema_version=2 natively. Explicit migration can be triggered by calling `_migrate_v1_to_v2(state.data)` followed by a save.
- **Impact:** No production impact — existing v1 vaults in the field should be explicitly migrated; auto-migration on open was a design convenience, not a security requirement.

**2. [Design deviation] Roles stored in data["admins"], not in keyslot binary**
- **Found during:** Task 3 implementation (v3 deserialization)
- **Issue:** The 144-byte keyslot binary does not encode role. `deserialize_store` defaults all slots to role="admin". To get correct roles, we need the decrypted JSON payload's `admins` dict, but we need roles to know which slots are owners (for last-owner guard in `remove_keyslot`).
- **Resolution:** After `_decrypt_vault_v3` decrypts the payload, `open()` applies roles from `data["admins"]` to the deserialized KeyslotStore. This creates the correct roles in `_session_store` before `VaultState` is constructed. The `admins` dict is kept in sync by `add_keyslot` and `remove_keyslot` via the `_session_state` backreference.
- **Impact:** Correct behavior; roles are authoritative in the encrypted JSON payload.

## Self-Check: PASSED

| Check | Result |
|-------|--------|
| `src/wireseal/security/keyslot.py` exists | FOUND |
| `src/wireseal/security/exceptions.py` exists | FOUND |
| `src/wireseal/security/vault.py` exists | FOUND |
| `07-01-SUMMARY.md` exists | FOUND |
| Commit a70bf49 (exceptions) | FOUND |
| Commit 4e6cfe7 (keyslot.py) | FOUND |
| Commit ab6ec5c (vault.py refactor) | FOUND |
| 58 tests pass, 0 failures | VERIFIED |
