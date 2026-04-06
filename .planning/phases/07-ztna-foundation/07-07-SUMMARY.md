---
phase: "07"
plan: "07"
subsystem: security
tags: [audit, argon2id, keyslot, totp, integration-tests, hardening]
dependency_graph:
  requires: [07-01, 07-02, 07-03, 07-04, 07-05, 07-06]
  provides: [phase-7-complete, audit-actor-attribution, production-argon2-params]
  affects: [api.py, keyslot.py, vault.py, audit.py, expiry.py]
tech_stack:
  added: []
  patterns: [argon2-semaphore, audit-actor-attribution, dev-fast-params-pattern]
key_files:
  modified:
    - src/wireseal/security/audit.py
    - src/wireseal/security/keyslot.py
    - src/wireseal/security/vault.py
    - src/wireseal/api.py
    - src/wireseal/core/expiry.py
  created:
    - tests/security/test_keyslot.py
    - tests/security/test_totp.py
    - tests/integration/test_phase7.py
decisions:
  - "_argon2_semaphore is imported lazily inside _derive_wrapping_key to avoid circular import between keyslot.py and vault.py"
  - "unlock_keyslot accepts **_ignored_kdf_params to allow test code to pass _DEV_FAST_PARAMS uniformly without special-casing unlock vs create; slot stores its own params and always uses them"
  - "Vault.create gains keyslot_params kwarg accepted but ignored (v2 vaults have no keyslots); enables consistent test fixture pattern"
metrics:
  duration: "~25 minutes"
  completed_date: "2026-04-06"
  tasks_completed: 2
  files_changed: 8
  tests_added: 22
  total_tests_passing: 173
---

# Phase 07 Plan 07: Integration Hardening Summary

Audit actor attribution added to every audit log entry, Argon2id keyslot parameters raised to production values, concurrent KDF semaphore extended to keyslots, and a comprehensive 22-test suite covering keyslot crypto, TOTP anti-replay, multi-admin, DNS, and backup flows.

## Tasks Completed

| Task | Description | Commit |
| ---- | ----------- | ------ |
| 1 | Audit actor fields, _argon2_semaphore, production Argon2id keyslot params | fe4340f |
| 2 | Phase 7 integration tests — keyslot, TOTP, multi-admin, DNS, backup | 2ef749e |

## What Was Built

### Task 1: Production Argon2id Hardening + Audit Actor Attribution

**AuditLog.log() actor parameter** (`src/wireseal/security/audit.py`):
- Added `actor: str | None = None` kwarg to `AuditLog.log()`
- Actor is injected into the metadata dict before scrubbing (only if not already present — callers that already embed `actor` in metadata are left unchanged)

**Audit actor coverage in api.py** (`src/wireseal/api.py`):
- System events (`unlock-ratelimited`, `unlock-failed`, `admin-auth-ratelimited`, `peer-connected`, `heartbeat`, `auto-lock`, `shutdown`, `admin-auth-failed`, `unlock-pin`) use `actor="system"`
- Initialization (`init`) uses `actor="system"` (no session yet)
- User-triggered actions (`unlock-web`, `lock`, `add-client`, `remove-client`, `export-qr`, `export-config`, `change-passphrase`, `harden-server`, `update-endpoint`, `set-pin`, `remove-pin`, `admin-activate`, `admin-deactivate`, `admin-exec`, `admin-service`, `admin-read-file`, `admin-write-file`, `rotate-client-keys`, `rotate-server-keys`, `totp-enrolled`, `unlock-backup-code`, `start`, `terminate`) use the session's `admin_id` as actor
- Calls with actor already in metadata (`add-admin`, `remove-admin`, `change-passphrase` admin version, `totp-disabled`, `totp-reset`, `backup-trigger`, `backup-restore`) were left unchanged

**Audit actor in expiry.py** (`src/wireseal/core/expiry.py`):
- `peer-expired` audit call now passes `actor="system"`

**Production Argon2id keyslot params** (`src/wireseal/security/keyslot.py`):
- `KEYSLOT_TIME_COST`: 3 → 10
- `KEYSLOT_MEMORY_COST_KIB`: 65536 (64 MiB) → 262144 (256 MiB)
- Added `_DEV_FAST_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}` for test override

**_ARGON2_SEMAPHORE extension to keyslots**:
- `_derive_wrapping_key` now acquires `_ARGON2_SEMAPHORE` (imported lazily from vault.py to avoid circular import) before calling `hash_secret_raw`, preventing concurrent 256 MiB allocations from keyslot KDF calls

**Function signature updates for testability**:
- `create_keyslot` gains `time_cost`, `memory_cost`, `parallelism` keyword args (defaulting to production constants); allows `**_DEV_FAST_PARAMS` in tests
- `unlock_keyslot` gains `**_ignored_kdf_params` (KDF params always read from slot's stored values)
- `find_and_unlock` forwards `**kdf_params` to `unlock_keyslot`
- `Vault.add_keyslot` gains `keyslot_params: dict | None = None` — passed as `**kwargs` to `create_keyslot`
- `Vault.create` gains `keyslot_params: dict | None = None` — accepted but ignored for v2 vaults

### Task 2: Test Suite

**`tests/security/test_keyslot.py`** — 6 tests:
- `test_create_and_unlock_round_trip`: create + unlock, recovered key equals original
- `test_wrong_passphrase_raises`: wrong passphrase → `KeyslotNotFoundError`
- `test_serialize_deserialize_144_bytes`: serialized keyslot is exactly 144 bytes, round-trip preserves admin_id and master key
- `test_find_and_unlock_correct_admin`: multi-slot store unlocks with correct admin's passphrase
- `test_find_unknown_admin_raises`: unknown admin_id → `KeyslotNotFoundError`
- `test_serialize_store_round_trip`: N-slot store serializes to N*144 bytes and deserializes with correct roles

**`tests/security/test_totp.py`** — 9 tests:
- `test_secret_b32_round_trip`: generate → encode → decode round-trip
- `test_totp_uri_format`: URI starts with `otpauth://totp/`, contains `secret=` and `issuer=`
- `test_verify_totp_current_window`: current-step code accepted
- `test_verify_totp_previous_window`: T-1 step code accepted with window=1
- `test_verify_totp_wrong_code`: bad code rejected with window=0
- `test_verify_totp_anti_replay`: same code rejected on second use when used_codes set is provided
- `test_backup_code_single_use`: matched hash removed from list, second use returns None
- `test_backup_code_wrong_code`: non-matching code returns None
- `test_backup_code_generation_uniqueness`: 8 unique 10-char codes generated

**`tests/integration/test_phase7.py`** — 7 tests:
- `TestMultiAdmin::test_add_admin_and_unlock`: upgrade v2→v3, alice unlocks and sees data
- `TestMultiAdmin::test_cannot_remove_last_owner`: `AdminRoleError` on removing last owner keyslot
- `TestMultiAdmin::test_remove_non_owner_admin`: bob's keyslot removed, bob can no longer unlock
- `TestDnsMappings::test_add_and_retrieve_dns_mapping`: DNS entry persists across vault open/close
- `TestDnsMappings::test_remove_dns_mapping`: deleted DNS entry absent after save+reopen
- `TestBackupRestore::test_backup_and_restore_cycle`: backup, corrupt vault, restore, data intact
- `TestBackupRestore::test_restore_wrong_passphrase_rejected`: wrong passphrase → `VaultUnlockError`, live vault untouched

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] _ARGON2_SEMAPHORE already existed in vault.py under that name**
- **Found during:** Task 1
- **Issue:** The plan said to add `_argon2_semaphore = threading.Semaphore(1)` to vault.py, but vault.py already had `_ARGON2_SEMAPHORE = threading.Semaphore(1)` (uppercase, at line 93) already in use in `_derive_master_key`. Adding a duplicate would have been wrong.
- **Fix:** Used the existing `_ARGON2_SEMAPHORE` — imported it lazily in keyslot's `_derive_wrapping_key` to extend semaphore coverage without duplication or circular import
- **Files modified:** `src/wireseal/security/keyslot.py`

**2. [Rule 1 - Bug] AuditLog.log() had no actor parameter — actor was embedded in metadata dicts, not a separate field**
- **Found during:** Task 1
- **Issue:** The plan specified passing `actor=_session.get("admin_id", "system")` to `audit_log.log()`, but the actual signature only had `(action, metadata, success, error)`. Several existing calls already embedded `actor` in the metadata dict.
- **Fix:** Added `actor: str | None = None` kwarg to `AuditLog.log()`. Implementation injects actor into metadata before scrubbing, only if not already present there. Existing calls that already have `actor` in metadata are unaffected.
- **Files modified:** `src/wireseal/security/audit.py`, `src/wireseal/api.py`, `src/wireseal/core/expiry.py`

**3. [Rule 2 - Missing critical functionality] create_keyslot and unlock_keyslot needed **kwargs for test override**
- **Found during:** Task 2 (test design)
- **Issue:** The test plan called for passing `**_DEV_FAST_PARAMS` to `create_keyslot` and `unlock_keyslot`, but neither function accepted those kwargs. Tests would have failed with `TypeError`.
- **Fix:** Added explicit `time_cost`, `memory_cost`, `parallelism` kwargs to `create_keyslot`; added `**_ignored_kdf_params` to `unlock_keyslot` (KDF params always come from the stored slot). Added `keyslot_params: dict | None` to `Vault.add_keyslot` and `Vault.create`.
- **Files modified:** `src/wireseal/security/keyslot.py`, `src/wireseal/security/vault.py`

**4. [Rule 1 - Bug] Integration test used incorrect Vault.open() call pattern**
- **Found during:** Task 2 (test design)
- **Issue:** The plan's proposed test used `Vault.open(vault_path, owner_pass)` as a classmethod, but `open()` is an instance method requiring `Vault(vault_path).open(passphrase)`.
- **Fix:** Tests use `Vault(vault_path)` then `.open()` per actual API.
- **Files modified:** `tests/integration/test_phase7.py`

## Self-Check: PASSED

Created files exist:
- `tests/security/test_keyslot.py` — FOUND
- `tests/security/test_totp.py` — FOUND
- `tests/integration/test_phase7.py` — FOUND

Commits exist:
- fe4340f — FOUND (feat(07-07): audit actor fields...)
- 2ef749e — FOUND (feat(07-07): Phase 7 integration tests...)

Test results: 22 new tests passing, 173 total passing.
