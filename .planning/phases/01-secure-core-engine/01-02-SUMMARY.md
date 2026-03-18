---
phase: 01-secure-core-engine
plan: "02"
subsystem: security
tags: [aes-gcm, argon2id, vault, encryption, atomic-write, context-manager, kdf]

# Dependency graph
requires:
  - "01-01 (SecretBytes, wipe_bytes)"
provides:
  - "Vault: encrypted state container with AES-256-GCM + Argon2id, atomic writes"
  - "VaultState: context-manager-scoped state with SecretBytes wrapping"
  - "VaultError / VaultUnlockError / VaultTamperedError: vault exception hierarchy"
affects:
  - 01-03
  - 01-04
  - all downstream phases (vault is the single source of truth for all secrets)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Binary header as AES-GCM AAD: any header modification invalidates tag"
    - "Argon2id KDF with parameters stored in header for forward-compatible decryption"
    - "Fresh os.urandom(12) nonce per encryption (SEC-06: never reuse)"
    - "Atomic write: mkstemp + fsync + os.replace, permissions set before rename"
    - "VaultState context manager: wipe all SecretBytes in finally on exit"
    - "Generic unlock error message: never distinguish wrong passphrase from tampering"

key-files:
  created:
    - src/wg_automate/security/exceptions.py
    - src/wg_automate/security/vault.py
  modified:
    - src/wg_automate/security/__init__.py

key-decisions:
  - "Corrupted ct_len field raises VaultUnlockError (not VaultTamperedError) to preserve generic error contract"
  - "Argon2 params stored in binary header (not just constants) for forward-compatible decryption"
  - "Header (47 bytes) used as AES-GCM AAD so header tampering also invalidates the authentication tag"
  - "Hint stored as vault_path.with_suffix('.hint') plaintext file beside vault.enc"

patterns-established:
  - "VAULT-04 Pattern: use 'with vault.open(passphrase) as state:' for automatic secret cleanup"
  - "ct_len validation before slice: Python silently truncates slices, explicit check required"

requirements-completed: [SEC-06, VAULT-01, VAULT-02, VAULT-03, VAULT-04, VAULT-05, VAULT-06, VAULT-07, VAULT-08]

# Metrics
duration: 3min
completed: 2026-03-18
---

# Phase 1 Plan 02: Encrypted Vault Summary

**AES-256-GCM vault with Argon2id KDF (262144 KiB / 4 iter / 4 par), atomic writes, context-manager secret cleanup, passphrase change, and integrity verification**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-18T02:41:09Z
- **Completed:** 2026-03-18T02:44:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- `VaultError`, `VaultUnlockError`, `VaultTamperedError` exception hierarchy with documented security contracts
- `vault.py`: full encrypted vault implementation with:
  - AES-256-GCM encryption; 47-byte binary header used as AAD (header tampering detected by GCM tag)
  - Argon2id KDF: 262144 KiB (256 MiB) memory / 4 iterations / 4 parallelism
  - KDF parameters stored in header for forward-compatible decryption across parameter upgrades
  - `os.urandom(12)` nonce generated fresh per encryption (SEC-06)
  - Atomic write: `mkstemp` + `os.fsync` + `os.replace`; permissions set on temp file BEFORE rename (vault is never world-readable)
  - Vault directory: 700 permissions (Unix); best-effort `icacls` on Windows (VAULT-02)
  - `VaultState` context manager: wipes all `SecretBytes` in `finally` on exit (VAULT-04)
  - `Vault.create()` enforces minimum 12-character passphrase before any file I/O (VAULT-03)
  - `Vault.change_passphrase()`: decrypt with old, re-encrypt with new salt+nonce, atomic write (VAULT-07)
  - `Vault.verify_integrity()`: tests GCM tag without persisting decrypted state (VAULT-08)
  - `Vault.get_hint()`: reads plaintext `.hint` file beside vault; `create()` warns user hint is unprotected (VAULT-06)
- Wrong passphrase and tampered ciphertext/header both raise `VaultUnlockError("Vault unlock failed")` -- attacker cannot distinguish failure modes

## Task Commits

Each task was committed atomically:

1. **Task 1: Vault exceptions and binary format constants** - `93f4ec5` (feat)
2. **Task 2: Encrypted vault with Argon2id KDF, AES-256-GCM, context manager, and atomic writes** - `370bf94` (feat)

## Files Created/Modified

- `src/wg_automate/security/exceptions.py` - VaultError / VaultUnlockError / VaultTamperedError hierarchy
- `src/wg_automate/security/vault.py` - Full vault implementation (596 lines)
- `src/wg_automate/security/__init__.py` - Added exception exports

## Decisions Made

- `VaultUnlockError` (not `VaultTamperedError`) is raised when the ct_len field is corrupted. This preserves the generic error contract: all decryption failures are `VaultUnlockError`. `VaultTamperedError` is reserved for structural pre-decrypt failures (bad magic bytes) where it is safe to be more specific.
- Argon2 parameters are read from the header (not module constants) during decryption. This enables future parameter upgrades without breaking existing vaults.
- The 47-byte binary header is passed as AES-GCM AAD. Any modification to version, KDF parameters, salt, or nonce also invalidates the authentication tag.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed silent truncation of ciphertext slice when ct_len is tampered**
- **Found during:** Task 2 verification
- **Issue:** Python's slice notation `blob[51: 51 + ct_len]` silently returns fewer bytes than requested when the slice end exceeds the blob length. A tampered ct_len field (e.g., byte 50 XOR 0xFF inflates ct_len to 501 for a 317-byte blob) caused `_decrypt_vault` to feed the real ciphertext bytes (just fewer than expected) to AESGCM, which decrypted successfully -- bypassing tampering detection entirely.
- **Fix:** After extracting `ct_len`, validate `len(blob) >= _HEADER_SIZE + 4 + ct_len`. If not, raise `VaultUnlockError("Vault unlock failed") from None` (same generic message -- attacker cannot tell if ct_len is tampered vs blob is truncated).
- **Files modified:** `src/wg_automate/security/vault.py`
- **Commit:** `370bf94`

## Issues Encountered

None beyond the one auto-fixed bug above.

## User Setup Required

None.

## Next Phase Readiness

- Vault is complete and verified. Plans 01-03 (key generation) and 01-04 (IP pool + config builder) can import and use `Vault`, `VaultState`, and the exception hierarchy immediately.
- The `VaultState.to_dict()` / `VaultState._wrap_secrets()` pattern is established: all `*_key` and `psk` fields auto-wrap/unwrap as `SecretBytes`.

---
*Phase: 01-secure-core-engine*
*Completed: 2026-03-18*
