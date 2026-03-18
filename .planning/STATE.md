# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-17)

**Core value:** Zero plaintext secrets on disk, ever -- if the vault is compromised without the passphrase, no key material is exposed.
**Current focus:** Phase 1: Secure Core Engine

## Current Position

Phase: 1 of 5 (Secure Core Engine)
Plan: 3 of 4 in current phase
Status: Executing
Last activity: 2026-03-18 -- Completed plan 01-03 (key generation X25519/PSK + IP pool manager)

Progress: [██░░░░░░░░] 19% (3/16 plans complete)

## Performance Metrics

**Velocity:**
- Total plans completed: 3
- Average duration: 2 min
- Total execution time: 0.10 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-secure-core-engine | 3/4 | 7 min | 2 min |

**Recent Trend:**
- Last 5 plans: 3 min
- Trend: Stable

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Roadmap]: SecretBytes (security/secret_types.py) must be built FIRST -- it is the dependency chain foundation for vault and all secret handling
- [Roadmap]: vault.py lives in security/, not core/ -- the vault IS the security boundary
- [Roadmap]: Python 3.12 minimum (not 3.10 -- 3.10 EOL October 2026)
- [Roadmap]: os.replace() for atomic writes (not os.rename() -- fails on Windows when target exists)
- [Roadmap]: wg syncconf with file locking (not wg setconf) to preserve active sessions
- [01-01]: Python upper bound widened to <3.15 -- installed Python is 3.14.2; original <3.14 excluded it
- [01-01]: setuptools.build_meta used (not setuptools.backends.legacy:build -- path invalid in setuptools 80.9)
- [01-01]: wipe_bytes uses simple index-based loop (cleaner than ctypes memmove for bytearray item assignment)
- [01-02]: Corrupted ct_len field raises VaultUnlockError (not VaultTamperedError) to preserve generic error contract
- [01-02]: Argon2 params stored in binary header for forward-compatible decryption across parameter upgrades
- [01-02]: 47-byte header used as AES-GCM AAD so header tampering also invalidates the authentication tag
- [01-03]: Public key returned as plain bytes (not SecretBytes) -- WireGuard public keys are non-secret by design
- [01-03]: Standard base64 (not url-safe) used for key encoding -- matches wg CLI output format
- [01-03]: IPPool uses ip_network(strict=False) for user-friendly host-bit input (e.g., 10.0.0.1/24)

### Pending Todos

None.

### Blockers/Concerns

- [Phase 2]: Windows WireGuard tunnel service API (DPAPI config store, named pipe IPC) needs verification -- biggest unknown in the project
- [Phase 2]: macOS SIP/TCC restrictions evolve per release -- pfctl anchor approach needs testing on current macOS
- [Phase 5]: PyInstaller behavior with ctypes mlock calls needs verification

## Session Continuity

Last session: 2026-03-18
Stopped at: Completed 01-03-PLAN.md (X25519 key generation, PSK generation, IP pool manager)
Resume file: None
