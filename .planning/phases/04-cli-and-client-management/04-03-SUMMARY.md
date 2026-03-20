---
phase: 04-cli-and-client-management
plan: "03"
subsystem: cli
tags: [click, wireguard, keygen, psk, vault, audit, key-rotation, atomic-write]

requires:
  - phase: 04-01
    provides: Click CLI skeleton with rotate-keys, rotate-server-keys, audit-log stubs
  - phase: 01-secure-core-engine
    provides: SecretBytes, Vault, generate_keypair, generate_psk, ConfigBuilder, wipe_bytes
  - phase: 03-dynamic-dns-and-audit
    provides: AuditLog, get_recent_entries

provides:
  - rotate-keys command: atomic client key rotation (new keypair + PSK, validate, write, reload, wipe old, QR display)
  - rotate-server-keys command: atomic server keypair rotation propagating new server public key to all client configs
  - audit-log command: passphrase-free display of last N audit log entries with security invariant check

affects:
  - 04-02-PLAN (parallel wave — both extend main.py; 04-03 stubs for update-dns/export/add-client remain untouched)
  - 05-deployment (rotate-keys and rotate-server-keys are the highest-risk runtime operations; deployment testing must cover key rotation)

tech-stack:
  added: []
  patterns:
    - "Generate-before-wipe rotation order: new material generated and validated BEFORE old SecretBytes are wiped"
    - "Vault-atomic boundary: vault context manager holds old state as fallback; vault.save() called only after all file writes succeed"
    - "WireGuard reload resilience: wg syncconf failure prints warning but does not abort (disk state already correct)"
    - "Passphrase-free audit display: audit-log reads log file directly without opening vault"
    - "AUDIT-01 security invariant check in audit-log: asserts no PrivateKey/psk/passphrase/token field names in retrieved entries"

key-files:
  created: []
  modified:
    - src/wg_automate/main.py

key-decisions:
  - "Generate-before-wipe order enforced: new keypair + PSK generated and configs validated before old SecretBytes.wipe() is called — ensures old keys exist as fallback until new configs confirmed written"
  - "Vault context manager is the atomic boundary for key rotation: vault.save() is only called after all file writes and wg syncconf attempt complete; if any write fails, the exception propagates and vault state is not committed"
  - "WireGuard reload failure is non-fatal for rotation: configs on disk are already updated, so not aborting is the correct choice — the operator can run the printed wg syncconf command manually"
  - "audit-log requires no vault passphrase by design: AUDIT-01 ensures no secrets are ever logged, so the log is safe to read without authentication"
  - "AUDIT-01 invariant check in audit-log display: field names PrivateKey/psk/passphrase/token trigger CRITICAL warning if found — does not crash since the invariant should have been enforced at write time"
  - "rotate-server-keys requires explicit click.confirm before proceeding: server rotation disconnects all clients and is irreversible without reconnection"

patterns-established:
  - "Key rotation atomicity pattern: generate new -> validate -> write configs -> reload WireGuard -> wipe old SecretBytes -> save vault"
  - "Passphrase-free command pattern: audit-log reads directly from AuditLog without vault unlock (AUDIT-01 guarantees no secrets in log)"
  - "Confirmation gate pattern: rotate-server-keys uses click.confirm(default=False) before destructive server-wide operation"

requirements-completed: [CLIENT-05, CLIENT-06, AUDIT-03]

duration: 3min
completed: 2026-03-20
---

# Phase 4 Plan 03: Key rotation commands and audit-log display Summary

**Atomic rotate-keys and rotate-server-keys commands with generate-before-wipe SecretBytes ordering, plus passphrase-free audit-log display with AUDIT-01 security invariant check**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-20T15:41:10Z
- **Completed:** 2026-03-20T15:43:46Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- Implemented `rotate-keys`: full atomic rotation pipeline — generate new keypair + PSK before touching old material, validate new configs, write atomically, reload WireGuard via wg syncconf, wipe old SecretBytes, commit vault, display new QR with 60-second auto-clear
- Implemented `rotate-server-keys`: server-wide rotation requiring explicit confirmation, propagates new server public key to every client config atomically, wipes old server private key before committing new vault state
- Implemented `audit-log`: passphrase-free log display calling `AuditLog.get_recent_entries(n)`, formats entries as `timestamp [action] key=value` pairs, enforces AUDIT-01 by checking for secret field names in each entry and printing a CRITICAL warning if found

## Task Commits

Both tasks modify only `src/wg_automate/main.py` and were committed together in one atomic commit:

1. **Task 1+2: rotate-keys, rotate-server-keys, audit-log** - `a43ea4d` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `src/wg_automate/main.py` — rotate-keys (CLIENT-05), rotate-server-keys (CLIENT-06), and audit-log (AUDIT-03) stubs replaced with full implementations

## Decisions Made

- Generate-before-wipe order: new SecretBytes material is fully generated and configs validated before any old SecretBytes.wipe() calls — ensures the old keys remain valid until the new config is confirmed written to disk
- Vault context manager is the commit boundary: vault.save() is called only after all file writes succeed; if any write throws, the vault state reverts without committing half-rotated state
- WireGuard reload failure is non-fatal: the configs on disk are already correct at that point, so aborting would leave a divergence between disk state and what we'd report as success; the warning message gives the operator a precise recovery command
- audit-log needs no passphrase: AUDIT-01 was enforced at write time; reading the log without vault auth is safe by design

## Deviations from Plan

### Structural Note

Both tasks were committed in a single commit (`a43ea4d`) because both modify only `src/wg_automate/main.py` and the implementations were applied sequentially in the same edit session. Both task-level verifications passed independently before the single commit was made.

**Total deviations:** None from plan logic — committed together only due to single-file scope.

## Issues Encountered

- The file was slightly modified between my first and second edit (a linter or concurrent process updated the module-level imports and docstring). I re-read the file and applied the audit-log edit cleanly on the updated version.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- All three commands (rotate-keys, rotate-server-keys, audit-log) are fully implemented and verified
- rotate-keys and rotate-server-keys depend on `core/qr_generator.py` (lazy import) which plan 04-02 creates; the import is inside the function body so no import-time error occurs if 04-02 hasn't run yet
- audit-log is fully standalone and operational — tested against the existing audit.log written by the lock command

---
*Phase: 04-cli-and-client-management*
*Completed: 2026-03-20*
