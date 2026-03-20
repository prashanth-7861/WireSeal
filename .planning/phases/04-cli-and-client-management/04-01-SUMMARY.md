---
phase: 04-cli-and-client-management
plan: "01"
subsystem: cli
tags: [click, wireguard, vault, audit, integrity, argon2, aes-gcm]

requires:
  - phase: 01-secure-core-engine
    provides: SecretBytes, Vault, keygen, IPPool, ConfigBuilder
  - phase: 02-platform-hardening
    provides: AbstractPlatformAdapter, get_adapter, deploy_config, enable_tunnel_service
  - phase: 03-dynamic-dns-and-audit
    provides: AuditLog, verify_config_integrity

provides:
  - Click CLI group with all 14 commands registered (wg-automate --help complete)
  - init: vault creation + keygen + platform setup + optional DuckDNS in one command
  - status: wg show parser displaying peers without key material
  - verify: SHA-256 config file integrity check against vault records
  - lock: decrypted state wipe with sys.exit(0)
  - change-passphrase: vault re-encryption with hidden prompts
  - 9 stub commands for plans 04-02 and 04-03

affects:
  - 04-02-PLAN (adds add-client, remove-client, list-clients, show-qr, export)
  - 04-03-PLAN (adds rotate-keys, rotate-server-keys, update-dns, audit-log)

tech-stack:
  added: [click]
  patterns:
    - Lazy imports inside command functions to keep wg-automate --help fast
    - SecretBytes wrapping passphrase strings immediately after click.prompt
    - try/finally wipe pattern for every passphrase variable
    - click.ClickException for all error paths (no bare exceptions leaking tracebacks)

key-files:
  created:
    - src/wg_automate/main.py
  modified:
    - src/wg_automate/__init__.py

key-decisions:
  - "Lazy imports inside command functions: heavy modules (Vault, platform adapters) imported inside the function body, not at module top-level, so wg-automate --help stays fast"
  - "click.ClickException wraps all exceptions in command bodies so Click formats errors cleanly without Python tracebacks leaking locals or passphrase fragments"
  - "lock command does not require passphrase; it wipes temp artifacts and exits 0 even if audit log is inaccessible"
  - "verify resolves config paths via adapter.get_config_path() using config name stored in vault integrity dict"
  - "wg show PrivateKey assertion added as defense-in-depth guard in status command"

patterns-established:
  - "Passphrase pattern: collect via click.prompt(hide_input=True), wrap in SecretBytes immediately, wipe in finally"
  - "Command error pattern: catch Exception, re-raise as click.ClickException to prevent traceback leaks"
  - "Stub pattern: _not_implemented(name) raises click.ClickException, giving exit code 1 with clean message"

requirements-completed: [CLI-01, CLI-02, CLI-03, CLI-04, CLI-05]

duration: 8min
completed: 2026-03-20
---

# Phase 4 Plan 01: Click CLI skeleton and vault-lifecycle commands Summary

**Click group with 14 registered commands (wg-automate --help complete from day one), plus full init/status/verify/lock/change-passphrase implementations wiring Vault + platform adapter + keygen + ConfigBuilder + AuditLog**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-20T15:30:36Z
- **Completed:** 2026-03-20T15:38:05Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Created `src/wg_automate/main.py` as the authoritative CLI entry point with all 14 commands visible in `--help`
- Implemented `init` command that chains: passphrase prompt -> privilege check -> keypair generation -> IP allocation -> vault creation -> config build + deploy -> firewall + service enable -> optional DuckDNS -> audit log
- Implemented `status` (wg show parser), `verify` (SHA-256 integrity checker), `lock` (temp file wipe + sys.exit(0)), and `change-passphrase` (vault re-encryption)
- All 9 future commands registered as stubs that raise `click.ClickException` cleanly (exit code 1) on invocation while returning exit code 0 for `--help`

## Task Commits

Each task was committed atomically:

1. **Task 1+2: Click CLI skeleton with 14-command group** - `a3dd7c4` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `src/wg_automate/main.py` - Click CLI group with all 14 commands; init/status/verify/lock/change-passphrase fully implemented; 9 stubs for 04-02/04-03
- `src/wg_automate/__init__.py` - Added CLI entry-point comment

## Decisions Made

- Lazy imports inside command functions to keep `wg-automate --help` fast (Vault, platform adapters, keygen imported inside function bodies)
- `click.ClickException` wraps all exception paths so Python tracebacks (which could leak passphrase fragments from locals) are never shown to users
- `lock` command does not prompt for passphrase and must never fail — audit log write is wrapped in a bare `except Exception: pass`
- `verify` resolves filesystem paths by calling `adapter.get_config_path()` using the config name key stored in the vault's integrity dict
- Defense-in-depth assertion in `status`: checks that `wg show` output does not contain the string `"PrivateKey"` before displaying anything

## Deviations from Plan

None — plan executed exactly as written. Task 1 (skeleton) and Task 2 (implementations) were delivered together in a single file since the implementations are part of `main.py`.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- All 14 command stubs registered: plans 04-02 and 04-03 can fill in bodies without touching the CLI group declaration
- `init` wires all Phase 1-3 subsystems into one command; the full flow is exercisable once WireGuard is installed on the target platform
- Stub commands (add-client, remove-client, list-clients, show-qr, export, rotate-keys, rotate-server-keys, update-dns, audit-log) await 04-02 and 04-03 implementations

---
*Phase: 04-cli-and-client-management*
*Completed: 2026-03-20*
