---
phase: 04-cli-and-client-management
plan: "02"
subsystem: cli
tags: [wireguard, qrcode, click, vault, client-lifecycle, ip-pool, config-builder]

# Dependency graph
requires:
  - phase: 04-01
    provides: Click CLI skeleton with 14 registered commands and all vault-lifecycle implementations
  - phase: 01-secure-core-engine
    provides: keygen, psk, ip_pool, config_builder, vault, atomic, permissions
  - phase: 03-dynamic-dns-and-audit
    provides: ip_resolver, duckdns, audit log
provides:
  - generate_qr_terminal(config_str) -> str — in-memory ASCII QR via qrcode library
  - save_qr(config_str, path, auto_delete) — file save with 600 perms, 5-min timer
  - add-client command — full pipeline: keygen, PSK, IP allocation, config, syncconf, QR
  - remove-client command — immediate revocation, syncconf, IP release, vault purge
  - list-clients command — name/IP/last-handshake table with no key material
  - show-qr command — ASCII QR with 60-second auto-clear, --save-qr / --auto-delete
  - export command — 600-permission config file export with private-key warning
  - update-dns command — 2-of-3 IP consensus + vault-sourced DuckDNS token
affects:
  - 04-03 (rotation commands that also call _reload_wireguard and use the same helpers)
  - 04-04 (integration tests for client lifecycle)

# Tech tracking
tech-stack:
  added:
    - qrcode>=7.4 (pure-Python, no Pillow required for ASCII terminal output)
  patterns:
    - All commands use hide_input=True for passphrase (CLI-02)
    - Vault context manager kept open for entire atomic operation; saved only after syncconf
    - _extract_secret_str() helper unifies SecretBytes and plain str access
    - _reload_wireguard() uses wg syncconf + bash process substitution on Linux/macOS,
      wg-quick down/up fallback on Windows
    - QR displayed post-vault-wipe to prevent context from holding secrets during sleep

key-files:
  created:
    - src/wg_automate/core/qr_generator.py
  modified:
    - src/wg_automate/main.py
    - src/wg_automate/core/__init__.py
    - pyproject.toml

key-decisions:
  - "qrcode library added to pyproject.toml — missing from prior plans, required for Task 1"
  - "generate_qr_terminal never writes to disk; config_str (with private key) stays in memory only"
  - "save_qr uses threading.Timer(300) daemon to schedule file deletion; daemon=True prevents blocking exit"
  - "Vault context manager closed and wiped before time.sleep(QR_DISPLAY_TIMEOUT) to avoid holding secrets during 60-second wait"
  - "_reload_wireguard uses wg syncconf + bash process substitution (wg-quick strip); Windows uses wg-quick down/up fallback"
  - "server_ip used as DNS server in client configs (VPN server acts as DNS forwarder)"
  - "DuckDNS domain used for server_endpoint if configured; plain server_ip:port fallback"
  - "update-dns keeps token in SecretBytes until _update_dns() call (DNS-03 enforced)"

patterns-established:
  - "Client add/remove: vault stays open across syncconf; save() called only after syncconf succeeds"
  - "Secret extraction: _extract_secret_str() handles SecretBytes vs plain str uniformly"
  - "Audit log: metadata contains only non-secret name/ip/path fields; no key material ever"
  - "QR display: vault wiped before sleep; config string deleted after click.clear()"

requirements-completed: [CLIENT-01, CLIENT-02, CLIENT-03, CLIENT-04, CLIENT-07, CLIENT-08]

# Metrics
duration: 12min
completed: 2026-03-20
---

# Phase 4 Plan 02: Client lifecycle commands — add-client, remove-client, list-clients, show-qr, export, update-dns Summary

**In-memory QR generation via qrcode library and full client lifecycle — add, revoke, inspect, and export — all routing key material through the vault with zero plaintext on disk.**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-03-20T00:00:00Z
- **Completed:** 2026-03-20T00:12:00Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- Created `core/qr_generator.py` with `generate_qr_terminal()` (in-memory, no file) and `save_qr()` (600 perms + auto-delete timer)
- Implemented `add-client`: generates keypair + PSK, allocates IP, builds + validates config, atomic write, updates server config, wg syncconf reload, vault commit, QR display with 60-second terminal clear
- Implemented `remove-client`: immediate revocation (no grace period), syncconf, IP release, vault purge, audit log
- Implemented `list-clients`: vault auth, wg show dump for handshake times, table output with no private key material
- Implemented `show-qr`: reconstructs config from vault, ASCII QR, 60-second auto-clear, --save-qr/--auto-delete options
- Implemented `export`: reconstructs config from vault, atomic write with 600 permissions, private-key warning and shred hint
- Implemented `update-dns`: vault-sourced DuckDNS token, 2-of-3 IP consensus, HTTPS update, audit log

## Task Commits

Each task was committed atomically:

1. **Task 1: QR generator module (in-memory, qrcode library)** - `5c0cf2e` (feat)
2. **Task 2: add-client and remove-client commands** - `3ad40a0` (feat)
3. **Task 3: list-clients, show-qr, export, and update-dns commands** - `581bb14` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `src/wg_automate/core/qr_generator.py` - QR generator: generate_qr_terminal, save_qr, QR_DISPLAY_TIMEOUT
- `src/wg_automate/main.py` - add-client, remove-client, list-clients, show-qr, export, update-dns; _reload_wireguard helper, _extract_secret_str helper
- `src/wg_automate/core/__init__.py` - Export generate_qr_terminal and save_qr
- `pyproject.toml` - Added qrcode>=7.4 dependency

## Decisions Made

- qrcode library (pure-Python) added to pyproject.toml — was missing despite being specified in the plan
- generate_qr_terminal uses io.StringIO for in-memory ASCII output; no image file ever written
- save_qr schedules file deletion with threading.Timer(300, daemon=True) for --auto-delete
- Vault context manager is closed and state wiped before time.sleep() to avoid holding secrets during the 60-second QR display window
- _reload_wireguard() uses bash process substitution (wg syncconf wg0 <(...)) on Linux/macOS; wg-quick down/up fallback on Windows since process substitution is not available
- Server VPN IP used as DNS server in client configs (server acts as DNS forwarder)
- DuckDNS domain preferred over server IP for client endpoint when configured

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added qrcode>=7.4 to pyproject.toml and installed it**
- **Found during:** Task 1 (QR generator module)
- **Issue:** qrcode was specified in the plan but missing from pyproject.toml; `import qrcode` failed with ModuleNotFoundError
- **Fix:** Added `qrcode>=7.4` to pyproject.toml dependencies and ran `pip install qrcode`
- **Files modified:** pyproject.toml
- **Verification:** `import qrcode; qr = qrcode.QRCode(); qr.add_data('test'); qr.make()` succeeds
- **Committed in:** `5c0cf2e` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking dependency)
**Impact on plan:** Essential for Task 1 — qrcode is the core library. No scope creep.

## Issues Encountered

None beyond the missing qrcode dependency resolved under Deviations.

## User Setup Required

None — no external service configuration required by this plan.

## Next Phase Readiness

- All 6 client lifecycle commands are fully implemented and verified
- `_reload_wireguard()` and `_extract_secret_str()` helpers are available for plan 04-03 (rotate-keys, rotate-server-keys)
- Vault state schema for clients (`private_key`, `public_key`, `psk`, `ip`, `config_hash`) is established
- IP pool `allocated` dict persisted in vault state and restored on each command

---
*Phase: 04-cli-and-client-management*
*Completed: 2026-03-20*
