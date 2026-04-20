# Changelog

All notable changes to WireSeal are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.9] — 2026-04-20

### Security — Production-readiness hardening

- **API brute-force protection** (`/api/unlock`): per-IP sliding-window rate limit
  (5 attempts / 5 minutes). Exceeding the window returns HTTP 429 and logs an
  `unlock-ratelimited` audit entry. Successful unlock clears the counter.
- **Audit log rotation + tamper evidence**: logs rotate at 10 MiB (keeping
  `audit.log.1`..`.5`) with 0o640 enforced after each rotation. Every entry
  now carries `prev_hash` / `chain_hash` (SHA-256) anchored to a genesis
  constant — the new `verify_chain()` detects truncation, reordering, and
  in-place edits. `get_recent_entries(n)` walks rotated files when the
  current log is shorter than *n*.
- **Graceful shutdown**: the API server now installs SIGTERM + SIGHUP + atexit
  handlers that wipe the in-memory passphrase, close the HTTP socket, flush
  the audit log with a `shutdown` entry, and exit cleanly. Double-fire is
  guarded with a `_cleaned_up` flag.
- **Session timeout (auto-lock)**: after `_SESSION_TIMEOUT` (15 minutes) of
  inactivity, a daemon thread wipes the vault passphrase and logs an
  `auto-lock` audit entry. Every authenticated request refreshes the idle
  clock.

### Added

- **`GET /api/health`** — no-auth, O(1) monitoring endpoint returning
  `{status, vault_initialized, vault_locked, uptime_seconds}`. Suitable for
  Docker `HEALTHCHECK`, systemd watchdogs, and uptime services.
- **`POST /api/clients/<name>/rotate`** and **`POST /api/rotate-server-keys`** —
  key rotation now reachable from the dashboard, not just the CLI. Both
  endpoints require an unlocked vault, audit-log the action, and return the
  refreshed config (with QR for client rotation).
- **`wireseal backup-vault <dest>`** and **`wireseal restore-vault <src>`** —
  new CLI commands. Backup verifies the passphrase before copying (0o600 on
  Unix). Restore verifies the passphrase against the source file and prompts
  before overwriting an existing vault. Both audit-log the operation.
- **Vault mode propagation to the dashboard**: `GET /api/vault-info` now
  exposes `mode: "server" | "client" | null`. The dashboard syncs with the
  vault's reported mode after unlock, preventing a stale `localStorage`
  value from showing the wrong UI when the underlying vault is the other
  mode.
- **Mode-aware polling in the dashboard**: `/api/status` (which runs
  `wg show`) and admin-session polling now only run in server mode. Client
  mode no longer wastes cycles probing a WireGuard server it doesn't manage.

### Fixed

- **CI pipeline**: `pip-audit` in the workflow now ignores
  `CVE-2025-71176` (pytest 8.4.2, dev-only, fix in 9.x which is incompatible
  with our plugin matrix) alongside the existing pygments exception.

### Tests

- 299 tests pass / 2 platform-skipped / 0 failed locally (Python 3.12 & 3.14).
- New coverage for all seven hardening phases: rate limit, audit rotation,
  backup/restore CLI, shutdown path, health endpoint, session timeout, and
  rotation API.

---

## [0.7.8] — 2026-04-19

### Security — MEDIUM / LOW audit findings (SEC-011 through SEC-027)

- **SEC-011** `wipe_string`: now refuses empty, non-ASCII, and interned
  strings (returns `False` instead of silently corrupting the interpreter).
- **SEC-012** `SecretBytes.__bytes__` raises `TypeError` — callers must use
  `expose_secret()` for a zero-copy view or `to_bytearray()` for a
  wipe-capable copy.
- **SEC-013** Unlock: reject unknown `admin_id` values rather than silently
  granting `owner` role to fabricated IDs.
- **SEC-014 / SEC-023** PIN attempts are now tracked per-IP, and the
  check-then-act is atomic under a single lock.
- **SEC-015** Heartbeat authenticates via a per-client bearer token
  (`X-WireSeal-Heartbeat`).
- **SEC-016** `/api/init` serialised — the exists+create pair is atomic.
- **SEC-017** `webdav_pass` and all `*_password` vault fields are wrapped
  as `SecretBytes`.
- **SEC-019** Argon2 header parameters validated before derivation (rejects
  attacker-weakened or DoS-sized values).
- **SEC-020** WireGuard private keys are no longer returned from
  `/api/clients/<name>/config` by default.
- **SEC-021** `SshTicket.password` is a `SecretBytes` and is wiped when the
  ticket is consumed or expires.
- **SEC-022** Static file serving is sandboxed to the bundled `dist`
  directory via `Path.resolve().relative_to(...)`.
- **SEC-024 / SEC-026** `/api/remove-pin` and `/api/update-check` require
  an unlocked vault.
- **SEC-025** Audit log entries now include `prev_hash` / `chain_hash`.
- **SEC-027** Backup destinations are checked against a system-directory
  blocklist.

### Added

- 24 new dedicated tests (`tests/security/test_medium_low_fixes.py`) that
  each link back to the SEC-xxx id they exercise.

---

## [0.7.7] — earlier

- Explicit WireGuard tunnel start/stop controls.

## [0.7.6] — earlier

- SSH terminal in the browser via the WebSocket bridge.

## [0.7.0] — earlier

- Zero-Trust Network Access (ZTNA) foundation: multi-admin vault, TOTP 2FA,
  ephemeral keys, split-DNS, local backup.

---

*Earlier versions — see `git log` for the full history.*
