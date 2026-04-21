# Changelog

All notable changes to WireSeal are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.13] — 2026-04-21

### Added — Windows installer auto-upgrade

- **Auto-detect previous install and upgrade in place.** The NSIS installer
  now reads `DisplayVersion` from the Add/Remove Programs registry key:
  - Same version already installed → prompts "repair / reinstall or cancel".
  - Different version installed → prompts "upgrade from X.X.X to Y.Y.Y?"
    and, on confirm, silently runs the previous uninstaller via
    `/S _?=<InstallLocation>` before proceeding.
  - No previous install → fresh install as before.
- **User data preserved on upgrade.** The uninstaller never touches
  `%APPDATA%\WireSeal`, so your vault, client configs, and settings survive
  the upgrade.
- **Residual-file cleanup.** After the silent uninstaller finishes it leaves
  `uninstall.exe` behind (expected with `_?=`); the new installer deletes
  it plus any stale `_internal\` / `bin\` trees before writing the fresh
  install.
- **Finish page "View Guide" link.** Checkbox on the final installer page
  opens the GitHub README in the default browser, alongside the existing
  "Launch WireSeal" option. A direct link to the current release notes is
  also shown on the finish page.

---

## [0.7.12] — 2026-04-20

### Fixed — Upgrade migration from v0.7.10 and below

- **Windows `sc.exe` tunnel services migrated to manual-start on upgrade**:
  v0.7.10 and earlier registered `WireGuardTunnel$wg0` with `start=auto`.
  v0.7.11 only changed the *new-install* path, so existing installs kept
  autostarting. `serve()` now reconciles the service to `start=demand` on
  every startup, stopping the tunnel if it was running under the old
  registration.
- **Windows firewall rules reconcile when `WG_PORT` changes**: the old
  idempotency short-circuit skipped re-apply if *any* `wireseal-wg0-in`
  rule existed. `netsh` output is now parsed for `LocalPort:` and the rule
  is rebuilt when the port differs.
- **macOS launchd DNS plist reloads when content changes**: `launchctl
  bootstrap` silently ignores new settings on an already-loaded service.
  `setup_dns_updater` now diffs the plist bytes and runs `launchctl bootout
  system/com.wireseal.dns` before bootstrap when content differs.
- **macOS pf anchor rebuilds on subnet/port change**: the old idempotency
  check returned early as long as *any* rules existed in the anchor. Now
  the check verifies the anchor contains the current subnet, port, and
  outbound interface — otherwise flushes and reapplies.

### Fixed — Dashboard UI

- **Security page "Harden Server" button hidden on Windows**: the button
  and the "IP forwarding is off" warning were visible on Windows where
  neither applies (Linux-only features). Both are now gated on
  `status.checks.length > 0`.
- **Backup page password field + config gating**: added a write-only WebDAV
  password input (the backend already accepted it). Also disables the
  "Trigger Backup Now" button when backup is not enabled in the config —
  previously clicking it returned a generic 400, confusing users.
- **Backup local-path placeholder is OS-aware**: shows
  `C:\ProgramData\WireSeal\backups` on Windows instead of the Linux-style
  `/var/backups/wireseal`.
- **Admins self-removal guard fixed**: `currentAdminId` was read from a
  nonexistent method on the `api` module and always returned `"owner"`,
  defeating the "Cannot remove yourself" guard for any non-owner admin.
  The `api` module now tracks `admin_id` from the last successful `unlock`
  and exposes `api.getCurrentAdminId()`; cleared on `lock` and on any 401.
- **Start Server poll loop reads fresh status**: the poll loop in
  `handleStart` closed over the React `status` state and never saw
  post-refetch updates. It now reads from the module-level `_statusCache`.

---

## [0.7.11] — 2026-04-20

### Fixed — Windows user-reported bugs

- **Autostart-on-boot removed (all platforms)**: installing the tunnel service
  previously registered it with `start=auto` on Windows, `systemctl enable` on
  Linux, and `RunAtLoad=true` on macOS — meaning the VPN came up automatically
  after every reboot. Now registration is manual-only (`start=demand` / no
  enable / `RunAtLoad=false`); the user controls lifecycle via the Dashboard
  Start/Stop buttons.
- **Windows Start button no longer re-installs the service on every click**:
  previously every click of Start invoked `wireguard.exe /installtunnelservice`,
  which re-ran the DPAPI encryption cycle. Start now detects an already-
  registered service and issues `sc.exe start` directly. ERROR 1056 (already
  running) is treated as success.
- **Windows Stop button keeps the service registered**: previously Stop ran
  `wireguard.exe /uninstalltunnelservice` after `sc.exe stop`, destroying the
  service so the next Start had to re-install it. Now Stop only issues
  `sc.exe stop` — service stays in `start=demand` mode for the next Start.

### Fixed — DNS tab

- **Console window flash on Windows**: `DnsmasqManager.is_available()` spawned
  `where.exe dnsmasq` on Windows, which briefly flashed a cmd console. The
  check now short-circuits to `False` on Windows and uses `CREATE_NO_WINDOW`
  for all other subprocess calls.
- **OS-aware "dnsmasq not found" banner**: Windows doesn't have dnsmasq (not a
  bug, design). The warning is replaced on Windows with an informational blue
  banner explaining that DNS is pushed via WireGuard's `DNS` directive and
  pointing to Linux/macOS for a dedicated split-DNS resolver.
- **API response includes `platform`** for the Dashboard to render OS-aware UI.

### Fixed — Security tab

- **Windows `harden_server` now wires in IP forwarding**: sets
  `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter=1`
  (reboot required to take effect) and best-effort starts the `RemoteAccess`
  service to honor it without a reboot.
- **Windows `harden_server` now installs OpenSSH Server if missing**:
  `Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'`, configures
  startup type Automatic, and starts the `sshd` service before attempting to
  harden `sshd_config`.

---

## [0.7.10] — 2026-04-20

### Fixed

- **Backup destination blocklist on macOS**: `/etc`, `/var`, `/tmp` are firmlinks
  to `/private/etc`, `/private/var`, `/private/tmp` on macOS, and
  `Path.resolve()` returns the canonical `/private/*` form. The SEC-027
  system-directory guard only listed the short form, so resolved paths slipped
  past the check and reached `mkdir()` — which then raised `PermissionError`
  instead of the expected `ValueError("system directory")`. Added the three
  `/private/*` canonical forms to `_UNIX_BLOCKED_ROOTS`. Fixes macOS CI job in
  `release.yml`.
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
