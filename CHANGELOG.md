# Changelog

All notable changes to WireSeal are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.19] — 2026-04-25

### Fixed — "Switch mode" button silently flipped back to vault mode

- **Removed the misleading "Switch to Client" / "Switch to Server" sidebar
  buttons** from both `Layout.tsx` (server) and `ClientLayout.tsx` (client).
  They called `clearMode()` then `navigate(...)`, which cleared the
  localStorage mode hint. The next render saw `mode === null` so
  `ModeSelector` rendered. The user picked the OTHER mode → `setMode(...)`
  → next `probeVault()` re-synced from the vault → role flipped right back
  to the original. Result: clicking "Switch to Client" appeared to do
  nothing on a server vault, leaving users confused.
- **Server vs client roles are locked at vault init.** Switching requires
  Fresh-Start (Settings → Danger Zone → Fresh Start), which destroys the
  vault and lets the user re-init in the other mode. Sidebar Switch
  button removed entirely on both layouts so the action that can't
  succeed is no longer offered.

### Fixed — Windows tunnel auto-started after vault init

- **`enable_tunnel_service()` now stops the tunnel immediately after
  installing it.** `wireguard.exe /installtunnelservice` STARTS the
  service as a side effect — `sc.exe config start=demand` only affects
  *future* boots, not the current session. Newly-installed servers
  therefore had a running WireGuard tunnel before the user clicked Start
  on the dashboard. The fix issues `sc.exe stop` after install + config
  on the freshly-installed-only path, so the user's first interaction
  decides when the tunnel comes up. Linux + macOS were already correct
  (Linux `enable_tunnel_service` is a no-op; macOS writes the plist with
  `RunAtLoad=False` and never bootstraps).

---

## [0.7.18] — 2026-04-25

### Hardened — Client mode: stability + state reconciliation

The client side now survives API restarts, manual `wg-quick` invocations,
crashed config writes, and same-profile reconnects without UI lying.

- **`tunnel_status()` reconciles cache against the kernel.** Previously
  the dashboard trusted module-level `_state["connected"]` exclusively,
  so a restarted API process showed "Disconnected" even when the
  `wg-client` interface was still up. Now `wg show wg-client` is the
  source of truth — cache is updated to match. Same logic catches
  external `wg-quick down` (UI flips to disconnected) and external
  `wg-quick up` (UI adopts the tunnel).
- **`tunnel_down()` addresses the interface by name, not config path.**
  If the deployed `.conf` was wiped by a different process or system
  cleanup, `wg-quick down /etc/wireguard/wg-client.conf` would throw
  ENOENT. Now uses `wg-quick down wg-client`, which falls back to the
  canonical config path internally. Also tolerates "Cannot find device"
  / "No such device" stderr as a successful no-op so a
  partially-stopped tunnel can be cleared.
- **`tunnel_up()` allows same-profile reconnect.** Previously
  reconnecting to the same profile threw "Tunnel already active".
  Returns `status: "already-connected"` instead so the UI doesn't
  surface a spurious error on idempotent calls.
- **Atomic config write.** `_deploy_config()` writes to
  `wg-client.conf.tmp`, fsyncs, then renames. A disk-full or
  process-crash mid-write no longer leaves a half-written
  `wg-client.conf` for the next `wg-quick up` to choke on.

### Added — Client mode: handshake-failed signal

- **`tunnel_status()` now returns `handshake_ok: bool`.** True when the
  parsed `wg show` output reports a finite `latest handshake: … ago`
  string. False when the interface is up but no peer response has been
  received — the typical signature of an unreachable endpoint, wrong
  server key, or NAT/firewall blocking UDP.
- **Connect.tsx banner flips amber when handshake fails.** "VPN
  Connected" → "Tunnel up, no handshake" with hint "Check server
  reachability + key match." Catches the painful debug case where the
  tunnel claims to be up but no traffic flows.

### Added — Client mode: edit imported profile

- **`PUT /api/client/configs/<name>`** + Dashboard `api.clientUpdateConfig()`
  + Edit pencil button next to each profile. Use case: the server admin
  rotated keys or changed the WireGuard port. Client receives a fresh
  `.conf`, clicks Edit, pastes the new content, saves. Profile name
  stays the same; `imported_at` preserved; `updated_at` set to now.
- Validates the new config (Interface section + Peer + PrivateKey) and
  rejects a paste that still contains `<redacted>` for PrivateKey.
- Dispatcher gained a `do_PUT` method to dispatch the new route.

### Added — Cross-mode 409 enforcement on client endpoints

- Server vs client mode are mutually exclusive on a single device. The
  vault locks the role at init. Until now, only the server endpoints
  enforced this via `_require_server_mode()` — client endpoints were
  ungated, so a server-mode vault could call `/api/client/configs` and
  corrupt state. New `_require_client_mode()` helper applied to all 8
  client endpoints (`import`, `list`, `get`, `update`, `delete`,
  `tunnel up/down/status`).

---

## [0.7.17] — 2026-04-25

### Fixed — Linux systemd unit name

- **Renamed `wireseal-api.service` → `wireseal.service`.** Users who tried
  `sudo systemctl enable wireseal` got `Failed to enable unit: Unit file
  wireseal.service does not exist` because the unit was registered under
  `wireseal-api.service`. The new name matches the binary, so all four
  natural commands work without surprise:

      sudo systemctl start  wireseal
      sudo systemctl stop   wireseal
      sudo systemctl status wireseal
      sudo systemctl enable wireseal

- **Auto-migration on reinstall.** `_migrate_legacy_unit()` runs at the
  start of `install_api_service()` to stop, disable, and remove the legacy
  `wireseal-api.service` so users upgrading from v0.7.14-v0.7.16 don't end
  up with two units.
- **Uninstall handles both names.** `uninstall_api_service()` now stops +
  disables + removes both `wireseal.service` and `wireseal-api.service`.
- **Settings UI hint** — Background Service info panel now shows the new
  path and the four `systemctl` commands users can run manually.
- **`uninstall-linux.sh`** already handled both names — no change needed.

---

## [0.7.16] — 2026-04-25

### Fixed — Cross-platform parity for service install + uninstall

The v0.7.15 release patched the Windows service-install bug, but the same
issues existed on Linux and macOS. Brought every binary to parity:

- **Linux service install** — new `_find_wireseal_launcher()` resolves to
  `sys.executable` when frozen, `/usr/local/bin/wireseal` when wrapper
  installed, then any `wireseal` on PATH, and finally `python -m wireseal.main`.
  Replaces the previous hard-coded `/usr/local/bin/wireseal` fallback that
  pointed at a non-existent path inside PyInstaller frozen binaries.
- **macOS service install** — same launcher resolver as Linux, but emits
  `ProgramArguments` as a list (matches `plistlib` schema). Also handles
  `~/.local/bin/wireseal` for non-sudo installs.
- **Linux/macOS service start/stop** — previously used `check=True` which
  raised an opaque `CalledProcessError` with no detail. Now captures
  `systemctl` / `launchctl` stderr and raises `SetupError` with the exact
  exit code + error text — same shape as the Windows fix in v0.7.15.
- **launchctl bootstrap exit-37 tolerance** — `launchctl bootstrap` returns
  exit 37 when the daemon is already loaded (idempotent reinstall). No
  longer treated as fatal.
- **launchctl kill graceful** — exit nonzero with "Could not find service"
  is treated as already-stopped (idempotent stop).
- **`POST /api/uninstall` script discovery** — added 3-tier resolution:
  (1) `WIRESEAL_SCRIPTS_DIR` env override, (2) PyInstaller `_MEIPASS/scripts`,
  (3) source `<repo>/scripts`. Frozen binaries can now actually find the
  bundled uninstall scripts.
- **PyInstaller spec files** — `wireseal.spec` and `wireseal-cli.spec` now
  bundle `scripts/` into `_MEIPASS/scripts`, otherwise the frozen binary
  ships without the platform uninstall scripts.

---

## [0.7.15] — 2026-04-25

### Fixed — Change Port dialog overflow

- The dialog grew tall enough on small viewports that the Apply / Cancel
  buttons were pushed off screen and the user could not close the popup
  at all. Restructured to `max-h-[90vh]` flex column with sticky header
  (X close button), scrollable body, and sticky footer pinned to the
  bottom — Apply + Cancel always visible. Click outside the dialog also
  dismisses now.

### Fixed — Add Service on Windows

- `install_api_service()` previously called `wireseal.cmd` via Task
  Scheduler under SYSTEM, which silently failed because Task Scheduler
  is unreliable invoking `.cmd` shims. New `_find_wireseal_launcher()`
  picks the right entry point: PyInstaller-frozen → `sys.executable`,
  venv → `Scripts\wireseal.exe`, fallback → `python.exe -m wireseal.main`.
- `install_api_service` and `start_api_service` now capture schtasks
  stderr and raise `SetupError` with the exact exit code + error text
  instead of an opaque `CalledProcessError`.

### Added — Run-uninstall-now from the dashboard

- New `POST /api/uninstall` — requires unlocked vault + `confirm:
  "UNINSTALL"` body literal. Spawns `scripts/uninstall-{linux,macos,windows}.{sh,ps1}`
  detached (`DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP` on Windows,
  `start_new_session` on Unix), then exits the API process ~2 s after
  responding so the HTTP 200 lands first and the uninstall script can
  clean up files this process held open.
- **Settings → Uninstall dialog now actually uninstalls.** Previously
  the dialog only displayed copy-paste commands. New red "Uninstall
  (keep vault) / Uninstall + Purge Vault" button alongside the manual
  commands. Purge checkbox toggles `--purge` / `-Purge`. Network
  failure after the click is treated as success because the server is
  intentionally shutting down.
- Dashboard `api.uninstall(purge: boolean)` wrapper added.

---

## [0.7.14] — 2026-04-24

### Added — Background-service registration (all platforms)

- **WireSeal API server can now run as an OS-managed background service**,
  surviving terminal close and (optionally) starting at boot. Per-platform
  implementation:
  - **Linux** — writes `/etc/systemd/system/wireseal-api.service`
    (`Type=simple`, `Restart=on-failure`, `User=root`, `NoNewPrivileges`,
    `ProtectSystem=full`, `ProtectHome=yes`, `PrivateTmp=yes`). Uses
    `systemctl daemon-reload` and `systemctl enable` for auto-start.
  - **macOS** — writes `/Library/LaunchDaemons/com.wireseal.api.plist`
    (`RunAtLoad=true`, `KeepAlive=true`, stdout/err in `/var/log/`). Uses
    `launchctl bootout` before `bootstrap` only when content changed
    (avoids spurious reloads).
  - **Windows** — registers Scheduled Task `WireSeal-API` (`/SC ONSTART
    /RU SYSTEM /RL HIGHEST`). Avoids `sc.exe create` because Python click
    doesn't natively respond to SCM control messages — Task Scheduler
    runs the same `wireseal serve` binary at boot under SYSTEM with the
    same effective privileges.
- **CLI sub-group `wireseal service`** — `install`, `uninstall`, `start`,
  `stop`, `status`. The `install` command accepts `--bind`, `--port`,
  `--no-autostart`. `status` prints `installed / running / enabled`
  with green/red checkmarks.
- **Five HTTP endpoints** (vault-unlock-gated):
  `GET /api/service/status`, `POST /api/service/install`,
  `POST /api/service/uninstall`, `POST /api/service/start`,
  `POST /api/service/stop`. Audit-logged as `service-install` /
  `service-uninstall`.
- **Settings → Background Service card** — three indicator pills
  (Registered, Auto-start, Running) backed by 60-second polling +
  manual Refresh button. Install button when not installed; Start /
  Stop + Uninstall pair when installed. Includes an info panel showing
  on-disk paths per OS (`/etc/systemd/system/...`, `/Library/.../com.wireseal.api.plist`,
  `Task Scheduler: WireSeal-API`).
- **Uninstall scripts now drop the API service**:
  - `scripts/uninstall-linux.sh` — adds `wireseal-api.service` to the
    `systemctl stop / disable` loop and to the unit-removal list.
  - `scripts/uninstall-macos.sh` — `launchctl bootout
    system/com.wireseal.api` + `rm /Library/LaunchDaemons/com.wireseal.api.plist`.
  - `scripts/uninstall-windows.ps1` — `schtasks /End` + `/Delete /F /TN
    WireSeal-API`.

### Added — Port policy (blocklist + warn-list + recommended)

- **`_validate_wg_port()`** classifies every port pick into BLOCK / WARN /
  OK. Wired into `/api/init` AND `/api/change-port` so bad ports are caught
  before any disk or network side effect.
- **Blocklist (rejected with 400):** UDP ports for DNS (53), DHCP (67/68),
  TFTP (69), NTP (123), NetBIOS (137/138), SNMP (161/162), IKE (500),
  syslog (514), RIP (520), SSDP/UPnP (1900), mDNS (5353), LLMNR (5355),
  plus port 0. Picking these would break the host or collide with critical
  services on at least one of Linux/macOS/Windows defaults.
- **Warn-list (require `confirm_warning: true`):** UDP/443 (QUIC),
  UDP/4500 (IPsec NAT-T), UDP/3389 (RDP UDP transport), UDP/8080. Plus the
  privileged range 1-1023. The dashboard surfaces the warning and offers
  an **"Apply anyway"** button that resubmits with the override flag.
- **OK by default:** anything 1024-65535 not on either list. WireGuard's
  default 51820 lands here clean.
- **`GET /api/port-policy`** — public endpoint (no unlock needed) that
  returns `{default, min, max, privileged_max, blocked, warnings,
  recommended}` so the UI can colour-code the input field and show the
  full block/warn lists in a `<details>` panel.
- **Settings → Change Port dialog now shows:**
  - Recommended-port quick-pick chips (51820, 51821, 51822, 4500, 443).
  - Collapsible "Port restrictions" section listing every blocked + flagged
    port with the reason.
  - Orange "Port flagged by policy" callout when the backend returns a
    400 with a warning, plus "Apply anyway" submit that forwards
    `confirm_warning: true`.
- **TCP-only services (22 SSH, 80 HTTP, 25 SMTP, 110 POP3, 3306 MySQL,
  6379 Redis…) are deliberately NOT blocked** — WireGuard is UDP, so the
  OS hosts both transports on the same port number without conflict. The
  only WireGuard-relevant restrictions are UDP services.

### Hardened — Port + endpoint change handlers

- **Pre-render before vault write.** `_h_change_port` now builds the new
  `wg0.conf` *before* committing the new port to the vault. If the render
  fails (missing keys, malformed subnet, builder bug) the request returns
  500 with the vault untouched — no half-applied state.
- **Bug fix:** `_h_change_port` previously read `state.server["server_ip"]`,
  which doesn't exist (the canonical key is `state.server["ip"]`). Every
  port-change call would have raised `KeyError` at runtime. Fixed.
- **Stricter endpoint validation.** `_validate_endpoint()` now rejects URL
  schemes (`http://`, `ftp://`), control characters, whitespace inside
  hostnames, over-long inputs (>255 chars), and out-of-range ports
  (`host:0`, `host:99999`). Accepts IPv4, bracketed IPv6, hostname/FQDN,
  with optional `:port` suffix.
- **Audit-log failures never block a successful response** — wrapped in
  try/except so a read-only-FS audit log can't roll back a port change.
- **Catch-all around vault open/save** so a decrypt error returns 500 with
  a clean message instead of leaking a stack trace.

### Added — Live port change (post-init)

- **`POST /api/change-port`** — full port reconciliation pipeline. Validates
  range (1–65535), refuses no-op, then: (1) reads peers + keys from the
  vault, (2) **pre-renders the new wg0.conf with the new `ListenPort` and
  aborts with 500 if render fails (vault untouched)**, (3) commits the new
  port to the vault, (4) deploys the rendered config via the platform
  adapter, (5) calls `apply_firewall_rules(new_port, ...)` so the platform
  code drops the old `wireseal-wg0-in` rule and opens the new one —
  `nftables` on Linux, `pfctl` on macOS, `netsh advfirewall` on Windows —
  (6) re-opens the firewalld zone where applicable, (7) restarts the
  tunnel via `_reload_wireguard()`. Steps 4-7 capture failures as non-fatal
  warnings so a partial reconciliation still leaves the vault consistent
  for the next `wireseal serve`. Audit-logged as `change-port` with old +
  new values + warnings.
- **Settings → Server Settings → "Change Port" button.** Modal accepts
  numeric input, shows the background steps (firewall reconcile, config
  re-render, tunnel restart) and a yellow callout that existing peers
  cache the endpoint and must re-scan QR codes after the change.
- **`/api/update-endpoint` now refuses in client-mode vaults** via
  `_require_server_mode()` — previously it would silently mutate
  `state.server` on a vault that has no server keypair.
- Dashboard `api.changePort(port: number)` client wrapper added to
  `Dashboard/src/app/api.ts`.

### Added — User-chosen port + endpoint at vault init

- **Init dialog now exposes Subnet, WireGuard Port, and Endpoint Source.**
  The backend has always accepted `subnet`, `port`, and `endpoint` on
  `POST /api/init`, but the dashboard only sent `mode` — leaving every
  install on UDP 51820 + auto-detected public IPv4. The setup form now
  surfaces all three so users running multiple WireSeal servers (one per
  device, behind the same NAT/account) can pick non-overlapping ports.
- **Endpoint preset dropdown (10 sources):** auto-detect public IPv4
  (recommended), manual IPv4, manual hostname/FQDN, DuckDNS, No-IP /
  Dynu / FreeDNS, Cloudflare DDNS, LAN IPv4 (LAN-only VPN), public IPv6,
  Tailscale IPv4, or fully custom `host[:port]`. Auto presets leave the
  endpoint blank so the backend resolver fills it in; manual presets
  pre-fill a placeholder and require user input. Validation is
  client-side first (CIDR format, port 1–65535) with backend re-validation.
- **Stripped pre-emptive UDP 51820 firewall rule from
  `install-windows.ps1`.** Previously the installer hardcoded a
  `WireSeal-WireGuard-UDP-51820` rule before the user picked a port, so a
  custom port left UDP 51820 open *and* required a second rule. Firewall
  management is now owned exclusively by the platform adapter
  (`platform/windows.py:apply_firewall_rules`), which reads the chosen
  port from the unlocked vault and reconciles `wireseal-wg0-in` at every
  `wireseal init` / `wireseal serve`.

### Fixed — Client config download

- **`Download config` button now works inside pywebview/WebView2.**
  Previously the dashboard called `window.open(/api/clients/<n>/config/download)`,
  which on Windows + WebView2 opened a blank popup and dropped the
  `Content-Disposition: attachment` response. The handler now `fetch()`es the
  config in the current document, wraps it in a Blob URL, and triggers a
  synthetic `<a download>` click — matching the native browser save flow on
  every platform.

### Added — Uninstall flow (all platforms)

- **`scripts/uninstall-linux.sh`** — removes `/usr/local/bin/wireseal`, the
  virtualenv, the systemd units (`wireseal.service`, `wireseal-dns.service`),
  the `wireseal` nftables table, and the `wireseal` sudoers drop-in. Stops the
  tunnel via `wg-quick down wg0` first. `--purge` also deletes
  `~/.config/wireseal`.
- **`scripts/uninstall-macos.sh`** — removes both system + user wrappers, the
  virtualenv, the `com.wireseal.dns` launchd plist (via `launchctl bootout`
  before deletion), and flushes the `wireseal` pf anchor. `--purge` also
  deletes `~/Library/Application Support/WireSeal`.
- **`scripts/uninstall-windows.ps1`** — stops + removes the
  `WireGuardTunnel$wg0` service (via `wireguard.exe /uninstalltunnelservice`
  when the .conf is found), drops the firewall rule, removes the install dir,
  the virtualenv, and the `C:\Program Files\WireSeal` PATH entry. `-Purge`
  also deletes `%APPDATA%\WireSeal`.
- **Reinstall detection in install scripts** — running `install-linux.sh`,
  `install-macos.sh`, or `install-windows.ps1` against an existing install
  now detects the prior version and prompts `[r]einstall / [u]ninstall /
  [c]ancel`. The installers also accept `--uninstall` (Linux/macOS) or
  `-Uninstall` (Windows) as a passthrough so users have a single discoverable
  entry point.
- **`wireseal uninstall` CLI command** — auto-detects the platform and
  shells out to the matching uninstall script. Accepts `--purge` and
  `--yes/-y`. Falls back to a clear error message when run from a frozen
  PyInstaller binary (where the script tree is absent).
- **Settings → Danger Zone → "Uninstall WireSeal" button** — opens an
  instructions dialog with OS-detected, copy-to-clipboard commands. By design
  the dialog never auto-executes the uninstall: it would have to terminate
  the dashboard server it is running inside, and admin/sudo can't be
  delegated from the browser context safely.

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
