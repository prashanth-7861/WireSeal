# WireSeal — New Features Plan

Detailed implementation plan for 7 competitive features identified from market
research (wg-easy, wg-portal, Defguard, Firezone, NetBird/Tailscale). Each item
is grounded in the current codebase with concrete file paths, data models, API
contracts, platform handling, tests, and acceptance criteria.

Baseline at time of writing: **v0.9.49**.

---

## Architecture recap (shared building blocks)

These existing patterns are reused throughout the plan — do not reinvent them.

| Concern | Where | Notes |
|---------|-------|-------|
| API route table | `src/wireseal/api/__init__.py` `_ROUTES` | regex-dispatch tuples `(METHOD, re, handler)`; handlers auto-globbed from submodules |
| API handlers | `src/wireseal/api/<area>.py` | `_h_*` funcs; `from . import _shared as _mod` glob trick |
| Auth gates | `_require_unlocked()`, `_require_admin_role()` | in `_shared.py`, available via glob |
| Request body / query | `req._json()`, `urlsplit(getattr(req,"path",""))` | type-guard non-str path (see audit fix) |
| Vault read/write | `vault.open(passphrase, admin_id=...) as state` → `state.data[...]` → `vault.save(state, passphrase)` then `_refresh_cache_unlocked(...)` | session cache in `_session["cache"]` |
| Clients store | `cache["clients"][name]` | fields: pubkey, ip, `permanent`, `ttl_seconds`, `ttl_expires_at`, heartbeat token |
| WG iface | `_WG_IFACE` (`_shared.py:199`) | |
| `wg show` plumbing | `_shared.py:1709` `_resolve_wg_tool("wg")` + `_sudo([...])` | already used by `/api/status`; reuse for dump parse |
| nftables | `platform/linux.py` tables `ip wg_postup_nat`, `inet wg_forward` (forward chain, policy accept) | ACL drop rules slot into `wg_forward` |
| dnsmasq | `dns/dnsmasq.py` `DnsmasqManager` (`write_config`, `reload`, `is_available`) | DNS mappings in `cache["dns_mappings"]` |
| Scheduler pattern | `backup/scheduler.py` (cron/schtasks + 0600 env file) | reuse shape for periodic sweeps |
| Audit | `AuditLog(_s._AUDIT_PATH).log(action, metadata)` | hash-chained; emit events for every new mutation |
| Frontend fetch | `Dashboard/src/app/api.ts` `_fetch<T>(method, path, body?)` | |
| Server nav | `Dashboard/src/app/components/Layout.tsx` + `routes.tsx` | add new pages here |
| Platform adapters | `platform/{linux,macos,windows}.py` + abstract `base.py` | add capability methods; gate per-OS |

**Version mapping (proposed):** Feature 1 → v0.9.50, Feature 3+4 → v0.9.51,
Feature 2 → v0.9.52, Feature 5 → v0.9.53, Feature 6 → v0.9.54, Feature 7 →
folded into 0.9.5x polish. Ship vertically; each feature is independently
releasable.

---

## Feature 1 — Live per-peer WireGuard stats ⭐

**Value:** wg-easy's headline feature; WireSeal currently shows configured
clients but not their live link state. Turns the Clients page from a config list
into a live dashboard.

**User story:** As an admin I open Clients and see, per client, an online/offline
dot, last handshake ("2m ago"), data up/down, and current endpoint IP — refreshing
live.

### Backend
- **New parser** `src/wireseal/core/wg_stats.py`:
  - `parse_wg_dump(text: str) -> dict[str, PeerStat]` keyed by **public key**.
  - Source: `wg show <iface> dump` (tab-separated: pubkey, psk, endpoint,
    allowed-ips, latest-handshake (unix), rx, tx, keepalive).
  - `@dataclass PeerStat`: `public_key, endpoint, latest_handshake:int,
    rx_bytes:int, tx_bytes:int, online:bool` (online = handshake within 180s).
- **Reuse** `_resolve_wg_tool("wg")` + `_sudo(...)` from `_shared.py` to run
  `wg show <iface> dump`. Windows server: `wg.exe show` (already resolved); if
  unavailable return empty stats (graceful).
- **Handler** `_h_clients_stats` in `api/clients.py`:
  - `GET /api/clients/stats` → `{ "peers": { name: PeerStat-dict }, "iface": ..., "available": bool }`.
  - Map dump pubkey → client name via `cache["clients"]` (each client stores its
    pubkey). `_require_unlocked()`.
  - Cheap: no vault write, just a subprocess + parse. Safe to poll.
- **Route** in `__init__.py`: `("GET", r"^/api/clients/stats$", _h_clients_stats)`
  (place before `^/api/clients/<name>$` so it doesn't get captured as a name).

### Frontend
- `api.ts`: `PeerStat` interface + `clientsStats()`; extend nothing else.
- `Clients.tsx` (789 lines): add columns/badges — online dot (green/grey),
  "last handshake" relative time, up/down via existing `formatBytes`, endpoint.
- **Live polling**: `setInterval` 5s while page mounted + tab visible
  (`document.visibilityState`), cleared on unmount. Reuse the Network page's
  module-cache pattern to avoid flash.
- Optional **sparkline**: keep a ring buffer of last N samples per client in
  component state; render a tiny inline transfer-rate graph (delta bytes / delta
  t). No new dep — small SVG polyline.

### Edge cases
- Client configured but never connected → handshake 0 → "never", offline.
- Stat pubkey with no matching client (stale peer) → list under "Unknown peer".
- Non-Linux server / `wg` missing → `available:false`, hide live columns with a
  one-line note.

### Tests
- `tests/core/test_wg_stats.py`: parse a known `wg show dump` fixture (multi-peer,
  handshake=0 case, IPv6 endpoint), assert online threshold, byte parsing.

**Effort:** ~1 day. **Risk:** low (read-only). **Acceptance:** online/last-handshake/
up-down/endpoint render live and match `wg show` on the server.

---

## Feature 2 — Per-client ACLs (resource access control)

**Value:** Defguard/Firezone's differentiator WireSeal lacks. Restrict which LAN
resources each client may reach. Pairs naturally with existing Network discovery
("client Phone → only 10.0.0.10:32400").

**User story:** As an admin I open a client, choose "Restricted" mode, and allow
only specific destinations (IP, CIDR, or host:port). All else is dropped.

### Data model (vault)
Extend each `cache["clients"][name]` with:
```jsonc
"acl": {
  "mode": "allow_all" | "restricted",   // default allow_all (back-compat)
  "rules": [ { "dest": "10.0.0.10", "port": 32400, "proto": "tcp|udp|any" } ]
}
```

### Backend
- **New module** `src/wireseal/core/acl.py`:
  - Validate rules (reuse `security/validator` + `ipaddress`; reject non-LAN/
    public per policy; cap rule count).
  - `build_nft_rules(clients) -> str`: generate `inet wg_forward` rules. For each
    restricted client, match `ip saddr <client_wg_ip>` → `accept` listed
    destinations, then `drop` remaining from that saddr. Allow-all clients
    untouched. Established/related accepted first.
- **Platform method** `apply_client_acls(ruleset: str)` on adapters:
  - **Linux**: write `/etc/wireseal/wg_acl.nft`, `nft -f` into a dedicated
    `inet wg_acl` table (separate from `wg_forward` so we can flush/replace
    atomically); include from the managed nftables.d include (reuse
    `_ensure_nftables_conf_includes`). Idempotent: flush table then re-add.
  - **macOS**: pf anchor `wireseal/acl` (reuse existing pf anchor pattern).
  - **Windows**: not supported as server router → return capability=false; UI
    shows "ACLs require Linux/macOS server".
- **Handlers** in new `api/acl.py` (or extend `clients.py`):
  - `GET /api/clients/<name>/acl`, `PUT /api/clients/<name>/acl`
    (`_require_admin_role()` — mutates firewall + access).
  - On save: vault write → rebuild full ruleset → `apply_client_acls` → audit
    `acl-update` (actor, client, rule count). Graceful warning if apply fails
    (like backup `schedule_warning`).
- Re-apply ACLs on server start / config deploy (hook into existing
  config-deploy path so rules survive reboot — mirror NAT auto-inject).

### Frontend
- New component `components/clients/ClientAclEditor.tsx` (drawer/dialog): mode
  toggle, rule rows (dest autocompletes from **Network discovery** devices +
  their scanned ports — strong UX synergy), add/remove, save.
- `Clients.tsx`: per-row "Access" badge (Open / Restricted N rules) → opens editor.
- `api.ts`: `getClientAcl`, `setClientAcl`, `ClientAcl` types.

### Edge cases
- Client with no WG IP yet → block save with message.
- ACL referencing a device that later changes IP (DHCP) → document; recommend DNS
  mapping or static lease. Future: bind ACL to MAC via discovery.
- Forward chain currently `policy accept` — ACL table must DROP explicitly per
  saddr; never change global policy (avoid locking out everyone).

### Tests
- `tests/core/test_acl.py`: rule validation, nft ruleset generation snapshot,
  allow-all clients excluded, injection-safe dest/port.

**Effort:** ~3–4 days. **Risk:** medium-high (firewall — bad rules can break
connectivity). **Mitigations:** dedicated flushable table, dry-run validate,
never touch global policy, audit every change, "test from this client" hint.
**Acceptance:** restricted client reaches only listed dest:port; everything else
times out; allow-all clients unaffected; survives reboot.

---

## Feature 3 — Notifications (ntfy / webhook / email)

**Value:** Today only local tray notify. Home users want "someone connected"
alerts and failure pings. Also the delivery layer for Features 4/7 and audit.

**User story:** As an admin I add an ntfy topic (or webhook/SMTP) and pick which
events notify me; I get a push when a new client connects or an unlock fails.

### Config (vault) — `cache["notifications"]`
```jsonc
{
  "enabled": true,
  "channels": {
    "ntfy":    { "enabled": true, "url": "https://ntfy.sh", "topic": "...", "token": "" },
    "webhook": { "enabled": false, "url": "https://..." },        // JSON POST
    "smtp":    { "enabled": false, "host": "", "port": 587, "user": "", "pass": "", "from": "", "to": "" }
  },
  "events": { "client_connect": true, "unlock_failed": true, "backup_done": true,
              "backup_failed": true, "ttl_expiring": true, "tamper_detected": true }
}
```
Secrets (token/pass) handled like `webdav_pass`: kept in vault; never logged;
scrubbed in audit; redacted in API GET responses.

### Backend
- **New module** `src/wireseal/notify/dispatch.py`:
  - `notify(event: str, title: str, body: str, priority="default")` → fan-out to
    enabled channels for which `events[event]` is true.
  - **ntfy**: HTTP POST to `<url>/<topic>` (title header, optional auth). stdlib
    `urllib` (no new dep). SSRF guard reuse from `backup/manager._validate_webdav_url`.
  - **webhook**: JSON POST `{event, title, body, ts}`; SSRF-guarded; HMAC-sign
    with a per-install secret header for verification.
  - **email**: stdlib `smtplib` + `ssl`; STARTTLS; timeouts.
  - All best-effort, bounded timeouts, swallow+log failures (never break the
    triggering action).
- **Event emission points** (call `notify(...)` alongside existing audit logs):
  - `client_connect`: in the heartbeat/first-handshake path (`api/clients.py`
    heartbeat handler) — debounce per client (don't spam every heartbeat; fire on
    offline→online transition using Feature 1 stats or a `last_notified` stamp).
  - `unlock_failed`: in unlock handler (`_shared.py` unlock path, already audits
    `unlock-failed`).
  - `backup_done`/`backup_failed`: in `api/backup.py` trigger + `wireseal backup`
    CLI.
  - `ttl_expiring`: from Feature 7 sweep.
  - `tamper_detected`: when `verify_chain()` fails (run on a schedule / on audit
    page load server-side).
- **Handlers** `api/notify.py`: `GET/POST /api/notifications/config`,
  `POST /api/notifications/test` (send a test message). `_require_admin_role()`
  for config; redact secrets in GET.

### Frontend
- New page `pages/Notifications.tsx` + nav entry: channel cards (enable, fields,
  Test button), event checklist grid. Reuse Backup page's secret-field handling
  (don't echo stored secret; only send on change).
- `api.ts`: `NotificationConfig` types + methods.

### Tests
- `tests/notify/test_dispatch.py`: channel selection by event flag, ntfy/webhook
  payload shape (monkeypatch urlopen), SSRF rejection, secret redaction in config
  GET, SMTP message build.

**Effort:** ~2 days. **Risk:** low-medium (outbound HTTP/SMTP — SSRF + secret
handling). **Acceptance:** Test button delivers to each enabled channel; real
events fire once per transition; secrets never appear in GET/audit/logs.

---

## Feature 4 — Prometheus `/metrics` endpoint

**Value:** Every competitor is monitoring-ready; WireSeal exposes nothing. Cheap,
high value for self-hosters (Grafana dashboards, alerting).

**User story:** As an operator I scrape `/metrics` and graph peer count, online
peers, per-peer transfer, unlock failures, backup age.

### Backend
- **New module** `src/wireseal/metrics/exporter.py`:
  - `render_metrics() -> str` in Prometheus text exposition format (build by
    hand; no client lib dependency).
  - Metrics:
    - `wireseal_info{version=...} 1`
    - `wireseal_clients_total`, `wireseal_clients_online` (from Feature 1 dump)
    - `wireseal_peer_rx_bytes{client=...}`, `..._tx_bytes`, `..._last_handshake_seconds`
    - `wireseal_unlock_failures_total` (from audit tally)
    - `wireseal_backup_last_success_timestamp`, `wireseal_backup_last_size_bytes`
    - `wireseal_audit_chain_valid` (0/1), `wireseal_audit_entries_total`
- **Handler** `_h_metrics` (`api/metrics.py`): `GET /api/metrics`.
  - **Auth decision:** metrics leak peer names/IPs → must be protected. Options:
    1. require unlock (simplest, but scrapers can't hold passphrase), or
    2. **bearer token** (`metrics_token` in vault; `Authorization: Bearer` or
       `?token=`), constant-time compare. **Recommended: token** so Prometheus
       can scrape unattended. Token settable on the Notifications/Settings page.
  - Content-Type `text/plain; version=0.0.4`.
- Optionally expose at the standard path `/metrics` (not under `/api`) for scraper
  ergonomics — add a route alias.

### Frontend
- Small card on a Settings/Monitoring section: enable metrics, show/rotate token,
  copy scrape URL + sample `scrape_config`.
- `api.ts`: `getMetricsConfig`, `rotateMetricsToken`.

### Tests
- `tests/metrics/test_exporter.py`: exposition format validity (no spaces in
  labels, HELP/TYPE lines), label escaping for client names, token auth (401 w/o,
  200 with).

**Effort:** ~1 day. **Risk:** low (info exposure → token-gate it).
**Acceptance:** `curl -H "Authorization: Bearer ..." /metrics` returns valid
Prometheus text; unauthorized = 401; values match live state.

---

## Feature 5 — DNS ad / malware blocking (Pi-hole-lite)

**Value:** You already run dnsmasq for split-DNS. Adding blocklists turns WireSeal
into a home **network gateway** (block ads/trackers/malware for every VPN client)
— a real differentiator vs pure VPN managers.

**User story:** As an admin I toggle "Block ads & malware", pick blocklists, and
all VPN clients get DNS-level filtering with a count of blocked domains.

### Config (vault) — `cache["dns_blocking"]`
```jsonc
{ "enabled": true,
  "lists": [ { "name": "StevenBlack hosts", "url": "https://...", "enabled": true } ],
  "allowlist": ["example.com"], "blocklist_extra": ["ads.bad.tld"],
  "last_updated": 0, "domain_count": 0 }
```

### Backend
- **New module** `src/wireseal/dns/blocklist.py`:
  - `fetch_and_compile(cfg) -> (path, count)`: download each list (stdlib urllib,
    SSRF-guard public only, size cap, timeout), parse hosts/domain formats,
    dedupe, subtract allowlist, add extra. Write a dnsmasq config fragment
    `/etc/dnsmasq.d/wireseal-blocklist.conf` using `address=/domain/0.0.0.0`
    (or `server=/domain/` sinkhole). Atomic write.
  - `DnsmasqManager.reload()` to apply (already exists).
- **Scheduler:** reuse `backup/scheduler.py` shape → cron/schtasks job
  `wireseal dns-update-blocklists` (daily). Env-less (reads vault? no — store a
  small out-of-vault flag like backup.env, OR run via the API server on a timer).
  Simplest: a periodic refresh triggered by the running API service (in-process
  timer thread) since no secrets needed.
- **CLI** `wireseal dns-blocklists --update` for manual/cron refresh.
- **Handlers** `api/dns.py` (extend): `GET/POST /api/dns/blocking`,
  `POST /api/dns/blocking/update` (force refresh → returns new count).
  `_require_admin_role()` for changes.
- **Stats:** optional — parse dnsmasq query log for blocked-hit count (if logging
  enabled); keep light (counts only, privacy-respecting; off by default).

### Frontend
- Extend `Dns.tsx`: a "Filtering" section — enable toggle, curated blocklist
  presets (StevenBlack, OISD, etc.) + custom URL, allow/deny textareas, "Update
  now", last-updated + domain count. Windows server → note dnsmasq unavailable
  (reuse existing Windows banner).
- `api.ts`: `DnsBlockingConfig` + methods.

### Edge cases
- Huge lists (1M+ domains) → memory/dnsmasq load: cap total, warn, stream parse.
- dnsmasq missing → save config but inactive (reuse existing pattern).
- Allowlist must win over blocklist (apply after).

### Tests
- `tests/dns/test_blocklist.py`: hosts/domain parsing, dedupe, allowlist subtract,
  fragment format, size cap, SSRF reject.

**Effort:** ~2–3 days. **Risk:** medium (could break DNS for all clients).
**Mitigations:** validate fragment, keep split-DNS mappings separate, easy
disable, allowlist. **Acceptance:** toggling on blocks a known ad domain for VPN
clients; split-DNS mappings still resolve; disable restores instantly.

---

## Feature 6 — Documented REST API + scoped API tokens

**Value:** You already have a full internal HTTP API (vault, clients, dns, backup,
audit, network). Exposing it with scoped tokens enables automation (Terraform,
scripts, CI) — table-stakes for wg-portal/NetBird-class tools.

### Backend
- **Token store (vault)** `cache["api_tokens"]`: list of
  `{ id, name, hash (sha256), scopes:[...], created, last_used, expires }`.
  Token shown once on creation; only hash stored.
- **Auth middleware** in `_shared.py` request dispatch: if `Authorization: Bearer
  <token>` present and valid, resolve to scopes and **bypass passphrase-unlock**
  for endpoints whose scope is granted (read-only by default). Constant-time
  compare; update `last_used`; reject expired.
- **Scopes** map to endpoint groups: `clients:read`, `clients:write`, `dns:*`,
  `backup:*`, `audit:read`, `metrics:read`, `network:read`. Enforce per route via
  a small decorator/table alongside `_ROUTES`.
- **Handlers** `api/tokens.py`: `GET /api/tokens`, `POST /api/tokens` (create →
  returns plaintext once), `DELETE /api/tokens/<id>`. `_require_admin_role()`.
  Audit `api-token-create`/`-revoke` (never log the token).
- **CSRF/origin:** token auth is exempt from the browser CSRF check (it's for
  non-browser clients); ensure tokens cannot be used to escalate beyond scope.
- **OpenAPI doc:** generate `docs/openapi.yaml` (hand-authored or from the route
  table) + a short `docs/API.md` with examples. Optionally serve Swagger UI under
  `/api/docs` (static, admin-gated).

### Frontend
- New "API Tokens" section (Settings): create (name, scopes, expiry), one-time
  reveal + copy, list with last-used, revoke.
- `api.ts`: token CRUD types/methods.

### Tests
- `tests/api/test_tokens.py`: create→hash stored not plaintext, scope enforcement
  (write token blocked on read-only route → 403), expiry, revoke, constant-time
  compare presence, audit emitted.

**Effort:** ~3 days. **Risk:** medium-high (new auth path — must not weaken vault
security). **Mitigations:** read-only default, explicit scopes, expiry, audit,
no privilege beyond granted scope, tokens never unlock the vault file itself
(only gate API operations on already-running unlocked server **or** define
clearly that tokens require the server vault to be unlocked — decide & document).
**Acceptance:** scoped token performs allowed calls, is denied others, appears in
audit, and is revocable.

> **Decision needed:** do tokens work while the vault is *locked*? Simplest &
> safest: tokens only function while an admin session has the vault unlocked
> (tokens authorize API actions, not vault decryption). Document this explicitly.

---

## Feature 7 — Peer-expiry polish (scheduled sweep + reactivation)

**Value:** You already store `ttl_expires_at` per client; wg-portal adds a
background sweep that disables expired peers and a UI to reactivate. Today expiry
is data-only.

### Backend
- **Sweep** `src/wireseal/core/expiry.py` (a module already exists — extend):
  - `sweep(cache) -> {disabled:[...], expiring:[...]}`: for each non-permanent
    client past `ttl_expires_at`, mark `disabled` and **remove from live wg
    interface** (drop peer via `wg set <iface> peer <pubkey> remove`) without
    deleting vault record (so it can be reactivated). Collect clients within 24h
    of expiry → `expiring` (feeds Feature 3 `ttl_expiring`).
- **Trigger:** in-process timer in the running API service (every 5 min) — no
  cron needed since the server is long-running; on each tick run sweep, apply wg
  changes, emit notifications, audit `client-expired`.
- **Reactivate:** extend client API — `POST /api/clients/<name>/reactivate`
  (sets new TTL or permanent, re-adds peer to wg). Already have the TTL-reset
  handler pattern in `clients.py`.

### Frontend
- `Clients.tsx`: "Expired"/"Expiring soon" badges (combine with Feature 1 online
  state); Reactivate button on expired rows; show countdown for expiring.
- `api.ts`: `reactivateClient`.

### Tests
- `tests/core/test_expiry.py`: sweep selects only past-expiry non-permanent,
  produces expiring window, reactivate restores; permanent never swept.

**Effort:** ~1–1.5 days. **Risk:** low-medium (touches live wg peers).
**Acceptance:** expired client loses connectivity automatically, shows Expired,
and Reactivate restores access; permanent clients untouched.

---

## Cross-cutting concerns

- **Audit everything:** every new mutating endpoint emits an `AuditLog.log(...)`
  entry (already the convention). New actions: `acl-update`, `notify-config`,
  `notify-test`, `metrics-token-rotate`, `blocklist-update`, `api-token-create`,
  `api-token-revoke`, `client-expired`, `client-reactivate`. Add matching
  `ACTION_META` entries in `AuditLog.tsx` so they render with icons.
- **Security review gate:** Features 2 (firewall), 5 (DNS), 6 (auth) touch
  security-sensitive surfaces → run `security-reviewer` before merge; SSRF guard
  reuse for 3/5; constant-time compares for 4/6 tokens; secret redaction for 3/4/6.
- **Cross-platform:** gate router-only features (2 ACL, 5 DNS-block) to
  Linux/macOS with clear Windows-server notices (reuse the existing DNS Windows
  banner pattern). Stats (1), notifications (3), metrics (4), tokens (6), expiry
  (7) are cross-platform.
- **Backwards compatibility:** all new vault keys default to off/empty; absent
  keys must behave as today (allow_all ACL, no blocking, no tokens).
- **Changelog + version bump** per feature (`CHANGELOG.md`, `pyproject.toml`,
  `src/wireseal/__init__.py`) — established 0.9.x cadence.
- **Tests:** maintain the project's pytest suite; register the `unit` mark in
  `pyproject.toml`/`pytest.ini` to silence the `PytestUnknownMarkWarning` seen in
  CI.

## Suggested sequencing

1. **F1 Live stats** (v0.9.50) — fast, high visibility, unblocks F4 + F7 badges.
2. **F3 Notifications** + **F4 Metrics** (v0.9.51) — shared "observability" theme;
   notifications becomes the delivery layer for later events.
3. **F2 Per-client ACLs** (v0.9.52) — flagship security feature; reuses Network
   discovery for the rule editor.
4. **F5 DNS blocking** (v0.9.53) — "home gateway" differentiator.
5. **F6 API + tokens** (v0.9.54) — automation surface.
6. **F7 Expiry polish** — fold into a 0.9.5x release alongside the above.

## Open decisions (resolve before build)
- F4/F6: token auth while vault locked vs unlocked-only (recommend unlocked-only).
- F2: DHCP/IP-drift for ACL destinations (recommend pairing with DNS mappings /
  static leases; future MAC-binding via discovery).
- F5: query-log stats privacy (default off).
- F6: ship Swagger UI or just `openapi.yaml` + `API.md` (recommend the latter
  first).
