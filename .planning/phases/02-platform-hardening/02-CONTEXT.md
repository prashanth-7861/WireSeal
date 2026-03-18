# Phase 2: Platform Hardening - Context

**Gathered:** 2026-03-18
**Status:** Ready for planning

<domain>
## Phase Boundary

Build platform-specific adapters (Linux, macOS, Windows) behind an `AbstractPlatformAdapter` ABC: WireGuard installation, firewall rule application, service management (systemd / launchd / Windows tunnel service), and file permission enforcement. The CLI command that calls these adapters (`init`) is Phase 4. This phase delivers the adapter library only.

</domain>

<decisions>
## Implementation Decisions

### Privilege Escalation
- Fail immediately at startup with clear message: `"wg-automate requires root/Administrator privileges. Re-run with: sudo wg-automate"` — no auto-escalation, no sudo re-exec offer
- Privilege check runs at startup, before any vault interaction — fast fail prevents partial state
- Windows UAC and Linux sudo/root handling: Claude's Discretion — pick the cleanest approach per platform
- Linux sudo vs root distinction: Claude's Discretion — decide whether to warn about HOME directory implications

### WireGuard Interface Naming
- Fixed: always `wg0` — not configurable by user
- Interface name stored in vault (encrypted) — consistent with Phase 1 "all settings in vault" decision
- Existing `wg0` interface detection: Claude's Discretion — decide whether to fail, warn, or overwrite
- Windows: tunnel name = `wg0`, config file = `wg0.conf` — naming consistent across all platforms

### Firewall Approach (Linux)
- nftables only — no iptables fallback, no autodetection
- Idempotent: check if rules already exist before applying — safe to re-run without duplicating rules
- Firewall rules applied separately by platform adapter, NOT via PostUp/PostDown hooks in wg0.conf — cleaner separation of concerns; rules persist across wg-quick restarts without hook timing dependency
- Missing nftables: Claude's Discretion — decide between fail-with-instructions vs auto-install

### Setup Failure and Progress
- Partial setup failure: fail with clear message listing what succeeded and what failed, leave state as-is — no automatic rollback (rollback is risky and hard to get right)
- Prerequisite failures: print exact install command (e.g., `"Run: apt install wireguard nftables"`) — actionable, not vague
- Setup progress: numbered steps with status (e.g., `"[1/5] Installing WireGuard... done"`) — user sees exactly where it is and where it failed
- Re-running init on an already-initialized system: Claude's Discretion — decide between hard fail vs idempotent skip

### Claude's Discretion
- Windows UAC elevation approach (print instructions vs ShellExecuteEx runas)
- Linux sudo vs direct root warning behavior
- Existing wg0 interface detection on init (fail vs warn+confirm vs overwrite)
- Missing nftables: auto-install vs fail-with-instructions
- Re-running init on initialized system (fail vs idempotent)
- Privilege drop mechanism: HARD-04 (DuckDNS non-root user) lives in this phase

</decisions>

<specifics>
## Specific Ideas

- Progress output format: `[1/5] Installing WireGuard... done` / `[2/5] Applying firewall rules... done` — numbered, compact
- Failure message format: `"Setup failed at step 3/5 (firewall). Steps 1-2 completed successfully. Fix the error above and re-run."` — precise
- Exact prerequisite error: `"wireguard not found. Run: apt install wireguard nftables"` — platform-specific, not generic
- The "fail immediately, no re-exec" privilege model is intentional — keeps the tool explicit and auditable; no magic elevation

</specifics>

<deferred>
## Deferred Ideas

- None — discussion stayed within Phase 2 scope

</deferred>

---

*Phase: 02-platform-hardening*
*Context gathered: 2026-03-18*
