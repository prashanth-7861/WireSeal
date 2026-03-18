---
phase: 02-platform-hardening
plan: 02
subsystem: platform
tags: [linux, wireguard, nftables, systemd, sysctl, cron, privilege-drop, firewall]

# Dependency graph
requires:
  - phase: 02-platform-hardening
    provides: AbstractPlatformAdapter ABC, exception hierarchy, validate_firewall_rules (02-01)
  - phase: 01-secure-core-engine
    provides: atomic_write (security/atomic.py) used in deploy_config and rule file writes

provides:
  - LinuxAdapter implementing all 12 AbstractPlatformAdapter abstract methods
  - nftables deny-by-default firewall with rate limiting 5/s burst 10 (FW-01)
  - NAT masquerade targeted to detected outbound interface only (FW-02)
  - FW-03 validation called before applying any firewall rules
  - IP forwarding via /etc/sysctl.d/99-wireguard.conf (persistent, reboot-safe)
  - systemd wg-quick@wg0 enable+start lifecycle management
  - Non-root wg-automate system user + /etc/cron.d/wg-automate (HARD-04)

affects:
  - 04-init-command (calls LinuxAdapter methods to set up the system)
  - 02-03-macos-adapter (follows same pattern)
  - 02-04-windows-adapter (follows same pattern)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - nftables drop-in file at /etc/nftables.d/wireguard.nft (never edits base /etc/nftables.conf)
    - sysctl.d drop-in approach for persistent IP forwarding (survives OS updates)
    - Idempotent table flush+re-apply pattern for nftables (check then flush before apply)
    - System user creation via adduser --system --no-create-home --shell /usr/sbin/nologin (HARD-04)
    - FW-03 validation: generated and template rules built from same function, symmetric comparison

key-files:
  created:
    - src/wg_automate/platform/linux.py
  modified: []

key-decisions:
  - "nftables ruleset is built by a single _build_nftables_ruleset() helper so generated and template strings are always symmetric -- FW-03 validation cannot silently pass on a code mismatch"
  - "apply_firewall_rules flushes and re-applies existing tables (rather than skip) to ensure current rules always match the generated ruleset"
  - "deploy_config does NOT call set_file_permissions -- atomic_write already sets 0o600 before rename, so the file is never world-readable at any point"
  - "subnet parameter in apply_firewall_rules is accepted but unused in nftables rules: masquerade uses iifname match (per FW-02 outbound-interface-only requirement), not subnet CIDR"

patterns-established:
  - "Platform adapter pattern: all 12 methods implemented, all subprocess calls use shell=False with list args"
  - "Idempotency: check state before acting (shutil.which for install, file content for sysctl, table existence for nftables, user id for adduser)"
  - "Error propagation: CalledProcessError always re-raised as SetupError with decoded stderr for actionable messages"

requirements-completed: [PLAT-03, FW-01, FW-02]

# Metrics
duration: 3min
completed: 2026-03-18
---

# Phase 02 Plan 02: Linux Adapter Summary

**LinuxAdapter with nftables deny-by-default firewall (FW-01/FW-02/FW-03), systemd service lifecycle, sysctl.d IP forwarding, and non-root DuckDNS cron user (HARD-04)**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-18T15:17:42Z
- **Completed:** 2026-03-18T15:20:26Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- LinuxAdapter implementing all 12 AbstractPlatformAdapter abstract methods -- no missing method gaps, verified at instantiation time
- nftables firewall with `policy drop` on input/forward chains, rate limiting (5/second burst 10) on WireGuard UDP port, and NAT masquerade constrained to detected outbound interface only (satisfies FW-01 and FW-02)
- FW-03: `validate_firewall_rules` called before every `nft -f` application; generated and template strings are built from the same `_build_nftables_ruleset()` function, making the comparison symmetric and always meaningful
- All 12 operations are idempotent: safe to re-run without duplicating state

## Task Commits

Each task was committed atomically:

1. **Task 1: Privilege checks, prerequisites, WireGuard install, config path, outbound detection** - `4ac6bbd` (feat)
2. **Task 2: Firewall, IP forwarding, systemd service, DNS updater** - committed in same file as Task 1 (`4ac6bbd`) -- both tasks targeted the same file and were implemented together

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `src/wg_automate/platform/linux.py` - Full LinuxAdapter (506 lines): all 12 abstract method implementations, _build_nftables_ruleset() helper, nftables drop-in at /etc/nftables.d/wireguard.nft

## Decisions Made

- `_build_nftables_ruleset()` is a module-level helper used for both generated and template strings so FW-03 comparison is always symmetric. Any future template change automatically updates both sides.
- `apply_firewall_rules` flushes existing tables before re-applying rather than skipping if tables exist. This ensures running `wg-automate` again always results in current rules applied, not stale ones.
- `deploy_config` uses `atomic_write` with `mode=0o600` -- permissions are set before rename, so the config file is never world-readable at any instant. `set_file_permissions` is not called again afterward (would be redundant).
- `subnet` parameter in `apply_firewall_rules` is accepted (required by ABC signature) but the nftables NAT rule uses `iifname` match rather than subnet CIDR, satisfying FW-02 (outbound interface only, not globally).

## Deviations from Plan

None - plan executed exactly as written. All methods implemented in a single cohesive file pass per the plan's done criteria and verification commands.

## Issues Encountered

None. The file was implemented from scratch with all methods in one pass. All plan verification criteria passed without iteration.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- LinuxAdapter is complete and fully implements the platform contract. Plan 02-03 (macOS) and 02-04 (Windows) can now follow the same pattern.
- The `get_adapter()` factory in `detect.py` will return `LinuxAdapter()` on Linux systems -- the platform is now functional end-to-end.
- FW-03 validation infrastructure (via the inherited `validate_firewall_rules` method) is exercised and confirmed working in LinuxAdapter.

---
*Phase: 02-platform-hardening*
*Completed: 2026-03-18*
