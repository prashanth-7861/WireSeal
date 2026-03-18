---
phase: 02-platform-hardening
plan: 03
subsystem: platform
tags: [macos, wireguard, pfctl, launchd, homebrew, firewall, ip-forwarding, dns-updater]

# Dependency graph
requires:
  - phase: 02-platform-hardening
    plan: 01
    provides: AbstractPlatformAdapter ABC, exception hierarchy, atomic_write, validate_firewall_rules

provides:
  - MacOSAdapter implementing all 12 AbstractPlatformAdapter abstract methods
  - pfctl anchor-based firewall (com.apple/wireguard) with deny-by-default, rate-limited UDP, and NAT
  - Runtime sysctl IP forwarding with launchd boot persistence (not sysctl.conf)
  - launchd plist service management for WireGuard tunnel
  - DuckDNS scheduled via launchd with non-admin wg-automate user (HARD-04)
  - Homebrew root refusal handling via SUDO_USER env var

affects:
  - Any CLI command that calls get_adapter() on macOS will now return MacOSAdapter

# Tech tracking
tech-stack:
  added: []
  patterns:
    - pfctl anchor (com.apple/wireguard) for firewall -- survives OS updates, never edits /etc/pf.conf
    - PF overload table (wg_bruteforce) for rate-limited UDP brute-force protection
    - plistlib.dumps() for launchd plists (not string templates)
    - Runtime sysctl -w + companion launchd plist (not unreliable sysctl.conf on Sonoma/Sequoia)
    - SUDO_USER drop for Homebrew (brew refuses root; sudo -u SUDO_USER brew install)
    - dscl for system user creation (wg-automate user with UID < 500, shell=/usr/bin/false)

key-files:
  created:
    - src/wg_automate/platform/macos.py
  modified: []

key-decisions:
  - "pfctl anchor com.apple/wireguard used for all firewall rules -- never edits /etc/pf.conf, survives macOS OS updates"
  - "sysctl.conf skipped entirely; runtime sysctl -w + launchd plist used for IP forwarding persistence on Sonoma/Sequoia"
  - "Homebrew root refusal handled via SUDO_USER: sudo -u SUDO_USER brew install (raises SetupError if pure root)"
  - "PF overload table wg_bruteforce implements rate limiting at 5 UDP packets/second for FW-01"
  - "dscl used to create wg-automate system user (UID 300-499) for HARD-04 DNS privilege drop"

patterns-established:
  - "macOS firewall: anchor-only, never global pf.conf edits"
  - "macOS boot persistence: launchd plist in /Library/LaunchDaemons, not sysctl.conf"
  - "Homebrew + sudo pattern: SUDO_USER env var for privilege drop to regular user"

requirements-completed: [PLAT-04, FW-01, FW-02]

# Metrics
duration: 2min
completed: 2026-03-18
---

# Phase 02 Plan 03: macOS Platform Adapter Summary

**MacOSAdapter with pfctl anchor firewall, launchd service management, runtime sysctl IP forwarding, and Homebrew-aware WireGuard installation handling root refusal via SUDO_USER**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-18T15:17:38Z
- **Completed:** 2026-03-18T15:20:35Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- MacOSAdapter fully implements all 12 abstract methods from AbstractPlatformAdapter; ABC enforcement confirmed at instantiation
- pfctl anchor `com.apple/wireguard` used for all firewall rules -- never edits `/etc/pf.conf` so rules survive macOS OS updates
- Deny-by-default firewall with PF overload table (`wg_bruteforce`) for rate-limited UDP: hosts exceeding 5 packets/second are blocked (FW-01)
- NAT via `nat on {outbound} from {subnet} to any -> ({outbound})` targets only the detected outbound interface, not global (FW-02)
- FW-03 satisfied: `validate_firewall_rules()` called on generated vs. template before `pfctl -f` is invoked
- IP forwarding via `sysctl -w net.inet.ip.forwarding=1` at runtime plus a companion launchd plist at `/Library/LaunchDaemons/com.wg-automate.sysctl.plist` for boot persistence (sysctl.conf unreliable on Sonoma 14+ / Sequoia 15+)
- Homebrew root refusal handled: `install_wireguard()` drops to `SUDO_USER` via `sudo -u $SUDO_USER brew install wireguard-tools`; raises `SetupError` if running as pure root without `SUDO_USER`
- launchd plist service management for WireGuard tunnel using `plistlib.dumps()` (not string templates); correct `root:wheel` ownership and 644 permissions
- DuckDNS launchd plist uses `UserName: wg-automate` key for privilege drop (HARD-04); system user created via `dscl` with UID < 500, shell `/usr/bin/false`
- Intel Mac + Sequoia (15+) bottle warning emitted to stderr for wireguard-tools
- All subprocess calls use `shell=False` with list arguments; all operations are idempotent

## Task Commits

Each task was committed atomically:

1. **Task 1 & 2: MacOSAdapter full implementation** - `32d5666` (feat)
   - Note: both tasks shared the same file; the complete implementation was written in a single atomic commit since Task 2 builds directly on Task 1's class structure

## Files Created/Modified

- `src/wg_automate/platform/macos.py` (577 lines) -- Complete MacOSAdapter implementation

## Decisions Made

- pfctl anchor `com.apple/wireguard` used for all firewall rules -- never edits `/etc/pf.conf`, survives macOS OS updates
- sysctl.conf skipped entirely; runtime `sysctl -w` plus launchd plist used for IP forwarding persistence on Sonoma/Sequoia
- Homebrew root refusal handled via `SUDO_USER`: `sudo -u SUDO_USER brew install` raises `SetupError` if pure root
- PF overload table `wg_bruteforce` implements rate limiting at 5 UDP packets/second for FW-01
- `dscl` used to create `wg-automate` system user (UID 300-499) for HARD-04 DNS privilege drop

## Deviations from Plan

None -- plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None -- no external service configuration required.

## Next Phase Readiness

- MacOSAdapter complete -- `get_adapter()` will return it on macOS once platform detection is wired
- Plan 02-04 (Windows adapter) is the final platform implementation remaining
- All three firewall requirements (FW-01, FW-02, FW-03) are now satisfied by the macOS adapter

---
*Phase: 02-platform-hardening*
*Completed: 2026-03-18*
