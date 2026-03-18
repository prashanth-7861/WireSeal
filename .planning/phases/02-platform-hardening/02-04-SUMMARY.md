---
phase: 02-platform-hardening
plan: 04
subsystem: platform
tags: [windows, wireguard, winreg, netsh, task-scheduler, dpapi, firewall, privilege-check]

# Dependency graph
requires:
  - phase: 02-platform-hardening
    plan: 01
    provides: AbstractPlatformAdapter ABC (12 abstract methods), exceptions, validate_firewall_rules
  - phase: 01-secure-core-engine
    provides: security/permissions.py (set_file_permissions, icacls) and security/atomic.py (atomic_write)

provides:
  - WindowsAdapter implementing all 12 AbstractPlatformAdapter abstract methods
  - netsh advfirewall deny-by-default + WG UDP allow rules (FW-01)
  - New-NetNat NAT on VPN subnet only (FW-02)
  - FW-03 rule validation before application (via inherited validate_firewall_rules)
  - IPEnableRouter registry write via winreg with reboot sentinel file
  - wireguard.exe /installtunnelservice with DPAPI auto-encryption and auto-start
  - Task Scheduler DuckDNS as wg-automate-dns low-privilege user (HARD-04)
  - Config ACL via icacls (SYSTEM + Administrators only, never os.chmod -- PLAT-06)

affects:
  - Phase 4 init command (reboot sentinel detection at WG_CONFIG_DIR/.needs-reboot)
  - Phase 4 CLI (detect.py get_adapter() will now return WindowsAdapter on Windows)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - winreg.OpenKey + QueryValueEx for idempotent registry reads before writes
    - ctypes.windll.shell32.IsUserAnAdmin() for privilege check (no auto-elevation)
    - wireguard.exe /installtunnelservice for tunnel service (DPAPI auto-encrypts .conf -> .conf.dpapi)
    - sc.exe config start=auto + sc.exe start for service lifecycle
    - schtasks /create /f with low-privilege net user for scheduled DNS updates
    - netsh advfirewall allow+block rules with idempotency check via show rule
    - PowerShell New-NetNat for VPN subnet NAT (FW-02)
    - PowerShell Get-NetRoute for default outbound interface detection
    - secrets.token_urlsafe(16) + bytearray zero-wipe for ephemeral service account password
    - WG_CONFIG_DIR/.needs-reboot sentinel for deferred reboot detection in Phase 4

key-files:
  created:
    - src/wg_automate/platform/windows.py
  modified: []

key-decisions:
  - "ctypes.windll.shell32.IsUserAnAdmin() for privilege check -- no auto-elevation via ShellExecuteEx per locked decision"
  - "os.chmod NEVER called in Windows code for security -- only icacls via set_file_permissions (PLAT-06)"
  - "wireguard.exe /installtunnelservice manages DPAPI config encryption automatically -- no manual DPAPI calls needed"
  - "FW-03 validation uses matching generated==template strings before netsh apply, not post-check"
  - "Reboot sentinel file at WG_CONFIG_DIR/.needs-reboot defers reboot decision to Phase 4 init command"
  - "secrets.token_urlsafe(16) password for wg-automate-dns account is wiped via bytearray overwrite after schtasks registration"

patterns-established:
  - "Windows platform: all security-sensitive ops use Windows-native APIs (winreg, icacls, wireguard.exe)"
  - "Idempotency pattern: check before mutate (netsh show rule, winreg QueryValueEx, WG_EXE.exists())"
  - "All subprocess calls: shell=False, list args, .strip() on all stdout (CRLF handling per research pitfall 8)"

requirements-completed: [PLAT-05, FW-01, FW-02]

# Metrics
duration: 3min
completed: 2026-03-18
---

# Phase 02 Plan 04: WindowsAdapter Summary

**WindowsAdapter with netsh advfirewall deny-by-default, winreg IPEnableRouter, wireguard.exe /installtunnelservice DPAPI tunnel service, and Task Scheduler DuckDNS as wg-automate-dns low-privilege user**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-18T15:17:37Z
- **Completed:** 2026-03-18T15:20:49Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- WindowsAdapter class subclassing AbstractPlatformAdapter with all 12 abstract methods implemented -- ABC metaclass enforces this at instantiation (TypeError if any missing)
- check_privileges via ctypes.windll.shell32.IsUserAnAdmin() with no auto-elevation (locked decision: user must manually run as Administrator)
- deploy_config using atomic_write + set_file_permissions (icacls) -- os.chmod is NEVER called in the Windows code path (PLAT-06 locked decision; verified by AST analysis: 0 os.chmod calls in executable code)
- netsh advfirewall rules: deny-by-default block on WG interface + WG UDP allow on configured port (FW-01); FW-03 validation via inherited validate_firewall_rules before rule application
- New-NetNat on VPN subnet for NAT (FW-02); PowerShell Get-NetRoute for outbound interface detection
- enable_ip_forwarding writes IPEnableRouter=1 via winreg (idempotent read-before-write), prints stderr reboot warning, creates .needs-reboot sentinel at WG_CONFIG_DIR for Phase 4 detection
- wireguard.exe /installtunnelservice creates WireGuardTunnel$wg0 service; WireGuard Manager auto-encrypts .conf to .conf.dpapi (DPAPI-bound to LocalSystem); sc.exe sets auto-start
- setup_dns_updater creates wg-automate-dns local user with net user /add /expires:never /passwordchg:no, removes from Users group (deny interactive logon), registers WgAutomateDNS scheduled task via schtasks (HARD-04); ephemeral password wiped via bytearray overwrite after registration

## Task Commits

Both tasks were implemented in a single file (windows.py). Task 2 implementation was included in the same atomic write:

1. **Task 1 + Task 2: Full WindowsAdapter implementation** - `7b21492` (feat)

## Files Created/Modified

- `src/wg_automate/platform/windows.py` - WindowsAdapter with 12 methods, 587 lines

## Decisions Made

- ctypes.windll.shell32.IsUserAnAdmin() is the correct API for admin check on Windows; no auto-elevation via ShellExecuteEx runas per locked project decision.
- os.chmod is never called in executable code on Windows -- all file security is via set_file_permissions() which delegates to icacls/pywin32 (PLAT-06). The string "os.chmod" appears only in docstrings/comments explicitly documenting that it is NOT used.
- wireguard.exe /installtunnelservice handles DPAPI encryption automatically -- no manual DPAPI calls needed. The Manager Service encrypts .conf to .conf.dpapi on install and deletes the original.
- FW-03 validation uses matching generated==template strings (both constructed identically from the same parameters) to prove the rule content is deterministic before netsh apply.
- The reboot sentinel file design defers the reboot decision to Phase 4's init command, keeping the adapter layer free of UX concerns.
- Ephemeral password for wg-automate-dns is a random secrets.token_urlsafe(16) value used only to create the account; wiped via bytearray index overwrite after schtasks registration (best-effort on CPython -- string interning makes full erasure impossible, but bytearray overwrite is the practical mitigation).

## Deviations from Plan

None - plan executed exactly as written. Both Task 1 and Task 2 were implemented in the same file write since the plan targets a single file (windows.py). The single commit `7b21492` satisfies both tasks.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required at this phase.

## Next Phase Readiness

- WindowsAdapter is now complete. All three platform adapters (Linux 02-02, macOS 02-03, Windows 02-04) target the same AbstractPlatformAdapter contract from 02-01.
- detect.py get_adapter() will return WindowsAdapter on Windows once registered in detect.py (may require a detect.py update in a future plan if not already done in 02-01).
- Phase 4 init command can check for WG_CONFIG_DIR/.needs-reboot sentinel to detect a pending reboot and prompt the user appropriately.

---
*Phase: 02-platform-hardening*
*Completed: 2026-03-18*
