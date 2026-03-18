---
phase: 02-platform-hardening
plan: 01
subsystem: platform
tags: [abc, wireguard, platform-detection, abc, nftables, firewall, privilege-check]

# Dependency graph
requires:
  - phase: 01-secure-core-engine
    provides: security/permissions.py and security/atomic.py used by deploy_config abstract signature

provides:
  - AbstractPlatformAdapter ABC with 12 abstract methods (contract for Linux/macOS/Windows adapters)
  - get_adapter() platform detection factory with lazy imports
  - get_platform_info() diagnostic OS info dict
  - Platform exception hierarchy (PlatformError, PrivilegeError, UnsupportedPlatformError, PrerequisiteError, FirewallValidationError, SetupError)
  - Progress step reporter with locked [N/TOTAL] format
  - validate_firewall_rules() deny-by-default template validator (FW-03)

affects:
  - 02-02-linux-adapter
  - 02-03-macos-adapter
  - 02-04-windows-adapter

# Tech tracking
tech-stack:
  added: []
  patterns:
    - ABC enforced at instantiation (not runtime) -- missing abstract methods raise TypeError on class instantiation
    - Lazy platform imports in get_adapter() prevent cross-OS stdlib import errors (winreg on Linux, etc.)
    - Module-level function + concrete method delegation pattern for validate_firewall_rules
    - Firewall rules validated against canonical template before taking effect (FW-03)

key-files:
  created:
    - src/wg_automate/platform/__init__.py
    - src/wg_automate/platform/base.py
    - src/wg_automate/platform/detect.py
    - src/wg_automate/platform/exceptions.py
    - src/wg_automate/platform/progress.py
  modified: []

key-decisions:
  - "Lazy imports in get_adapter() isolate platform-specific stdlib (winreg, etc.) from cross-OS imports"
  - "validate_firewall_rules lives as both a module-level function (for standalone use) and a concrete adapter method (for subclass inheritance)"
  - "PrivilegeError message format is locked per platform: sudo wg-automate (Unix) vs Run as Administrator (Windows)"
  - "Progress.fail() outputs FAILED on the same line then a recovery hint below, matching locked format"

patterns-established:
  - "Platform contract: all 12 abstract methods must be implemented or instantiation fails"
  - "Lazy imports: get_adapter() uses local imports per branch to prevent cross-OS errors"
  - "FW-03 validation: adapters call self.validate_firewall_rules() after generating rules"

requirements-completed: [PLAT-01, PLAT-02, PLAT-06, HARD-04, FW-03]

# Metrics
duration: 5min
completed: 2026-03-18
---

# Phase 02 Plan 01: Platform Adapter Foundation Summary

**AbstractPlatformAdapter ABC with 12 abstract methods, lazy-import platform detection factory, locked exception hierarchy, and FW-03 firewall rule validator**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-18T15:12:37Z
- **Completed:** 2026-03-18T15:15:07Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- AbstractPlatformAdapter ABC with 12 abstract methods enforced at instantiation (TypeError if any missing) -- this is the contract all three platform adapters in plans 02-02 through 02-04 must fulfill
- Platform detection factory (get_adapter()) with lazy per-branch imports preventing winreg and other platform stdlib modules from loading on wrong OSes
- Locked exception hierarchy covering all failure modes: PrivilegeError (with OS-specific locked messages), UnsupportedPlatformError, PrerequisiteError, FirewallValidationError, SetupError
- Progress reporter matching locked [N/TOTAL] Description... done/FAILED format
- validate_firewall_rules() satisfying FW-03: normalizes both strings (strip, remove blanks and comments), raises FirewallValidationError on mismatch

## Task Commits

Each task was committed atomically:

1. **Task 1: Platform exceptions, progress reporter, and package init** - `3a1136a` (feat)
2. **Task 2: AbstractPlatformAdapter ABC and platform detection factory** - `6900733` (feat)

## Files Created/Modified

- `src/wg_automate/platform/__init__.py` - Package init with full public API exports
- `src/wg_automate/platform/exceptions.py` - PlatformError hierarchy with 5 subclasses and locked message formats
- `src/wg_automate/platform/progress.py` - Progress class with [N/TOTAL] locked step format and fail recovery hint
- `src/wg_automate/platform/base.py` - AbstractPlatformAdapter ABC (12 abstract methods) + module-level validate_firewall_rules
- `src/wg_automate/platform/detect.py` - get_adapter() factory with lazy imports + get_platform_info() diagnostic dict

## Decisions Made

- Lazy imports in get_adapter(): each platform branch uses a local import statement so winreg (Windows-only) and similar stdlib modules are never imported on other OSes.
- validate_firewall_rules exists as both a module-level function (callable standalone) and a concrete method on AbstractPlatformAdapter (inherited by all adapters without reimplementation). The method delegates to the function.
- PrivilegeError message is locked per platform (checked in __init__ based on sys.platform) so callers never need to construct the message manually.
- Progress.fail() decrements for "steps completed" count (current - 1) to give accurate recovery hint.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] __init__.py eager imports failed before base.py/detect.py existed**

- **Found during:** Task 1 (package __init__.py creation)
- **Issue:** __init__.py imported from detect and base at module load time; verify command failed with ModuleNotFoundError since Task 2 files didn't exist yet
- **Fix:** Used module-level __getattr__ for lazy imports during Task 1, then switched to direct imports in Task 2 once base.py and detect.py were created
- **Files modified:** src/wg_automate/platform/__init__.py
- **Verification:** Import succeeds after Task 2 commit; all plan verification commands pass
- **Committed in:** 3a1136a (Task 1 lazy version), 6900733 (Task 2 direct imports)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Required only during the two-task sequencing; final state is clean direct imports as intended.

## Issues Encountered

None beyond the __init__.py import sequencing issue documented above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Platform adapter contract fully established -- plans 02-02 (Linux), 02-03 (macOS), 02-04 (Windows) can now implement AbstractPlatformAdapter
- Exception classes, Progress reporter, and validate_firewall_rules are ready for use in all three adapter implementations
- get_adapter() will return the correct adapter once the platform modules exist; currently raises UnsupportedPlatformError on all platforms (no implementation yet)

---
*Phase: 02-platform-hardening*
*Completed: 2026-03-18*
