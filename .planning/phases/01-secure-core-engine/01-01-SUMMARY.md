---
phase: 01-secure-core-engine
plan: "01"
subsystem: security
tags: [ctypes, mlock, VirtualLock, bytearray, hmac, memory-wiping, secret-types]

# Dependency graph
requires: []
provides:
  - "SecretBytes: mutable secret container with mlock, wipe-on-release, repr/hash/pickle protection"
  - "wipe_bytes: zero-random-zero overwrite for bytearrays"
  - "wipe_string: best-effort CPython internal buffer zeroing for strings"
  - "Python package skeleton with src-layout, pyproject.toml, requirements.in"
affects:
  - 01-02
  - 01-03
  - 01-04
  - all downstream phases (every key and secret flows through SecretBytes)

# Tech tracking
tech-stack:
  added:
    - cryptography>=46.0,<47
    - argon2-cffi>=25.1,<26
    - jinja2>=3.1.6,<4
    - filelock>=3.20.3,<4
    - click>=8.3.1,<9
  patterns:
    - "SecretBytes context manager for automatic secret cleanup"
    - "zero-random-zero overwrite pattern for memory wiping"
    - "best-effort mlock/VirtualLock at construction, munlock after wipe"
    - "hmac.compare_digest for constant-time secret comparison"

key-files:
  created:
    - pyproject.toml
    - requirements.in
    - src/wg_automate/__init__.py
    - src/wg_automate/security/__init__.py
    - src/wg_automate/security/secret_types.py
    - src/wg_automate/security/secrets_wipe.py
    - src/wg_automate/core/__init__.py
    - src/wg_automate/templates/.gitkeep
    - tests/__init__.py
    - tests/security/__init__.py
    - tests/core/__init__.py
  modified: []

key-decisions:
  - "Upper Python bound widened to <3.15 (installed Python is 3.14.2; original <3.14 was too restrictive)"
  - "setuptools build-backend corrected to setuptools.build_meta (setuptools.backends.legacy path invalid)"
  - "wipe_bytes uses simple index-based loop (cleaner than ctypes memmove for bytearray item assignment)"
  - "wipe_string computes header offset as sys.getsizeof(s) - len(s) (portable across compact ASCII layouts)"

patterns-established:
  - "SEC-05 Pattern: use SecretBytes as context manager; all key material wiped in finally blocks"
  - "Best-effort platform calls: always wrap ctypes mlock/VirtualLock in try/except, never crash"
  - "Exception suppression convention: raise NewError from None to hide cause chain"

requirements-completed: [SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, HARD-01, HARD-02, HARD-03]

# Metrics
duration: 2min
completed: 2026-03-18
---

# Phase 1 Plan 01: Project Skeleton and Security Foundation Summary

**SecretBytes type with mlock/VirtualLock, zero-random-zero wipe, and Python src-layout package skeleton for wg-automate**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-18T02:36:00Z
- **Completed:** 2026-03-18T02:38:00Z
- **Tasks:** 2
- **Files modified:** 11

## Accomplishments

- Project skeleton with src-layout, pyproject.toml (setuptools build, Python >=3.12,<3.15, 5 pinned deps), requirements.in with pip-compile/pip-audit instructions
- `wipe_bytes`: zero-random-zero three-pass overwrite for bytearrays (SEC-03)
- `wipe_string`: best-effort CPython internal buffer wipe using ctypes memset with dynamic header offset
- `SecretBytes`: mutable secret container enforcing all SEC-01..SEC-05 invariants -- repr/str/hash/pickle blocked, constant-time equality, mlock on creation, wipe on release, context manager support

## Task Commits

Each task was committed atomically:

1. **Task 1: Project skeleton and dependency configuration** - `51fa738` (chore)
2. **Task 2: SecretBytes type and secrets_wipe module** - `53009a1` (feat)

## Files Created/Modified

- `pyproject.toml` - Build system, Python version, 5 dependency bounds, pytest config
- `requirements.in` - Pip-compile source with audit instructions (HARD-02/03)
- `src/wg_automate/__init__.py` - Package root with `__version__ = "0.1.0"`
- `src/wg_automate/security/__init__.py` - Exports SecretBytes, wipe_bytes, wipe_string
- `src/wg_automate/security/secret_types.py` - SecretBytes class (SEC-01..SEC-05)
- `src/wg_automate/security/secrets_wipe.py` - wipe_bytes, wipe_string functions
- `src/wg_automate/core/__init__.py` - Empty package marker
- `src/wg_automate/templates/.gitkeep` - Preserves templates dir in git
- `tests/__init__.py`, `tests/security/__init__.py`, `tests/core/__init__.py` - Empty test package markers

## Decisions Made

- Upper Python bound widened from `<3.14` to `<3.15` because the installed Python is 3.14.2 and the original bound would have excluded it. The plan's intent was "3.12 minimum" with an upper bound as a precaution; 3.15 maintains that intent while matching the installed environment.
- `setuptools.build_meta` used instead of `setuptools.backends.legacy:build` -- the legacy path does not exist in setuptools 80.9.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Corrected setuptools build-backend path**
- **Found during:** Task 1 (project skeleton)
- **Issue:** `setuptools.backends.legacy:build` does not exist in setuptools 80.9 -- `pip install -e .` failed with BackendUnavailable
- **Fix:** Changed to `setuptools.build_meta` (the canonical backend)
- **Files modified:** `pyproject.toml`
- **Verification:** `pip install -e .` succeeded; `from wg_automate import __version__` works
- **Committed in:** `51fa738`

**2. [Rule 3 - Blocking] Widened Python version upper bound to <3.15**
- **Found during:** Task 1 (project skeleton)
- **Issue:** `requires-python = ">=3.12,<3.14"` excluded Python 3.14.2 (the installed version); `pip install -e .` rejected with "requires a different Python"
- **Fix:** Changed upper bound to `<3.15` to include the 3.14.x series
- **Files modified:** `pyproject.toml`, `requirements.in`
- **Verification:** Package installed and importable under Python 3.14.2
- **Committed in:** `51fa738`

---

**Total deviations:** 2 auto-fixed (both Rule 3 - blocking)
**Impact on plan:** Both fixes were essential to install the package at all. No scope creep.

## Issues Encountered

None beyond the two auto-fixed blockers above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SecretBytes and wipe_bytes/wipe_string are complete and verified; plan 01-02 (vault encryption) can import them immediately
- All security invariants SEC-01..SEC-05 enforced and manually tested
- Package is `pip install -e .`-able; pytest infrastructure configured

---
*Phase: 01-secure-core-engine*
*Completed: 2026-03-18*
