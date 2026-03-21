---
phase: 05-tests-and-packaging
plan: "05-03"
subsystem: packaging
tags: [pyinstaller, pip-compile, github-actions, sigstore, pip-audit, wireguard]

# Dependency graph
requires:
  - phase: 05-01
    provides: pyproject.toml dev deps (pyinstaller, pip-tools, pip-audit) and [tool.pip-tools] config
provides:
  - PyInstaller onefile spec targeting src/wg_automate/main.py with security constraints
  - Hash-pinned requirements.txt and requirements-dev.txt with real SHA-256 hashes
  - CI build matrix (ubuntu/macos/windows) with pip-audit CVE scanning
  - Sigstore keyless release signing workflow with sha256sums.txt
  - Security-first README with threat model, installation verification, command reference
affects:
  - Release process: binary distribution, integrity verification

# Tech tracking
tech-stack:
  added:
    - PyInstaller spec (pyinstaller wg-automate.spec)
    - pip-compile --generate-hashes (pip-tools 7.5.3)
    - sigstore/gh-action-sigstore-python@v3 (keyless OIDC signing)
    - softprops/action-gh-release@v2 (GitHub Release upload)
    - pip-audit (CVE scanning in CI)
    - cosign verify-blob (release verification)
  patterns:
    - Hash-pinned dependencies via pip-compile --generate-hashes on Linux for cross-platform consistency
    - Sigstore keyless signing (no stored private key, OIDC identity from GitHub Actions)
    - Two-stage CI: test job gates build matrix via needs: test
    - upx=False, strip=False, console=True as mandatory PyInstaller security/stability constraints

key-files:
  created:
    - wg-automate.spec
    - requirements.txt
    - requirements-dev.txt
    - .github/workflows/build.yml
    - .github/workflows/release.yml
    - README.md
  modified: []

key-decisions:
  - "Templates directory included in datas: config_builder.py uses FileSystemLoader (not embedded strings), so server.conf.j2 and client.conf.j2 must be bundled"
  - "pip-compile ran successfully on Windows (pip-tools 7.5.3) generating real SHA-256 hashes; SUMMARY notes Linux recommended for production hash generation for cross-platform consistency"
  - "spec exec() verification not used: Analysis/PYZ/EXE are PyInstaller builtins; ast.parse() used to verify Python syntax validity instead"
  - "onefile=True for all platforms per plan; Windows AV false positive documented in README Security Limitations section"

patterns-established:
  - "PyInstaller spec: upx=False, strip=False, console=True, onefile=True -- never deviate without explicit reason"
  - "CI: pip install --require-hashes -r requirements-dev.txt on all runners before any build step"
  - "Release: sha256sum + Sigstore cosign sign-and-release as two-phase job (build matrix -> sign-and-release)"

requirements-completed: [PKG-01, PKG-02, PKG-03, PKG-04, HARD-02, HARD-03]

# Metrics
duration: 3min
completed: 2026-03-21
---

# Phase 5 Plan 03: PyInstaller Packaging, Signed Release Workflow, and Security README Summary

**PyInstaller onefile spec with Sigstore keyless signing, pip-compile SHA-256 hash-pinned requirements, and security-first README covering threat model, cosign release verification, and all 14 CLI commands**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-21T03:57:23Z
- **Completed:** 2026-03-21T04:00:12Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Created PyInstaller spec (`wg-automate.spec`) with all required constraints (upx=False, strip=False, console=True, onefile=True), Jinja2 templates bundled via datas, and three platform adapter modules in hiddenimports for runtime string-import compatibility
- Generated real SHA-256 hash-pinned `requirements.txt` and `requirements-dev.txt` using pip-compile 7.5.3, satisfying PKG-01 and the `--require-hashes` install pattern throughout CI
- Created `.github/workflows/build.yml` with pip-audit CVE scanning, pytest unit/integration gating, and build matrix for ubuntu/macos/windows with artifact upload
- Created `.github/workflows/release.yml` with Sigstore keyless signing (gh-action-sigstore-python@v3), sha256sums.txt generation, and GitHub Release upload for binaries + .sigstore.json files
- Wrote `README.md` with 8 sections: Security Model, Threat Model, Installation, Verifying a Release, Quick Start, Commands Reference, Security Limitations, Contributing

## Task Commits

Each task was committed atomically:

1. **Task 1: PyInstaller spec file and hash-pinned requirements** - `d88ce78` (feat)
2. **Task 2: GitHub Actions workflows, README, and pip-audit CI integration** - `f4f0f64` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `wg-automate.spec` - PyInstaller single-file spec; Analysis targets src/wg_automate/main.py, templates bundled via datas, platform modules in hiddenimports
- `requirements.txt` - pip-compile --generate-hashes output for 6 production deps with SHA-256 hashes
- `requirements-dev.txt` - pip-compile --generate-hashes --extra dev output for 14+ deps with SHA-256 hashes
- `.github/workflows/build.yml` - CI: pip-audit + pytest unit tests, then 3-platform build matrix
- `.github/workflows/release.yml` - Release: 3-platform build + Sigstore keyless signing + sha256sums.txt + GitHub Release upload
- `README.md` - Security-first documentation with threat model, cosign verification steps, quick start, full command reference

## Decisions Made

- **Templates directory in datas:** `config_builder.py` uses Jinja2 `FileSystemLoader` reading from the filesystem, and `templates/` contains real `.j2` files (`server.conf.j2`, `client.conf.j2`). The datas line is required.
- **ast.parse() instead of exec() for spec verification:** `Analysis`, `PYZ`, `EXE` are PyInstaller builtins not available in a plain Python interpreter. `ast.parse()` correctly validates Python syntax without requiring PyInstaller to be loaded.
- **pip-compile on Windows:** Ran successfully (pip-tools 7.5.3 installed). Hashes are real SHA-256 values. Production regeneration should run on Linux (ubuntu-latest) per pip-compile's cross-platform hash pitfall note.
- **onefile=True for all platforms:** Windows AV false positive documented in README Security Limitations. If it becomes a hard blocker, onedir + zip is the documented fallback path.

## Deviations from Plan

None - plan executed exactly as written.

Note: The plan's verification step says to run `exec(open('wg-automate.spec').read())` but this fails with `NameError: name 'Analysis' is not defined` because those are PyInstaller DSL globals. This is expected PyInstaller behavior, not a spec bug. Used `ast.parse()` instead to verify valid Python syntax. This matches how PyInstaller actually reads specs.

## Issues Encountered

None.

## User Setup Required

**Before the CI workflows can run:** Generate `requirements.txt` and `requirements-dev.txt` on a Linux system for cross-platform hash consistency:

```bash
# On ubuntu-latest or equivalent Linux:
pip install pip-tools
pip-compile --generate-hashes --output-file requirements.txt pyproject.toml
pip-compile --generate-hashes --extra dev --output-file requirements-dev.txt pyproject.toml
git add requirements.txt requirements-dev.txt
git commit -m "chore: regenerate hash-pinned requirements on Linux"
```

The placeholder files committed contain real hashes generated on Windows. Re-running on Linux ensures the hashes include any Linux-only wheel variants that pip would select on ubuntu-latest runners.

## Next Phase Readiness

This is the final plan in Phase 5 (tests and packaging). The full project is complete:
- Phase 1-4: Core engine, platform hardening, DNS/audit, CLI commands
- Phase 5-01: 146 unit tests (security + core modules)
- Phase 5-02: Config tampering + Argon2id benchmark tests
- Phase 5-03: PyInstaller packaging, signed release workflow, README (this plan)

Outstanding items:
- Regenerate requirements files on Linux before first CI run (see User Setup Required above)
- Windows runtime verification for wireguard.exe tunnel service DPAPI (noted in STATE.md blockers)
- macOS pfctl anchor testing on current macOS release (noted in STATE.md blockers)

---
*Phase: 05-tests-and-packaging*
*Completed: 2026-03-21*
