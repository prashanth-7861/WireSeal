---
phase: 01-secure-core-engine
plan: "04"
subsystem: security
tags: [jinja2, wireguard, config-builder, validator, integrity, sha256, filelock, atomic-write, permissions]

# Dependency graph
requires:
  - "01-01 (SecretBytes, wipe_bytes, project skeleton)"
  - "01-02 (vault.py with _atomic_write inline, shared by extraction here)"
  - "01-03 (keygen, IPPool -- context only, not directly imported)"
provides:
  - "ConfigBuilder: Jinja2-based WireGuard config renderer with pre-render validation"
  - "atomic.py: shared atomic file write helper (extracted from vault.py)"
  - "validator.py: pre-apply config validation with compiler-quality error messages"
  - "integrity.py: SHA-256 config hash computation and tampering detection"
  - "permissions.py: cross-platform file/dir permission enforcement"
  - "server.conf.j2 and client.conf.j2: Jinja2 WireGuard config templates"
affects:
  - all downstream phases (config builder and validator used in CLI commands)
  - Phase 2 (platform adapters call write_config with FileLock)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Validate-before-render: validator called before Jinja2 template rendering; invalid input raises ValueError without producing any output"
    - "autoescape=False + StrictUndefined: correct Jinja2 config for plain-text WireGuard INI files"
    - "Shared atomic write: atomic_write extracted to security/atomic.py; both vault.py and config_builder.py import it"
    - "SHA-256 returned from write_config: caller stores hash in VaultState.integrity for tamper detection"
    - "FileLock (not SoftFileLock): hard lock enforced during write-apply cycle to prevent TOCTOU races"

key-files:
  created:
    - src/wg_automate/security/atomic.py
    - src/wg_automate/security/validator.py
    - src/wg_automate/security/integrity.py
    - src/wg_automate/security/permissions.py
    - src/wg_automate/core/config_builder.py
    - src/wg_automate/templates/server.conf.j2
    - src/wg_automate/templates/client.conf.j2
  modified:
    - src/wg_automate/security/vault.py
    - src/wg_automate/security/__init__.py
    - src/wg_automate/core/__init__.py

key-decisions:
  - "validate_subnet uses strict=False to accept server IP format (10.0.0.1/24) -- strict=True wrongly rejected valid server IPs with host bits set"
  - "autoescape=False in Jinja2 Environment is correct for WireGuard INI -- autoescape=True would corrupt base64 '=' characters to '&#61;'"
  - "atomic_write extracted from vault.py to security/atomic.py -- single source of truth, no duplication, no circular imports"
  - "FileLock timeout=30s -- hard lock, not SoftFileLock, to enforce CONFIG-05 TOCTOU protection"
  - "Caller (CLI layer) is responsible for SECURITY ALERT message on integrity failure -- integrity.py only returns bool"

patterns-established:
  - "CONFIG-02 Pattern: always call validate_*_config() before rendering; if validation raises, no template output is produced"
  - "CONFIG-04 Pattern: write_config() returns SHA-256 hex; store with store_hash_in_state() in VaultState.integrity"
  - "CONFIG-05 Pattern: pass lock_path to write_config() for write-apply cycle protection"

requirements-completed: [CONFIG-01, CONFIG-02, CONFIG-03, CONFIG-04, CONFIG-05, CONFIG-06]

# Metrics
duration: 5min
completed: 2026-03-18
---

# Phase 1 Plan 04: Config Generation Pipeline Summary

**Jinja2 config templates with pre-render validation (CONFIG-01..06), shared atomic write module, SHA-256 integrity tracking, and cross-platform permissions enforcement**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-18T02:47:49Z
- **Completed:** 2026-03-18T02:52:49Z
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments

- `atomic.py` extracted from `vault.py` as shared module: both vault and config builder now use the same atomic write implementation with no duplication
- `ConfigBuilder`: StrictUndefined + autoescape=False Jinja2 environment; `render_server_config()` and `render_client_config()` call validators before rendering -- invalid input raises `ValueError` without producing any output
- `server.conf.j2` and `client.conf.j2` with required `# Managed by wg-automate` header; client template includes `DNS = {{ dns_server }}` line; PostUp/PostDown block gated by `{% if post_up %}` for Phase 2 compatibility
- `validator.py`: precise error messages with exact field name, invalid character, and position (CONFIG-06 client name regex, CONFIG-02 key/port/subnet/injection validation)
- `integrity.py`: SHA-256 hash computation and constant-time `hmac.compare_digest` tampering detection (CONFIG-04)
- `permissions.py`: Unix chmod 600/700; Windows icacls with pywin32 fallback (CONFIG-03)

## Task Commits

Each task was committed atomically:

1. **Task 1: Jinja2 templates, config builder, and shared atomic write** - `0cf806b` (feat)
2. **Task 2: Validator, integrity tracker, and permissions module** - `c41ee88` (feat)

## Files Created/Modified

- `src/wg_automate/security/atomic.py` - Shared atomic write: mkstemp + fsync + os.replace, permissions set before rename
- `src/wg_automate/security/vault.py` - Updated to import `atomic_write` from `atomic.py`; inline `_atomic_write` removed
- `src/wg_automate/core/config_builder.py` - ConfigBuilder class with Jinja2 env, render/write methods
- `src/wg_automate/templates/server.conf.j2` - Server WireGuard config template
- `src/wg_automate/templates/client.conf.j2` - Client WireGuard config template with DNS and PersistentKeepalive
- `src/wg_automate/security/validator.py` - Pre-apply validation (client name, WG key, port, subnet, IP, injection, server/client composite)
- `src/wg_automate/security/integrity.py` - SHA-256 hash + hmac.compare_digest tampering detection
- `src/wg_automate/security/permissions.py` - Cross-platform file/dir permission enforcement
- `src/wg_automate/security/__init__.py` - Added exports for validator, integrity, and permissions functions
- `src/wg_automate/core/__init__.py` - Added ConfigBuilder export

## Decisions Made

- `validate_subnet` uses `strict=False` so it accepts both pure network addresses (`10.0.0.0/24`) and server IPs with prefix mask (`10.0.0.1/24`). The server config passes `f'{server_ip}/{prefix_length}'` -- using `strict=True` wrongly rejected valid server configurations.
- `autoescape=False` in Jinja2 is the correct setting for WireGuard INI files. `autoescape=True` would HTML-escape base64 `=` characters to `&#61;`, corrupting all cryptographic keys.
- `atomic_write` extracted from `vault.py` to `security/atomic.py` so both vault and config builder use identical atomic write behavior without code duplication or circular imports.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] validate_subnet used strict=True, rejecting valid server IPs**
- **Found during:** Task 1 verification (config builder test)
- **Issue:** `validate_subnet` called `ip_network(subnet, strict=True)` which requires the host bits to be zero. The server config passes `f'{server_ip}/{prefix_length}'` (e.g., `10.0.0.1/24`) where the server IP is the host address, not the network address. `strict=True` raised `ValueError: 10.0.0.1/24 has host bits set`, blocking all server config rendering.
- **Fix:** Changed to `strict=False` in `validate_subnet`. The function still validates RFC 1918 membership and CIDR syntax correctness.
- **Files modified:** `src/wg_automate/security/validator.py`
- **Verification:** Config builder tests passed; `10.0.0.1/24` accepted; `8.8.8.0/24` correctly rejected as non-RFC-1918
- **Committed in:** `c41ee88` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - Bug)
**Impact on plan:** The fix was essential -- `strict=True` would have made it impossible to render any server config. No scope creep.

## Issues Encountered

None beyond the auto-fixed bug above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Complete config generation pipeline is ready: vault secrets -> ConfigBuilder -> write_config -> SHA-256 hash stored in VaultState
- Phase 1 is now complete (4/4 plans): SecretBytes, vault, keygen/IPPool, config builder all implemented
- Phase 2 (platform adapters, CLI commands) can import ConfigBuilder, Vault, generate_keypair, IPPool, and all security primitives immediately
- The FileLock pattern for write-apply cycles is established -- Phase 2 only needs to provide the lock_path

---
*Phase: 01-secure-core-engine*
*Completed: 2026-03-18*
