# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-17)

**Core value:** Zero plaintext secrets on disk, ever -- if the vault is compromised without the passphrase, no key material is exposed.
**Current focus:** Phase 4: CLI and Client Management -- IN PROGRESS (1 of 4 plans done)

## Current Position

Phase: 4 of 5 (CLI and Client Management) -- IN PROGRESS
Plan: 1 of 4 in current phase (04-01 complete)
Status: In Progress
Last activity: 2026-03-20 -- Completed plan 04-01 (Click CLI skeleton with 14 commands + init/status/verify/lock/change-passphrase implementations)

Progress: [████████░░] 69% (11/16 plans complete)

## Performance Metrics

**Velocity:**
- Total plans completed: 10
- Average duration: 3 min
- Total execution time: 0.50 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-secure-core-engine | 4/4 | 12 min | 3 min |
| 02-platform-hardening | 4/4 | 12 min | 3 min |
| 03-dynamic-dns-and-audit | 2/4 | 10 min | 5 min |

**Recent Trend:**
- Last 5 plans: 4 min
- Trend: Stable

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Roadmap]: SecretBytes (security/secret_types.py) must be built FIRST -- it is the dependency chain foundation for vault and all secret handling
- [Roadmap]: vault.py lives in security/, not core/ -- the vault IS the security boundary
- [Roadmap]: Python 3.12 minimum (not 3.10 -- 3.10 EOL October 2026)
- [Roadmap]: os.replace() for atomic writes (not os.rename() -- fails on Windows when target exists)
- [Roadmap]: wg syncconf with file locking (not wg setconf) to preserve active sessions
- [01-01]: Python upper bound widened to <3.15 -- installed Python is 3.14.2; original <3.14 excluded it
- [01-01]: setuptools.build_meta used (not setuptools.backends.legacy:build -- path invalid in setuptools 80.9)
- [01-01]: wipe_bytes uses simple index-based loop (cleaner than ctypes memmove for bytearray item assignment)
- [01-02]: Corrupted ct_len field raises VaultUnlockError (not VaultTamperedError) to preserve generic error contract
- [01-02]: Argon2 params stored in binary header for forward-compatible decryption across parameter upgrades
- [01-02]: 47-byte header used as AES-GCM AAD so header tampering also invalidates the authentication tag
- [01-03]: Public key returned as plain bytes (not SecretBytes) -- WireGuard public keys are non-secret by design
- [01-03]: Standard base64 (not url-safe) used for key encoding -- matches wg CLI output format
- [01-03]: IPPool uses ip_network(strict=False) for user-friendly host-bit input (e.g., 10.0.0.1/24)
- [Phase 01-04]: validate_subnet uses strict=False to accept server IP format (10.0.0.1/24) -- strict=True wrongly rejected valid server IPs with host bits set
- [Phase 01-04]: autoescape=False in Jinja2 Environment is correct for WireGuard INI -- autoescape=True would corrupt base64 = characters to HTML entities
- [Phase 01-04]: atomic_write extracted from vault.py to security/atomic.py -- single source of truth for atomic writes
- [02-01]: Lazy imports in get_adapter() isolate platform-specific stdlib (winreg, etc.) from cross-OS imports
- [02-01]: validate_firewall_rules is both a module-level function and a concrete adapter method -- standalone use and subclass inheritance via delegation
- [02-01]: PrivilegeError message format locked per platform: "sudo wg-automate" (Unix) vs "Run as Administrator" (Windows)
- [02-01]: Progress.fail() uses (current - 1) for "steps completed" count to give accurate recovery hint
- [Phase 02-platform-hardening]: _build_nftables_ruleset() used for both generated and template strings so FW-03 comparison is always symmetric
- [Phase 02-platform-hardening]: deploy_config does not call set_file_permissions after atomic_write -- 0o600 is set on temp file before rename, making the extra chmod redundant
- [Phase 02-platform-hardening]: ctypes.windll.shell32.IsUserAnAdmin() for privilege check on Windows -- no auto-elevation per locked decision
- [Phase 02-platform-hardening]: os.chmod NEVER called in Windows code -- only icacls via set_file_permissions (PLAT-06)
- [Phase 02-platform-hardening]: wireguard.exe /installtunnelservice manages DPAPI config encryption automatically
- [03-01]: urllib + ssl.create_default_context() used for HTTPS (not requests) to avoid new dependency
- [03-01]: ThreadPoolExecutor with as_completed(timeout=10) prevents hanging source from blocking indefinitely
- [03-01]: update_dns always returns result dict even on failure so callers can pass it to audit.log() before re-raising
- [03-01]: DuckDNS error message truncates response body to 20 chars to prevent token fragments leaking in logs
- [Phase 03-dynamic-dns-and-audit]: Permission-after-write on Windows: icacls called AFTER first write to prevent process self-lockout; AUDIT-02 fully enforced only as SYSTEM/Administrator
- [Phase 03-dynamic-dns-and-audit]: WireGuard key regex accepts {42,43} base64 chars + = to match plan test vector (43 chars) and real keys (44 chars)
- [04-01]: Lazy imports inside Click command functions keep wg-automate --help fast (Vault, adapters, keygen imported inside function bodies)
- [04-01]: click.ClickException wraps all exception paths so Python tracebacks never leak to users (passphrase fragments could appear in locals)
- [04-01]: lock command does not require passphrase and must never fail; audit log write is silently swallowed in except Exception
- [04-01]: wg show PrivateKey assertion in status command is defense-in-depth; wg show does not output private keys but we assert it explicitly

### Pending Todos

None.

### Blockers/Concerns

- [Phase 3]: Windows WireGuard tunnel service API (wireguard.exe /installtunnelservice + DPAPI) implemented per research -- needs runtime verification on actual Windows with WireGuard installed
- [Phase 2]: macOS SIP/TCC restrictions evolve per release -- pfctl anchor approach needs testing on current macOS
- [Phase 5]: PyInstaller behavior with ctypes mlock calls needs verification

## Session Continuity

Last session: 2026-03-20
Stopped at: Completed 04-01-PLAN.md (Click CLI: 14-command group, init/status/verify/lock/change-passphrase implementations, 9 stubs for 04-02/04-03)
Resume file: None
