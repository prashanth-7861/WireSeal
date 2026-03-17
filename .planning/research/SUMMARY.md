# Project Research Summary

**Project:** wg-automate (WireGuard VPN Server Automation CLI)
**Domain:** Security-hardened cross-platform VPN server management
**Researched:** 2026-03-17
**Confidence:** MEDIUM (all research from training data; web verification unavailable)

## Executive Summary

wg-automate is a security-hardened WireGuard VPN server automation CLI whose core value proposition is "zero plaintext secrets on disk, ever." No existing WireGuard management tool (wg-easy, PiVPN, Algo, netmaker) encrypts keys at rest -- they all store private keys as plaintext files. This is the project's reason to exist, and the encrypted vault must be architecturally bulletproof from day one. The recommended approach is to build the security primitives first (SecretBytes wrapper type, vault with AES-256-GCM + Argon2id), validate them thoroughly, and only then build features on top.

The stack is validated and sound: Python 3.12+ with click, cryptography, argon2-cffi, Jinja2, qrcode, and requests. The architecture follows a strict layered model where secrets flow DOWN into a vault context manager and NEVER propagate upward to the CLI or platform layers. Cross-platform support (Linux, macOS, Windows) is the largest complexity driver -- Windows in particular has fundamentally different behavior for file permissions (ACLs vs chmod), WireGuard service management (SYSTEM context), and atomic file operations.

The dominant risks are all in the cryptographic foundation: Python's inability to reliably zero memory (CRIT-1), AES-GCM nonce reuse destroying all confidentiality (CRIT-2), weak Argon2id parameters defeating the vault (CRIT-4), and secrets leaking through exception tracebacks (CRIT-5). All four must be addressed in Phase 1 before any WireGuard integration begins. The secondary risk cluster is cross-platform: Windows ACLs, Windows SYSTEM service context, and macOS SIP restrictions all require platform-specific code paths that cannot be deferred.

## Key Findings

### Recommended Stack

The stack is validated with HIGH confidence on version numbers (verified via pip index on 2026-03-17). Key adjustments from research:

- **Python >=3.12,<3.14** -- pin minimum to 3.12 (not 3.10). 3.10 reaches EOL October 2026. 3.12 is battle-tested with PyInstaller 6.19.0.
- **cryptography 46.0.5** -- X25519 key generation + AES-256-GCM vault encryption. Use `X25519PrivateKey.generate()` for in-process key gen (never shell out to `wg genkey`).
- **argon2-cffi 25.1.0** -- Argon2id KDF. Parameters must meet OWASP minimums: 64MiB memory floor, 3 iterations, 4 parallelism. Store params in vault header for future upgrades. The planned 256MiB is good for servers but make it configurable.
- **click 8.3.1** -- CLI framework. Consider adding `rich` (14.3.3) for polished terminal output. `rich-click` is optional.
- **Jinja2 3.1.6** -- Config templating with `StrictUndefined` (prevents silent variable omission in WireGuard configs).
- **pip-tools 7.5.3 + pip-audit 2.10.0** -- Hash-pinned dependencies with vulnerability scanning. This is the gold standard for supply-chain security in Python.
- **PyInstaller 6.19.0** -- Single-binary distribution. Windows builds require special attention: AV false positives, hidden imports for argon2-cffi, prefer `--onedir` over `--onefile` for security.

### Expected Features

**Must have (table stakes):**
- One-command server setup (`init`) with vault creation, key generation, firewall, service management
- Add/remove/list clients with automatic IP allocation
- QR code generation for mobile client onboarding (terminal-only, no disk persistence)
- Client config export with permission enforcement
- Server and peer status display
- Persistent state across reboots (platform service integration)

**Should have (differentiators -- this is what justifies the project):**
- Encrypted vault (AES-256-GCM + Argon2id) -- the core differentiator, no competitor has this
- Zero plaintext keys on disk -- extends vault guarantee to all file operations
- Per-peer PSK (post-quantum forward security) -- no competitor does this
- In-process key generation (no subprocess exposure via ps/proc)
- Key rotation (client and server) -- no competitor offers this
- Append-only audit log with HMAC integrity chain
- Pre-apply config validation (catches IP conflicts, malformed keys, INI injection)
- Config integrity tracking (SHA-256 hash detects out-of-band tampering)
- Multi-source IP consensus for DuckDNS (prevents DNS poisoning via compromised IP service)
- Emergency lock command

**Defer to v1.1:**
- disable-client / enable-client (temporary peer suspension)
- backup / restore (vault backup)
- diagnose (troubleshooting command)
- destroy (clean uninstall)

**Defer to v2+:**
- IPv6 dual-stack
- Hardware key (YubiKey) support
- Alternative DDNS providers
- Prometheus metrics

**Gap identified:** No uninstall/cleanup command is planned. Add a `destroy` command to v1.1 at minimum.

### Architecture Approach

The architecture is a strict layered model with a security perimeter enforced by types. The `SecretBytes` wrapper type is the foundation -- it uses mutable `bytearray` (not immutable `bytes`), prevents exposure via `__repr__`/`__str__`, uses constant-time comparison, blocks serialization, and attempts `mlock` to prevent swap. The vault operates as a context manager that decrypts state, yields it for use, and guarantees wipe on exit (even on exception). Platform differences are handled by an ABC-based adapter pattern with lazy imports (so platform-specific modules do not fail on import on other OSes).

**Key architectural correction from research:** Move `vault.py` from `core/` to `security/`. The vault IS the security boundary, not a utility. Everything in `core/` should receive already-decrypted data.

**Major components:**
1. `security/secret_types.py` -- SecretBytes/SecretStr wrappers (build FIRST, before anything else)
2. `security/vault.py` -- AES-256-GCM encrypted state with Argon2id KDF, context manager pattern
3. `security/` cluster -- permissions, audit, validator, integrity, firewall abstraction, secrets_wipe
4. `core/` cluster -- keygen, psk, ip_pool, config_builder, qr_generator (pure domain logic)
5. `platform/` cluster -- ABC base + Linux/macOS/Windows adapters with lazy factory
6. `dns/` cluster -- DuckDNS integration + multi-source IP resolver
7. `main.py` -- Click CLI group, command dispatch, NEVER holds secrets directly

### Critical Pitfalls

The top 5 pitfalls that must be addressed, all in or before Phase 1:

1. **CRIT-1: Python secrets survive in memory indefinitely** -- Use `bytearray` (mutable, can be zeroed), never `str` or `bytes` for secrets. Implement `SecretBytes` with `mlock` and explicit `wipe()`. Disable core dumps via `resource.setrlimit`. This is the foundation everything else depends on.

2. **CRIT-2: AES-GCM nonce reuse destroys all confidentiality** -- Generate a fresh random 96-bit nonce via `os.urandom(12)` for every encryption. Prepend nonce to ciphertext. Include vault version as AAD to prevent downgrade attacks. Never use counters or timestamps as nonces.

3. **CRIT-4: Weak Argon2id parameters defeat the vault** -- Enforce minimums: 64MiB memory, 3 iterations, 4 parallelism. Store parameters in vault header for future upgrades. Benchmark on target hardware at vault creation time.

4. **CRIT-5: Secrets leak through exception tracebacks** -- Wipe secrets in `finally` blocks before exceptions propagate. Use `raise NewException("message") from None` to suppress traceback chaining. Never use `logging.exception()` near secret-handling code. Install custom `sys.excepthook`.

5. **CRIT-3: WireGuard config reload race condition** -- Always use `wg syncconf` (never `wg setconf` or `wg-quick` for live updates). File-lock the entire read-modify-write-apply cycle. IP allocation must happen inside the same lock.

## Implications for Roadmap

Based on combined research, the planned 5-phase structure is sound but needs refinement. The security foundation must be uncompromising in Phase 1, and cross-platform work must be pulled earlier than typical because it affects every subsequent phase.

### Phase 1: Secure Core Engine
**Rationale:** Every other component depends on the security primitives being correct. The vault is the single point of trust. Building features before the foundation is solid means retrofitting security later -- which never works.
**Delivers:** SecretBytes type, vault (encrypt/decrypt/context manager), Argon2id KDF with configurable parameters, atomic file writes, file permission enforcement, audit logging skeleton, key generation (X25519 + PSK), IP pool allocator, config builder with Jinja2 + StrictUndefined, config validator.
**Addresses features:** Encrypted vault, zero plaintext keys, in-process key generation, per-peer PSK, config validation.
**Must avoid:** CRIT-1 (memory leaks), CRIT-2 (nonce reuse), CRIT-4 (weak Argon2), CRIT-5 (traceback leaks), MOD-5 (random module misuse).
**Research flag:** Standard patterns -- well-documented crypto primitives, no phase-specific research needed.

### Phase 2: Platform Hardening + WireGuard Integration
**Rationale:** Cross-platform is a foundational concern, not a feature to bolt on later. File permissions, service management, and firewall rules are all platform-specific. If the abstraction layer is wrong, it contaminates every feature.
**Delivers:** PlatformAdapter ABC + Linux/macOS/Windows implementations, WireGuard config deployment with file locking, `wg syncconf` integration, firewall rule application (nftables/pfctl/netsh), service management (systemd/launchd/Windows service).
**Addresses features:** One-command server setup, persistent state across reboots, firewall hardening, cross-platform support.
**Must avoid:** HIGH-1 (Windows ACL), HIGH-2 (Windows SYSTEM context), HIGH-3 (macOS SIP), CRIT-3 (reload race), HIGH-5 (IP pool race), MOD-1 (INI injection), MOD-2 (os.replace Windows edge cases).
**Research flag:** NEEDS RESEARCH -- Windows WireGuard service management (DPAPI config store, named pipe IPC, tunnel service API) is not fully documented in training data. macOS SIP/TCC restrictions evolve per release and need current verification.

### Phase 3: Dynamic DNS + Audit Logging
**Rationale:** DuckDNS integration and audit logging are independent features that can be built on the stable foundation from Phases 1-2. Both involve secrets (DuckDNS token, audit integrity) and benefit from the vault and security primitives being proven.
**Delivers:** Multi-source IP consensus, DuckDNS HTTPS integration with token-in-vault, append-only audit log with HMAC chain, config integrity tracking (SHA-256).
**Addresses features:** DDNS integration, multi-source IP consensus, audit logging, config integrity tracking.
**Must avoid:** HIGH-6 (DuckDNS token exposure), MOD-4 (audit log injection/tampering).
**Research flag:** Standard patterns -- DuckDNS API is simple HTTPS, audit logging is well-documented.

### Phase 4: CLI Polish + Advanced Commands
**Rationale:** The full CLI surface area should be wired up only after the underlying operations are proven. Key rotation is the most complex command (requires coordinated client updates) and benefits from stable vault and platform layers.
**Delivers:** Full Click CLI with all 14+ commands wired, key rotation (client + server), emergency lock, rich terminal output, QR code display, JSON output mode.
**Addresses features:** Key rotation, lock command, terminal-only QR, all table-stakes commands via CLI.
**Must avoid:** MIN-1 (QR display on Windows console), MIN-2 (Click version compat).
**Research flag:** Standard patterns -- Click CLI wiring is straightforward.

### Phase 5: Tests + Packaging + Distribution
**Rationale:** Integration tests and packaging are the final validation layer. PyInstaller has known platform-specific gotchas that are best addressed after the code is feature-complete.
**Delivers:** Unit test suite (no privileges needed), integration tests (Docker-based, requires root), PyInstaller builds for Linux/macOS/Windows, code signing, GPG-signed releases, CI/CD pipeline with pip-audit.
**Addresses features:** Cross-platform binary distribution, supply-chain security.
**Must avoid:** HIGH-4 (PyInstaller temp directory injection), PyInstaller hidden import issues for cryptography/argon2-cffi.
**Research flag:** NEEDS RESEARCH -- PyInstaller behavior with ctypes mlock calls, current AV false positive mitigation strategies, and code signing workflows should be verified against current PyInstaller 6.19.0 documentation.

### Phase Ordering Rationale

- **Security first, features second:** The vault and SecretBytes type are load-bearing for every subsequent phase. Building them first and proving them with unit tests prevents the most catastrophic class of bugs (plaintext key leaks).
- **Platform early, not late:** Cross-platform is architectural, not a feature toggle. The PlatformAdapter ABC must be defined before any WireGuard integration, because every WireGuard operation (deploy config, start tunnel, apply firewall) is platform-specific.
- **DNS and audit are independent:** These can be developed in parallel if needed. Neither blocks the other.
- **CLI wiring last:** The CLI is a thin layer over proven operations. Wiring it up last ensures every command's underlying logic is tested before it gets a user-facing interface.
- **Packaging is validation, not development:** PyInstaller builds are the final proof that everything works as a standalone binary.

### Research Flags

**Phases needing deeper research during planning:**
- **Phase 2 (Platform Hardening):** Windows WireGuard service management is the biggest unknown. The DPAPI-encrypted config store, named pipe IPC, and tunnel service API need current documentation review. macOS SIP/TCC restrictions need verification on current macOS versions.
- **Phase 5 (Packaging):** PyInstaller behavior with ctypes mlock, hidden import requirements, and AV false positive mitigation need current verification.

**Phases with standard, well-documented patterns (skip research):**
- **Phase 1 (Secure Core):** Crypto primitives are well-documented (NIST, RFC 9106, OWASP). Python security patterns for SecretBytes are established.
- **Phase 3 (DNS + Audit):** DuckDNS API is trivial. Audit logging with HMAC chains is a standard pattern.
- **Phase 4 (CLI):** Click CLI framework is extremely well-documented.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Version numbers verified via pip index on 2026-03-17. Library choices are well-established. |
| Features | MEDIUM | Competitor analysis based on training data. Tools analyzed have stable feature sets but may have added features recently (especially wg-easy). |
| Architecture | MEDIUM | Security patterns (SecretBytes, vault context manager, ABC adapters) are well-established. Vault data format and component boundaries are sound. Windows DPAPI integration needs verification. |
| Pitfalls | MEDIUM-HIGH | Critical pitfalls (memory, nonce, Argon2, tracebacks) are based on well-documented language/crypto properties. Platform-specific pitfalls (Windows SYSTEM, macOS SIP, PyInstaller) are MEDIUM confidence and need current verification. |

**Overall confidence:** MEDIUM -- the crypto and security foundations are HIGH confidence, but cross-platform specifics (especially Windows) introduce uncertainty that must be resolved during Phase 2 planning.

### Gaps to Address

- **Windows WireGuard tunnel service API:** Current behavior of `wireguard.exe /installtunnelservice` and named pipe IPC needs verification. This is the biggest unknown in the project.
- **macOS SIP/TCC on current versions:** Restrictions evolve per release. pfctl anchor approach needs testing on current macOS.
- **Argon2id benchmarking on target hardware:** The 256MiB default needs validation on low-end targets (Raspberry Pi, small VPS). May need auto-tuning at vault creation.
- **PyInstaller + ctypes mlock interaction:** Unknown whether PyInstaller bundles correctly handle ctypes calls to mlock/VirtualLock.
- **Uninstall/cleanup command:** Not in the current 14-command plan. Should be added to v1.1 scope at minimum.
- **Client enable/disable:** Temporary peer suspension is a competitor feature gap. Should be scoped for v1.1.
- **Vault backup/restore:** The vault is a single point of failure for all key material. Backup mechanism should be prioritized.

## Sources

### Primary (HIGH confidence)
- PyPI version data: verified via `pip index versions` on 2026-03-17
- NIST SP 800-38D: AES-GCM specification and nonce requirements
- RFC 9106: Argon2 Memory-Hard Function parameter guidance
- CPython memory allocator documentation (pymalloc arenas, bytearray mutability)
- Python `os.chmod` documentation on Windows behavior
- Python `hmac.compare_digest` constant-time comparison

### Secondary (MEDIUM confidence)
- OWASP Password Storage Cheat Sheet: Argon2id parameter recommendations (verify current version)
- WireGuard protocol documentation at wireguard.com (verify `wg syncconf` behavior per platform)
- PyInstaller 6.x documentation on operating modes and extraction behavior
- WireGuard Windows architecture (tunnel service, DPAPI config store)
- macOS SIP/TCC restriction documentation

### Tertiary (LOW confidence)
- uv (Astral) maturity assessment: rapidly evolving, may be production-ready now
- WireGuard named pipe IPC on Windows: needs current documentation
- PyInstaller AV false positive mitigation strategies: evolving landscape

---
*Research completed: 2026-03-17*
*Ready for roadmap: yes*
