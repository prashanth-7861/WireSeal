# Roadmap: wg-automate

## Overview

wg-automate delivers a cross-platform WireGuard VPN server automation CLI with a security-first architecture where zero secrets ever touch disk unencrypted. The build order is dictated by the security dependency chain: secret types and vault first (everything depends on them), then platform abstraction (every WireGuard operation is platform-specific), then DNS and audit (independent features on a proven foundation), then the CLI surface (thin layer over proven operations), and finally tests and packaging (validation, not development). Five phases, 57 requirements, one invariant: the vault is the single point of trust.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Secure Core Engine** - Security primitives, encrypted vault, key generation, config builder, and IP pool (completed 2026-03-18)
- [ ] **Phase 2: Platform Hardening** - ABC-based platform adapters for Linux, macOS, and Windows with firewall and service management
- [ ] **Phase 3: Dynamic DNS and Audit** - Multi-source IP consensus, DuckDNS integration, and append-only audit logging
- [ ] **Phase 4: CLI and Client Management** - Full 14-command Click CLI with client lifecycle, key rotation, and QR display
- [ ] **Phase 5: Tests and Packaging** - Security-focused test suite, Docker integration tests, PyInstaller binaries, and signed releases

## Phase Details

### Phase 1: Secure Core Engine
**Goal**: Users have a cryptographically sound foundation where secrets are type-safe, vault-encrypted, and never exposed -- all downstream phases build on this proven base
**Depends on**: Nothing (first phase)
**Requirements**: SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, SEC-06, VAULT-01, VAULT-02, VAULT-03, VAULT-04, VAULT-05, VAULT-06, VAULT-07, VAULT-08, KEYGEN-01, KEYGEN-02, KEYGEN-03, KEYGEN-04, CONFIG-01, CONFIG-02, CONFIG-03, CONFIG-04, CONFIG-05, CONFIG-06, IP-01, IP-02, IP-03, HARD-01, HARD-02, HARD-03
**Success Criteria** (what must be TRUE):
  1. `SecretBytes` wrapper prevents secret exposure in repr, str, tracebacks, and serialization -- and wipes memory on release
  2. Vault encrypts and decrypts state via context manager; wrong passphrase and tampered ciphertext are both rejected immediately
  3. X25519 key pairs and per-peer PSKs are generated in-process (never via subprocess) and stored only in the vault
  4. Generated WireGuard configs pass the pre-apply validator (key format, IP conflicts, INI injection, subnet rules) and are written atomically with correct permissions
  5. Config integrity is tracked via SHA-256 hashes stored in the vault; tampering is detected before any reload
**Plans**: 4 plans

Plans:
- [x] 01-01-PLAN.md — SecretBytes type and memory safety primitives (security/secret_types.py, security/secrets_wipe.py)
- [x] 01-02-PLAN.md — Encrypted vault with Argon2id KDF and AES-256-GCM (security/vault.py)
- [x] 01-03-PLAN.md — Key generation, PSK, and IP pool management (core/keygen.py, core/psk.py, core/ip_pool.py)
- [ ] 01-04-PLAN.md — Config builder, validator, integrity tracking, and atomic writes (core/config_builder.py, security/validator.py, security/integrity.py, security/permissions.py)

### Phase 2: Platform Hardening
**Goal**: Users can run one-command server setup on Linux, macOS, or Windows with platform-native firewall hardening, service management, and correct file permissions
**Depends on**: Phase 1
**Requirements**: PLAT-01, PLAT-02, PLAT-03, PLAT-04, PLAT-05, PLAT-06, FW-01, FW-02, FW-03
**Success Criteria** (what must be TRUE):
  1. Platform is detected at startup and the tool refuses to run without root/admin, on unsupported OS, or with missing prerequisites
  2. All three platform adapters implement the same AbstractPlatformAdapter ABC -- missing methods cause import-time failure
  3. WireGuard is installed, configured, and started as a persistent service on each platform (systemd / launchd / Windows tunnel service)
  4. Firewall rules are deny-by-default on the WireGuard interface with rate-limited UDP accept and NAT masquerade only on the outbound interface
  5. File permissions use os.chmod(600) on Unix and icacls/pywin32 ACLs on Windows -- os.chmod is never used for security on Windows
**Plans**: TBD

Plans:
- [ ] 02-01: Platform detection and AbstractPlatformAdapter ABC (platform/detect.py, platform/base.py)
- [ ] 02-02: Linux adapter -- systemd, nftables/iptables, sysctl (platform/linux.py)
- [ ] 02-03: macOS adapter -- launchd, pfctl, sysctl (platform/macos.py)
- [ ] 02-04: Windows adapter -- tunnel service, netsh, registry, DPAPI (platform/windows.py)

### Phase 3: Dynamic DNS and Audit
**Goal**: Users have hardened DuckDNS integration with multi-source IP consensus and a tamper-evident append-only audit trail of every tool action
**Depends on**: Phase 2
**Requirements**: DNS-01, DNS-02, DNS-03, DNS-04, DNS-05, AUDIT-01, AUDIT-02, AUDIT-03
**Success Criteria** (what must be TRUE):
  1. Public IP is detected by querying 3 independent HTTPS sources with 2-of-3 consensus required; no consensus means no DNS update (fail closed)
  2. DuckDNS updates use HTTPS with certificate verification, token stored encrypted in vault, and every attempt is logged to the audit log
  3. Scheduled DNS updates run as a non-root user on all platforms (cron / launchd / Task Scheduler)
  4. Every tool action is logged with ISO 8601 UTC timestamp and no secrets ever appear in log entries
**Plans**: TBD

Plans:
- [ ] 03-01: Multi-source IP resolver and DuckDNS integration (dns/ip_resolver.py, dns/duckdns.py)
- [ ] 03-02: Append-only audit logging with platform-appropriate permissions (security/audit.py)

### Phase 4: CLI and Client Management
**Goal**: Users can manage the full WireGuard lifecycle through 14 CLI commands -- adding, removing, rotating, exporting, and inspecting clients with vault-secured operations
**Depends on**: Phase 3
**Requirements**: CLIENT-01, CLIENT-02, CLIENT-03, CLIENT-04, CLIENT-05, CLIENT-06, CLIENT-07, CLIENT-08, CLI-01, CLI-02, CLI-03, CLI-04, CLI-05
**Success Criteria** (what must be TRUE):
  1. `init` command creates vault, generates server keys, configures firewall, installs WireGuard service, and sets up DuckDNS -- all in one command
  2. `add-client` generates keypair + PSK, allocates IP, updates server config via `wg syncconf` with file locking, and displays QR in terminal
  3. `remove-client` revokes peer immediately (no grace period), reloads WireGuard, releases IP, purges keys from vault, and logs the action
  4. `rotate-keys` and `rotate-server-keys` generate new key material, update all affected configs, wipe old keys, and reload WireGuard
  5. All passphrase inputs use hidden prompts (never echoed, never in command arguments); `lock` wipes all decrypted state; `verify` detects config tampering
**Plans**: TBD

Plans:
- [ ] 04-01: Click CLI skeleton and init/status/verify/lock/change-passphrase commands (main.py)
- [ ] 04-02: Client lifecycle commands -- add, remove, list, show-qr, export (main.py, core/qr_generator.py)
- [ ] 04-03: Key rotation commands and audit-log display (main.py)

### Phase 5: Tests and Packaging
**Goal**: Users can trust the release through a comprehensive security test suite and download verified standalone binaries for their platform
**Depends on**: Phase 4
**Requirements**: TEST-01, TEST-02, TEST-03, TEST-04, TEST-05, PKG-01, PKG-02, PKG-03, PKG-04
**Success Criteria** (what must be TRUE):
  1. Unit tests cover all security-critical components: vault round-trip, wrong-passphrase rejection, tampered ciphertext rejection, key validity, validator rejection of malformed configs, permission enforcement, and IP pool collision prevention
  2. Docker integration test runs the full lifecycle: init, add-client, verify WireGuard interface up, remove-client, verify peer gone
  3. Config tampering integration test: modify a deployed config, run verify, confirm detection
  4. Argon2id KDF benchmark confirms >500ms on target hardware
  5. PyInstaller standalone binaries are built for Linux, macOS, and Windows with GPG-signed release artifacts and published checksums
**Plans**: TBD

Plans:
- [ ] 05-01: Security-focused unit test suite (tests/)
- [ ] 05-02: Docker integration tests and Argon2id benchmark (tests/)
- [ ] 05-03: PyInstaller packaging, GPG signing, and pyproject.toml (packaging/)

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Secure Core Engine | 4/4 | Complete   | 2026-03-18 |
| 2. Platform Hardening | 0/4 | Not started | - |
| 3. Dynamic DNS and Audit | 0/2 | Not started | - |
| 4. CLI and Client Management | 0/3 | Not started | - |
| 5. Tests and Packaging | 0/3 | Not started | - |
