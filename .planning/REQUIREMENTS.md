# Requirements: wg-automate

**Defined:** 2026-03-17
**Core Value:** Zero plaintext secrets on disk, ever -- if the vault is compromised without the passphrase, no key material is exposed.

## v1 Requirements

### Vault (Encrypted State Storage)

- [x] **VAULT-01**: User's private keys and tokens are stored encrypted at rest using AES-256-GCM with Argon2id-derived key (256MB/4iter/4par) -- vault file at `~/.wg-automate/vault.enc` (chmod 600)
- [x] **VAULT-02**: Vault directory `~/.wg-automate/` is created with 700 permissions; on Windows, ACL is set via icacls/pywin32 (SYSTEM + Administrators only; no Users)
- [x] **VAULT-03**: Master passphrase is collected via `getpass` (never echoed, never logged); minimum 12 characters enforced
- [x] **VAULT-04**: Vault state is decrypted to memory only, operated on in a context manager (`with vault.open() as state:`), and wiped in the `finally` block even on exception
- [x] **VAULT-05**: All vault writes are atomic -- written to `.tmp` with `O_CREAT|O_EXCL`, fsynced, then renamed via `os.replace()` (cross-platform atomic, unlike `os.rename()`)
- [x] **VAULT-06**: Tampered vault (wrong passphrase or modified ciphertext) is detected and rejected immediately via GCM authentication tag -- no partial decryption
- [x] **VAULT-07**: Vault passphrase can be changed without losing state (`change_passphrase(old, new)` -- decrypt with old, re-encrypt with new, atomic write)
- [x] **VAULT-08**: Vault integrity can be verified on demand (`verify_integrity()` -- checks AES-GCM tag + Argon2 salt integrity)

### Secret Types and Memory Safety

- [x] **SEC-01**: A `SecretBytes` wrapper type (using `bytearray`, not `bytes`) is implemented as the very first component -- overrides `__repr__`, `__str__`, `__eq__`, `__hash__`, `__getstate__` to prevent accidental secret exposure in logs, tracebacks, or serialization
- [x] **SEC-02**: `SecretBytes` calls `mlock()` via ctypes (best-effort, no exception on failure) to prevent secret memory from being swapped to disk
- [x] **SEC-03**: `secrets_wipe.wipe_bytes(bytearray)` overwrites memory with zeros, random bytes, zeros before releasing; `wipe_string(str)` uses ctypes to overwrite the internal buffer (best-effort)
- [x] **SEC-04**: All config/key generation uses `bytearray`/`SecretBytes` buffers -- secrets are never held in immutable Python `str` or `bytes` longer than necessary
- [x] **SEC-05**: Exception handlers wipe secrets in `finally` blocks; traceback chaining is suppressed with `raise X from None` where secrets could appear in frame locals
- [x] **SEC-06**: AES-GCM nonces are generated with `os.urandom(12)` per encryption operation -- nonce reuse is architecturally impossible (never counters, never timestamps)

### Key Generation

- [x] **KEYGEN-01**: Server and client Curve25519 key pairs are generated using `cryptography.X25519PrivateKey.generate()` -- no subprocess call to `wg genkey` (keys never appear in `ps aux`)
- [x] **KEYGEN-02**: Generated private keys are extracted as `bytearray` (raw bytes), base64-encoded in memory, and passed directly to the vault -- they never touch disk unencrypted
- [x] **KEYGEN-03**: Per-peer pre-shared keys (PSK) are generated using `os.urandom(32)` -- 256-bit symmetric layer on top of Curve25519 for post-quantum resistance; every peer gets a unique PSK (no reuse)
- [x] **KEYGEN-04**: After use, key bytes are wiped via `secrets_wipe.wipe_bytes()` before the buffer is released

### Config Generation and Validation

- [x] **CONFIG-01**: Server and client WireGuard configs are rendered in memory using Jinja2 templates with `undefined=StrictUndefined` and `autoescape=True` -- missing variables cause hard failure, not empty strings
- [x] **CONFIG-02**: Pre-apply validator runs on every generated config before it is written or any service is reloaded; validator checks: key format (base64, 44 chars, decodes to 32 bytes), PSK format, IP validity (RFC 1918, correct subnet, no conflicts), port range (1024-65535), no duplicate peers, no overlapping AllowedIPs, endpoint format, no INI injection characters (`[`, `]`, `=`, newlines) in any field
- [x] **CONFIG-03**: All config file writes are atomic (`os.replace()` pattern); configs are written with 600 permissions (Unix) or SYSTEM+Administrators ACL (Windows)
- [x] **CONFIG-04**: After writing any config file, SHA-256 hash is computed and stored in the vault; before WireGuard reload, hash is verified -- tampered configs cause hard stop with user alert
- [x] **CONFIG-05**: WireGuard peers are updated via `wg syncconf` (not `wg setconf`) to preserve active sessions; the entire read-modify-write-apply cycle is protected by a file lock to prevent TOCTOU races
- [x] **CONFIG-06**: Client names are validated as alphanumeric + hyphens only, max 32 characters -- path traversal and INI injection via name are impossible

### IP Pool Management

- [x] **IP-01**: VPN subnet is configurable (default `10.0.0.0/24`); server always gets `.1`; clients get sequential addresses starting at `.2`
- [x] **IP-02**: IP allocation table is stored in the vault (encrypted); before assigning, conflicts are validated and subnet is verified as RFC 1918
- [x] **IP-03**: IP is released immediately and unconditionally when a client is removed -- no grace period

### Platform Detection and Setup

- [ ] **PLAT-01**: OS and version are detected at startup; tool refuses to run if not root/admin, OS is unsupported/EOL, or required tools are missing and cannot be installed
- [ ] **PLAT-02**: Platform modules implement a shared `AbstractPlatformAdapter` ABC -- all three platforms (Linux, macOS, Windows) implement the same interface; missing method implementations cause import-time failure
- [ ] **PLAT-03**: Linux setup installs WireGuard via package manager (with GPG signature verification), writes server config with atomic write + 600 permissions, enables IP forwarding via `/etc/sysctl.d/99-wireguard.conf`, applies nftables deny-by-default firewall (rate limit: 5 new connections/second burst 10), enables `wg-quick@wg0` via systemd, sets up DuckDNS cron as non-root `wg-automate` user
- [ ] **PLAT-04**: macOS setup installs WireGuard via Homebrew, writes config with 600 permissions, enables IP forwarding via `/etc/sysctl.conf`, applies pfctl deny-by-default firewall anchor, configures launchd plist for auto-start and DuckDNS updates
- [ ] **PLAT-05**: Windows setup installs WireGuard via winget (verifies installer signature), writes config to `%ProgramData%\WireGuard\wg0.conf` with SYSTEM+Administrators ACL only, sets `IPEnableRouter=1` in registry (warns about reboot), applies `netsh advfirewall` deny-by-default on WG interface, installs tunnel service via `wireguard.exe /installtunnelservice`, sets up DuckDNS via Task Scheduler
- [ ] **PLAT-06**: File permission enforcement uses `os.chmod(600)` on Unix and `icacls`/`pywin32` on Windows -- `os.chmod()` is NOT used on Windows for security (it only sets read-only flag, not ACLs)

### Firewall Hardening

- [ ] **FW-01**: All platform firewall configurations are deny-by-default on the WireGuard interface -- only established/related traffic and rate-limited new UDP connections on the WireGuard port are accepted
- [ ] **FW-02**: NAT masquerade is applied only on the detected outbound interface (via default route), not globally
- [ ] **FW-03**: Generated firewall rules are validated against expected deny-by-default templates before application

### Dynamic DNS

- [ ] **DNS-01**: Public IP is detected by querying 3 independent sources (ipify, amazonaws, icanhazip) over HTTPS with certificate verification; 2-of-3 consensus is required -- if no consensus, DNS update fails closed (no update, log warning)
- [ ] **DNS-02**: Validated public IP is verified as a public IPv4 address (private ranges, multicast, loopback rejected)
- [ ] **DNS-03**: DuckDNS token is stored encrypted in the vault -- never in plaintext on disk or in process arguments
- [ ] **DNS-04**: DuckDNS updates use HTTPS only with TLS certificate verification; response must be exactly `"OK"` -- anything else is a failure; every attempt is logged to the audit log
- [ ] **DNS-05**: Scheduled DNS updates run as a non-root user (Linux cron / macOS launchd / Windows Task Scheduler)

### Client Management

- [ ] **CLIENT-01**: `add-client <name>` generates a keypair + PSK, allocates an IP, updates server config, verifies integrity, reloads WireGuard via `wg syncconf`, and displays QR in terminal -- all in one command
- [ ] **CLIENT-02**: `remove-client <name>` removes peer from server config immediately with no grace period, reloads WireGuard, releases IP, purges keys from vault, and logs the revocation
- [ ] **CLIENT-03**: `list-clients` displays client names, IPs, and last handshake times -- never displays private keys or PSKs
- [ ] **CLIENT-04**: `show-qr <name>` displays client config as terminal QR code (ASCII art only); requires vault unlock; terminal is cleared after 60 seconds
- [ ] **CLIENT-05**: `rotate-keys <name>` generates a new keypair + PSK for a client, updates both server and client configs, wipes old keys from vault, reloads WireGuard, and displays new QR
- [ ] **CLIENT-06**: `rotate-server-keys` regenerates server keypair, updates all client configs with new server public key, reloads WireGuard
- [ ] **CLIENT-07**: `export <name> <path>` writes client config to file with 600 permissions; warns user that the file contains private key; user is advised to delete after use
- [ ] **CLIENT-08**: QR code is generated in memory using pure-Python `qrcode` library; by default, no image file is written; `--save-qr` flag writes with 600 permissions and optional `--auto-delete` removes after 5 minutes

### Audit Logging

- [ ] **AUDIT-01**: Every tool action is logged to an append-only audit log with ISO 8601 UTC timestamp, action type, and relevant metadata -- no secrets (keys, tokens, passphrases) ever appear in log entries
- [ ] **AUDIT-02**: Audit log file has 640 permissions (root read/write, group read) on Linux/macOS; SYSTEM-only on Windows
- [ ] **AUDIT-03**: `audit-log` command displays the last 50 log entries

### CLI Interface

- [ ] **CLI-01**: All 14 commands are implemented: `init`, `add-client`, `remove-client`, `list-clients`, `show-qr`, `rotate-keys`, `rotate-server-keys`, `update-dns`, `status`, `export`, `audit-log`, `verify`, `lock`, `change-passphrase`
- [ ] **CLI-02**: All passphrase inputs use `click.prompt(hide_input=True)` -- never echoed, never in command arguments
- [ ] **CLI-03**: `verify` command checks SHA-256 of all deployed config files against vault records and reports any tampering
- [ ] **CLI-04**: `lock` command wipes all decrypted state from memory and exits
- [ ] **CLI-05**: `status` command shows connected peers, transfer stats, and last handshake times from `wg show` output -- no key material displayed

### Security Hardening

- [x] **HARD-01**: Python minimum version is 3.12 (3.10 reaches EOL October 2026; 3.12 is the stable cross-platform target through 2028)
- [x] **HARD-02**: All dependencies are pinned with SHA-256 hashes in `requirements.txt` (via pip-tools `--generate-hashes`); installation requires `pip install --require-hashes`
- [x] **HARD-03**: `pip-audit` is run against pinned requirements as a CI validation step to catch known CVEs
- [ ] **HARD-04**: Process privilege is dropped after setup where possible; DuckDNS scheduled tasks run as non-root/non-SYSTEM user

### Test Suite

- [ ] **TEST-01**: Unit tests cover all security-critical components: vault encrypt/decrypt round-trip, wrong-passphrase rejection, tampered ciphertext rejection, atomic write on crash, key validity (Curve25519 + base64), validator rejection of malformed/injected configs, permission enforcement, memory wipe (best-effort), IP pool collision prevention, config builder completeness
- [ ] **TEST-02**: Integration tests run in Docker (Linux): full `init` -> `add-client` -> verify WireGuard interface up -> `remove-client` -> verify peer gone
- [ ] **TEST-03**: Config tampering integration test: modify deployed config, run `verify`, confirm detection
- [ ] **TEST-04**: Argon2id parameter benchmark test: KDF time must exceed 500ms on target hardware
- [ ] **TEST-05**: All tests pass with zero failures before any release

### Packaging and Distribution

- [ ] **PKG-01**: `pyproject.toml` defines project metadata with pinned dependencies and SHA-256 hashes
- [ ] **PKG-02**: PyInstaller standalone single-file binaries are built for Linux, macOS, and Windows via platform CI matrix
- [ ] **PKG-03**: Release artifacts are GPG-signed; checksums published alongside binaries
- [ ] **PKG-04**: `README.md` documents the security model, threat model, and installation with hash verification

## v2 Requirements

### Advanced Security

- **ADV-01**: TOTP second factor for vault unlock (OWASP MFA recommendation)
- **ADV-02**: Hardware key support -- YubiKey/FIDO2 for vault unlock
- **ADV-03**: Automatic key rotation scheduler (zero-downtime peer update, N-day interval)
- **ADV-04**: Vault backup and restore with encrypted backup export

### Advanced Networking

- **NET-01**: IPv6 dual-stack VPN addressing alongside IPv4
- **NET-02**: Peer-to-peer mesh topology (clients communicate directly, not only through server)
- **NET-03**: Per-client AllowedIPs ACL (client A can reach file server but not SSH)

### Monitoring

- **MON-01**: Prometheus metrics export for connection stats and peer health
- **MON-02**: Fail2ban-style monitoring -- block IPs after repeated handshake failures

### DNS Providers

- **DNS-06**: Cloudflare DNS API alternative to DuckDNS
- **DNS-07**: Self-hosted PowerDNS support

### Deployment

- **DEPLOY-01**: Docker image with read-only filesystem and secrets via Docker secrets API
- **DEPLOY-02**: `disable-client <name>` -- temporary suspension without key deletion

## Out of Scope

| Feature | Reason |
|---------|--------|
| Web UI / dashboard | Contradicts security model -- browser attack surface, requires network-accessible port; CLI-only intentional |
| Real-time mesh topology (v1) | Server-client model sufficient; mesh is significant architecture change |
| Auto-update mechanism | Introduces supply chain risk; users should verify updates manually |
| Built-in DNS resolver | Out of scope for VPN automation; use system resolver |
| OAuth / SSO for vault unlock | Complexity; passphrase + optional TOTP sufficient |
| Telemetry / analytics | Explicitly excluded by design; zero phoning home |
| Mobile app | CLI tool only; QR code handles mobile client provisioning |
| Multi-server management | Out of scope for v1; single-server tool |

## Traceability

| Requirement | Phase | Plan | Status |
|-------------|-------|------|--------|
| SEC-01 | Phase 1 | 01-01 | Pending |
| SEC-02 | Phase 1 | 01-01 | Pending |
| SEC-03 | Phase 1 | 01-01 | Pending |
| SEC-04 | Phase 1 | 01-01 | Pending |
| SEC-05 | Phase 1 | 01-01 | Pending |
| SEC-06 | Phase 1 | 01-02 | Pending |
| VAULT-01 | Phase 1 | 01-02 | Pending |
| VAULT-02 | Phase 1 | 01-02 | Pending |
| VAULT-03 | Phase 1 | 01-02 | Pending |
| VAULT-04 | Phase 1 | 01-02 | Pending |
| VAULT-05 | Phase 1 | 01-02 | Pending |
| VAULT-06 | Phase 1 | 01-02 | Pending |
| VAULT-07 | Phase 1 | 01-02 | Pending |
| VAULT-08 | Phase 1 | 01-02 | Pending |
| KEYGEN-01 | Phase 1 | 01-03 | Pending |
| KEYGEN-02 | Phase 1 | 01-03 | Pending |
| KEYGEN-03 | Phase 1 | 01-03 | Pending |
| KEYGEN-04 | Phase 1 | 01-03 | Pending |
| IP-01 | Phase 1 | 01-03 | Pending |
| IP-02 | Phase 1 | 01-03 | Pending |
| IP-03 | Phase 1 | 01-03 | Pending |
| CONFIG-01 | Phase 1 | 01-04 | Pending |
| CONFIG-02 | Phase 1 | 01-04 | Pending |
| CONFIG-03 | Phase 1 | 01-04 | Pending |
| CONFIG-04 | Phase 1 | 01-04 | Pending |
| CONFIG-05 | Phase 1 | 01-04 | Pending |
| CONFIG-06 | Phase 1 | 01-04 | Pending |
| HARD-01 | Phase 1 | 01-01 | Pending |
| HARD-02 | Phase 1 | 01-04 | Pending |
| HARD-03 | Phase 1 | 01-04 | Pending |
| HARD-04 | Phase 2 | 02-01 | Pending |
| PLAT-01 | Phase 2 | 02-01 | Pending |
| PLAT-02 | Phase 2 | 02-01 | Pending |
| PLAT-03 | Phase 2 | 02-02 | Pending |
| PLAT-04 | Phase 2 | 02-03 | Pending |
| PLAT-05 | Phase 2 | 02-04 | Pending |
| PLAT-06 | Phase 2 | 02-01 | Pending |
| FW-01 | Phase 2 | 02-02 | Pending |
| FW-02 | Phase 2 | 02-02 | Pending |
| FW-03 | Phase 2 | 02-02 | Pending |
| DNS-01 | Phase 3 | 03-01 | Pending |
| DNS-02 | Phase 3 | 03-01 | Pending |
| DNS-03 | Phase 3 | 03-01 | Pending |
| DNS-04 | Phase 3 | 03-01 | Pending |
| DNS-05 | Phase 3 | 03-01 | Pending |
| AUDIT-01 | Phase 3 | 03-02 | Pending |
| AUDIT-02 | Phase 3 | 03-02 | Pending |
| AUDIT-03 | Phase 3 | 03-02 | Pending |
| CLIENT-01 | Phase 4 | 04-02 | Pending |
| CLIENT-02 | Phase 4 | 04-02 | Pending |
| CLIENT-03 | Phase 4 | 04-02 | Pending |
| CLIENT-04 | Phase 4 | 04-02 | Pending |
| CLIENT-05 | Phase 4 | 04-03 | Pending |
| CLIENT-06 | Phase 4 | 04-03 | Pending |
| CLIENT-07 | Phase 4 | 04-02 | Pending |
| CLIENT-08 | Phase 4 | 04-02 | Pending |
| CLI-01 | Phase 4 | 04-01 | Pending |
| CLI-02 | Phase 4 | 04-01 | Pending |
| CLI-03 | Phase 4 | 04-01 | Pending |
| CLI-04 | Phase 4 | 04-01 | Pending |
| CLI-05 | Phase 4 | 04-01 | Pending |
| TEST-01 | Phase 5 | 05-01 | Pending |
| TEST-02 | Phase 5 | 05-02 | Pending |
| TEST-03 | Phase 5 | 05-02 | Pending |
| TEST-04 | Phase 5 | 05-02 | Pending |
| TEST-05 | Phase 5 | 05-01 | Pending |
| PKG-01 | Phase 5 | 05-03 | Pending |
| PKG-02 | Phase 5 | 05-03 | Pending |
| PKG-03 | Phase 5 | 05-03 | Pending |
| PKG-04 | Phase 5 | 05-03 | Pending |

**Coverage:**
- v1 requirements: 57 total
- Mapped to phases: 57
- Mapped to plans: 57
- Unmapped: 0

**Notes:**
- HARD-04 (privilege drop after setup) moved from Phase 1 to Phase 2 -- it requires platform adapters to implement
- AUDIT-01 through AUDIT-03 moved from Phase 4 to Phase 3 -- audit logging is an independent feature that pairs naturally with DNS integration

---
*Requirements defined: 2026-03-17*
*Last updated: 2026-03-17 after roadmap creation*
