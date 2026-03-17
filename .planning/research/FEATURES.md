# Feature Landscape: WireGuard Server Management CLI Tools

**Domain:** WireGuard VPN server automation and management
**Researched:** 2026-03-17
**Overall confidence:** MEDIUM (training data only -- web search tools unavailable; findings based on well-established tools with stable feature sets)

## Methodology Note

WebSearch, WebFetch, and Brave Search were all unavailable during this research session. All findings are based on training data knowledge of the WireGuard management ecosystem. The tools analyzed (wg-easy, PiVPN, Algo, Streisand, wiresmith, dsnet, subspace, netmaker) have been stable and well-documented for years, so training data is reasonably reliable here. However, any claims about very recent changes (2025-2026) should be validated.

---

## Competitor Feature Matrix

Before categorizing, here is what existing tools actually provide:

| Feature | wg-easy | PiVPN | Algo | Streisand | netmaker | wg-automate (planned) |
|---------|---------|-------|------|-----------|----------|-----------------------|
| One-command setup | Yes (Docker) | Yes (curl\|bash) | Yes (Ansible) | Yes (Ansible) | Yes (Docker) | Yes (native) |
| Web UI | Yes | No | No | No | Yes | No (CLI only) |
| Client add/remove | Yes | Yes | Yes | Limited | Yes | Yes |
| QR code generation | Yes | Yes | No | No | Yes | Yes |
| Key generation | Automatic | Automatic | Automatic | Automatic | Automatic | Automatic (in-process) |
| Encrypted key storage | No | No | No | No | Partial | Yes (vault) |
| PSK per peer | No | No | No | No | No | Yes |
| DDNS integration | No | Yes (pivpn -d) | No | No | No | Yes (DuckDNS) |
| Firewall hardening | Partial | Yes (ufw) | Yes (iptables) | Yes | Yes | Yes (deny-by-default) |
| Audit logging | No | No | No | No | Partial | Yes (append-only) |
| Config validation | No | No | Partial | No | Partial | Yes (pre-apply) |
| Key rotation | No | No | No | No | No | Yes |
| Multi-platform | Linux (Docker) | Linux (Debian) | Linux (cloud) | Linux | Linux/Docker | Linux/macOS/Windows |
| Client listing | Yes | Yes | Yes | No | Yes | Yes |
| Config export | Yes (download) | Yes | Yes | Yes | Yes | Yes |

---

## Table Stakes

Features users expect from any WireGuard management tool. Missing any of these means users will choose a competitor.

| Feature | Why Expected | Complexity | wg-automate Status | Notes |
|---------|--------------|------------|-------------------|-------|
| One-command server setup | Every major tool (wg-easy, PiVPN, Algo) offers this. Users choose management tools specifically to avoid manual WireGuard config. | High | Planned | Cross-platform makes this harder than single-platform tools |
| Add/remove clients | The core workflow. Without CRUD for peers, users might as well edit configs by hand. | Medium | Planned (add-client, remove-client) | Must handle AllowedIPs allocation automatically |
| List clients with status | Users need to see who is connected and when they last handshaked. PiVPN and wg-easy both show this. | Low | Planned (list-clients, status) | Parse `wg show` output for handshake times |
| Automatic key generation | No tool requires users to run `wg genkey` separately. Key generation is always built in. | Low | Planned (Curve25519 in-process) | In-process generation is a differentiator on top of table stakes |
| QR code for mobile clients | PiVPN and wg-easy both generate QR codes. Mobile is a primary WireGuard use case. Without QR, onboarding mobile users requires manual config transfer. | Low | Planned (terminal-only) | Terminal-only default is a differentiator enhancement |
| Client config export | Users need to transfer configs to client devices. Every tool provides `.conf` file export. | Low | Planned (export command) | 600 permissions + warnings is a differentiator enhancement |
| Automatic IP address allocation | When adding a client, the tool must pick the next available IP in the subnet. Manual IP assignment is unacceptable UX. | Medium | Implied but not explicit | Must track allocated IPs in vault, detect conflicts |
| Persistent state across reboots | Server config must survive reboots. WireGuard interface must come up automatically. | Medium | Implied (systemd/launchd/service) | Platform service integration is essential |
| DNS configuration for clients | Clients need DNS servers set in their config. Common defaults: 1.1.1.1, 8.8.8.8, or the server itself if running a resolver. | Low | Implied | Should be configurable at init time |
| Uninstall/cleanup | PiVPN provides `pivpn uninstall`. Users need a way to cleanly remove everything. Not in the 14-command list. | Medium | GAP -- not in plan | Consider adding a `destroy` or `uninstall` command |

---

## Differentiators

Features that set wg-automate apart. These are not expected by users but represent genuine competitive advantages.

| Feature | Value Proposition | Complexity | wg-automate Status | Notes |
|---------|-------------------|------------|-------------------|-------|
| Encrypted vault (AES-256-GCM + Argon2id) | **The core differentiator.** No other WireGuard management tool encrypts keys at rest. PiVPN stores keys in `/etc/wireguard/` as plaintext. wg-easy stores them in a JSON file. This is wg-automate's reason to exist. | High | Planned | This alone justifies the project |
| Zero plaintext keys on disk | Extends the vault -- keys are generated in memory, encrypted, and never written unencrypted. Other tools all write plaintext private keys. | High | Planned | Requires careful implementation of memory handling |
| Per-peer PSK (post-quantum) | No competitor does this. PSK adds a symmetric encryption layer that quantum computers cannot break. With NIST PQC standards arriving, this is forward-looking security. | Medium | Planned | Low implementation cost, high security value |
| In-process key generation (no subprocess) | Other tools shell out to `wg genkey` which exposes keys in process arguments visible via `ps aux`. Using `cryptography` library's X25519 avoids this. | Low | Planned | Simple but meaningful security improvement |
| Key rotation commands | No competitor offers key rotation. Users of other tools must manually regenerate and redistribute. `rotate-keys` and `rotate-server-keys` are genuinely novel. | High | Planned | Server key rotation requires coordinated client updates |
| Append-only audit log | No competitor has audit logging. For compliance-sensitive environments (SOC2, HIPAA-adjacent), knowing who was added/removed/when is valuable. | Medium | Planned | "No secrets in logs" is critical -- audit log must never contain key material |
| Pre-apply config validation | Prevents broken WireGuard configs from being applied. Catches IP conflicts, malformed keys, and INI injection. Other tools just write and hope. | Medium | Planned | Validator should cover: key format, IP range, duplicate peers, MTU validity |
| Config integrity tracking (SHA-256) | Detects out-of-band config tampering. If someone edits the WireGuard config file directly, wg-automate can detect the mismatch. | Low | Planned | Store hash in vault, verify before operations |
| Multi-source IP consensus for DDNS | Other tools that do DDNS (PiVPN) use a single source. Multi-source consensus (2-of-3 agreement) prevents a compromised IP detection service from causing DNS poisoning. | Medium | Planned | Unique security feature |
| Cross-platform (Linux + macOS + Windows) | PiVPN is Debian-only. Algo targets cloud Linux. wg-easy requires Docker on Linux. True cross-platform including Windows is rare. | High | Planned | Windows is the hardest platform -- DPAPI, netsh, service management |
| Lock command (emergency lockdown) | No competitor has this. Ability to lock the vault / disable the VPN in an emergency is valuable for incident response. | Low | Planned | Should be fast and not require the vault passphrase |
| Terminal-only QR (no disk persistence) | wg-easy shows QR in a web UI (which is fine for its model). But wg-automate's terminal-only default means the QR (which contains the client private key) is never persisted to disk or transmitted over HTTP. | Low | Planned | The `--save-qr` opt-in with warnings is the right approach |

---

## Anti-Features

Features to deliberately NOT build. Each represents a complexity trap, security risk, or scope creep.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Web UI / dashboard | Introduces an entire attack surface: authentication, CSRF, XSS, session management, HTTPS certificate management. wg-easy exists for users who want a web UI. A CLI tool should stay a CLI tool. | Provide machine-readable output (JSON) so users can build their own dashboards |
| Docker-first deployment | Complicates the security model (container escape, volume permissions, secret mounting). Docker is a deployment option, not an architecture. | Provide standalone binaries via PyInstaller. Let users containerize if they want. |
| Automatic unattended updates | Auto-update mechanisms are a supply chain attack vector. The tool modifies firewall rules and manages crypto keys -- it must not silently change itself. | GPG-signed releases. Users update manually or via their package manager. |
| Built-in DNS resolver (Pi-hole style) | Massive scope creep. DNS resolution is a separate concern. Combining VPN + DNS resolver creates a monolith. | Document how to pair wg-automate with Pi-hole or Unbound |
| Mesh/peer-to-peer topology | Fundamentally different architecture from server-client VPN. Netmaker and Tailscale exist for mesh. Adding mesh support would require rewriting the IP allocation, routing, and firewall logic. | Stay focused on hub-and-spoke (server-client) topology |
| Multi-server management | Managing multiple WireGuard servers from one CLI instance adds distributed state, coordination, and a much larger attack surface. | Each server runs its own wg-automate instance. Provide export/import for migration. |
| OAuth/SSO integration for vault unlock | Adds network dependency to vault unlock. If the OAuth provider is down, you cannot manage your VPN. Passphrase is self-contained and works offline. | Passphrase-only for v1. Hardware key (YubiKey) is a better future direction than OAuth. |
| Bandwidth throttling / traffic shaping | Not a WireGuard management concern. This belongs in the OS networking stack (tc, pfctl). Adding it couples the tool to deep OS networking internals. | Document how to configure QoS outside wg-automate |
| Client-side agent / always-on daemon | A server management tool should not require installation on client devices. Client config files are the interface. | Export standard WireGuard `.conf` files that work with any WireGuard client |
| Payment/licensing integration | Tempting for "WireGuard as a service" use cases, but fundamentally changes the tool from infrastructure to product. | Keep it open source. Commercial users can wrap it. |
| Storing vault passphrase in environment variable | Convenient for automation but defeats the security model. ENV vars are visible in `/proc/PID/environ`, process listings, and crash dumps. | Support stdin piping for automation (`echo passphrase | wg-automate ...`) with explicit warnings. Better: support a key file with 400 permissions. |

---

## Gap Analysis: Features in Competitors Not Covered by wg-automate Plan

| Gap | Found In | Severity | Recommendation |
|-----|----------|----------|----------------|
| Uninstall/cleanup command | PiVPN (`pivpn uninstall`) | Medium | Add a `destroy` command that removes WireGuard config, firewall rules, and the vault. Require confirmation + passphrase. |
| Client enable/disable (without removal) | wg-easy (toggle on/off) | Medium | Add `disable-client` / `enable-client` or a `--disable` flag. Temporarily removing a peer without deleting their keys is useful for troubleshooting or temporary suspensions. |
| Backup/restore of vault | None (but implied need) | Medium | The encrypted vault is the single point of truth. If it is lost, all key material is gone. Add `backup` and `restore` commands. Backup should output an encrypted blob. |
| Connection status with bandwidth | wg-easy (real-time), PiVPN (`pivpn -c`) | Low | `status` command should show: peer name, endpoint IP, last handshake, transfer rx/tx. Parse from `wg show`. |
| Automatic subnet selection | PiVPN, Algo | Low | During `init`, auto-select a non-conflicting /24 subnet (e.g., 10.66.66.0/24). Check against existing routes. |
| Custom DNS per client | Rare but requested | Low | Allow per-client DNS override in `add-client`. Default to server-level DNS. |
| Port customization | PiVPN, Algo | Low | Allow non-default port during `init`. Default to 51820 but make it configurable. Already likely planned but not explicit in the 14 commands. |
| Update/upgrade mechanism | PiVPN (`pivpn update`) | Low | Not needed in v1 -- PyInstaller binaries are replaced manually. Document the upgrade path. |
| Debug/diagnostic command | PiVPN (`pivpn -d`) | Low | A `diagnose` command that checks: WireGuard loaded, interface up, firewall rules applied, DNS reachable, vault intact. Useful for troubleshooting. |

---

## Feature Dependencies

```
init (server setup)
  |-- generates server keypair --> vault must exist first
  |-- configures firewall --> platform detection must work
  |-- sets up WireGuard interface --> service manager integration
  |-- configures DDNS --> DuckDNS token in vault
  |
  v
add-client --> requires init completed
  |-- generates client keypair --> vault must be unlocked
  |-- allocates IP --> must track used IPs in vault
  |-- generates PSK --> vault stores PSK
  |-- can trigger show-qr
  |
  v
show-qr --> requires client exists
export --> requires client exists
remove-client --> requires client exists
  |-- must update WireGuard config
  |-- must update firewall rules
  |-- must update vault (mark removed, not delete -- for audit)
  |
rotate-keys --> requires client exists
  |-- generates new keypair
  |-- updates vault
  |-- updates WireGuard config
  |-- client must re-download config (breaking change for client)
  |
rotate-server-keys --> requires init completed
  |-- ALL clients must re-download configs (breaking change)
  |-- most disruptive operation -- needs confirmation + warnings
  |
update-dns --> requires DDNS configured
  |-- multi-source IP consensus
  |-- DuckDNS API call
  |
status --> requires init completed (reads wg show)
list-clients --> requires vault (reads from vault, not wg config)
audit-log --> always available (reads log file)
verify --> requires init completed (compares vault hash to config on disk)
lock --> requires vault exists (re-encrypts / zeros memory)
```

---

## Security-Relevant Features (Cross-Cutting)

These are not standalone features but security properties that must be maintained across all features:

| Property | Applies To | Implementation Note |
|----------|-----------|---------------------|
| Keys never in process args | Key generation, all commands | Use `cryptography` library, never shell out to `wg genkey` or `wg pubkey` |
| Vault locked when not in use | All commands that access keys | Decrypt to memory, use, zero memory, re-lock. Minimize time vault is open. |
| Atomic file writes | Config writes, vault writes, log writes | Write to `.tmp`, fsync, rename. Never partial state on disk. |
| Fail closed | All error paths | If anything is ambiguous, deny/lock/abort rather than proceeding with potentially insecure state |
| No secrets in logs | Audit log, error messages, debug output | Log operations (who, what, when) but never key material, passphrases, or PSKs |
| Input validation | Client names, IPs, ports, DNS | Alphanumeric + hyphens for names (prevent path traversal, INI injection). Validate IPs, ports, CIDR ranges. |
| Permission enforcement | All file creation | vault.enc: 600, directory: 700, exported configs: 600. Check and warn if permissions are wrong. |
| Memory zeroing | After vault operations | Zero sensitive buffers after use. Python makes this hard (GC, immutable strings). Use `bytearray` + explicit zeroing. |

---

## MVP Recommendation

### Must ship in v1 (table stakes + core differentiators):

1. **init** -- one-command server setup with vault creation, key generation, firewall, service
2. **add-client** -- with automatic IP allocation, PSK, vault storage
3. **remove-client** -- with config update and firewall cleanup
4. **list-clients** -- with connection status from `wg show`
5. **show-qr** -- terminal-only QR generation
6. **export** -- client config export with permission enforcement
7. **status** -- server and peer status
8. **Encrypted vault** -- the core differentiator, must be solid from day one
9. **Firewall hardening** -- deny-by-default on all platforms

### Ship in v1 but can be later in development:

10. **rotate-keys** -- client key rotation
11. **rotate-server-keys** -- server key rotation (complex, needs all clients updated)
12. **update-dns** -- DuckDNS with multi-source consensus
13. **audit-log** -- append-only log viewer
14. **verify** -- config integrity check
15. **lock** -- emergency lockdown

### Defer to v1.1 (gaps from competitor analysis):

- **disable-client / enable-client** -- temporary peer suspension
- **backup / restore** -- vault backup
- **diagnose** -- troubleshooting command
- **destroy** -- clean uninstall

### Defer to v2+:

- IPv6 dual-stack
- Hardware key (YubiKey) support
- Alternative DDNS providers
- Prometheus metrics
- Docker secrets integration

---

## Sources

- Training data knowledge of: wg-easy (GitHub), PiVPN (pivpn.io), Algo VPN (trailofbits/algo), Streisand (archived), netmaker, wiresmith, dsnet, subspace
- WireGuard protocol documentation (wireguard.com)
- OWASP password storage guidelines (Argon2id parameters)
- NIST post-quantum cryptography standards context

**Confidence note:** All findings are from training data (web tools were unavailable). The WireGuard management tool ecosystem has been stable since 2022-2023, so these findings are likely still accurate but should be spot-checked against current GitHub READMEs for any tools that may have added features recently (especially wg-easy, which has active development).
