# Security Policy

WireSeal is security infrastructure — a self-hosted WireGuard® server manager
that holds your VPN keys, admin credentials, and the keys to your home network.
We treat security reports as the highest priority.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Yes — active security support |
| < 1.0   | ❌ No — please upgrade to 1.0.x |

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Report privately via either:

- **GitHub Private Vulnerability Reporting** — the "Report a vulnerability"
  button under the repository's **Security** tab (preferred).
- **Email** — `mudigondaprashanth@gmail.com` with subject `WireSeal Security`.

Please include: affected version, a description, reproduction steps or PoC, and
the impact you observed. If you'd like, include a suggested fix.

### Our commitment

- **Acknowledgement** within 72 hours.
- **Triage + severity assessment** within 7 days.
- **Fix or mitigation** targeted within 30 days for High/Critical issues.
- **Coordinated disclosure** — we credit reporters (unless you prefer anonymity)
  and publish an advisory once a fix ships.

A small disclosure-only bug-bounty (acknowledgement + credit) is offered; there
is no monetary reward at this time.

## Security posture (what WireSeal does to protect you)

WireSeal is designed around three principles: **you own everything, nothing
phones home, and every privileged action is provable.**

- **Local-only control plane.** The management API binds to `127.0.0.1` only —
  it is never exposed to the network. Cross-origin browser requests are
  rejected (Origin check); only the local dashboard or a local client can talk
  to it.
- **Encrypted, passphrase-locked vault.** All secrets (WireGuard keys, client
  configs, admin credentials, DNS/backup settings) live in an authenticated-
  encryption vault that is useless without your passphrase. Multi-admin slots
  are independently keyed.
- **TOTP 2FA** for admin access, with rate-limited unlock and audited failures.
- **Tamper-evident audit log.** Every privileged action is appended to a
  SHA-256 **hash-chained** log (each entry binds to the previous). Modifying,
  deleting, or reordering an entry breaks the chain, which the dashboard
  verifies and flags. Unlike managed mesh VPNs, this log lives **on your box**,
  not in someone else's cloud.
- **Per-client ACLs** enforced by the host firewall (nftables) — restrict which
  LAN resources each client may reach, least-privilege by destination + port.
- **Secret hygiene.** Secrets are held in zeroizable buffers, never written to
  logs, never passed as process arguments, and redacted from API responses.
- **Hardened file handling.** Privileged files are written atomically with
  least-privilege permissions; backup/restore validates paths against a
  system-directory blocklist and verifies decryptability before replacing the
  live vault.
- **SSRF & injection guards.** Outbound integrations (WebDAV backup, DuckDNS)
  validate targets; firewall/DNS rule generation validates all inputs through
  `ipaddress`/allowlists so no untrusted string reaches a shell or rule file.

## Zero telemetry

WireSeal contains **no analytics, tracking, or phone-home of any kind.** Every
outbound network connection is a feature you explicitly enable or trigger, to an
endpoint **you** control or choose:

| Outbound call | When | Destination |
|---------------|------|-------------|
| Update check | You click "Check for updates" | GitHub Releases |
| DuckDNS refresh | You configure DuckDNS | DuckDNS (your domain) |
| Public-IP resolution | Computing your tunnel endpoint | Public IP echo services |
| Backup upload | You configure SSH/WebDAV backup | Your backup host |
| Notifications | You configure ntfy/webhook/email | Your chosen endpoint |
| LAN discovery | You open the Network page | Your local network only |

There is no account, no SaaS control plane, and no third party that can see your
traffic or hold your keys.

## Verifying releases

Release binaries are published on GitHub Releases with a `sha256sums.txt`
manifest. Verify your download before running:

```bash
sha256sum -c sha256sums.txt --ignore-missing
```

Signed releases and reproducible-build attestation are on the roadmap.

## Scope

In scope: the WireSeal API server, vault, audit log, dashboard, CLI, backup,
DNS, SSH/SFTP bridge, firewall/ACL generation, and notification dispatch.

Out of scope: vulnerabilities in WireGuard itself, the host OS, dnsmasq, or
third-party services (DuckDNS, your SMTP/WebDAV host); and issues requiring an
already-root local attacker (who, by definition, already controls the host).
