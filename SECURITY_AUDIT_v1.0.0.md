# WireSeal v1.0.0 — Security Audit Report

**Date:** 2026-06-14
**Scope:** WireSeal self-hosted WireGuard® server manager — Python stdlib API
server, encrypted multi-admin vault, dashboard, CLI, backup, DNS, SSH/SFTP
bridge, firewall/ACL generation, notification dispatch.
**Method:** Source-level review of the full server attack surface by three
independent reviewers, each covering a non-overlapping domain, followed by
maintainer triage against the product threat model and remediation.

This is a self-audit published in the interest of transparency. An independent
third-party audit is on the roadmap (see SECURITY.md).

---

## 1. Threat model

WireSeal is **not** an internet-exposed service. Understanding this is essential
to reading the findings correctly:

- The management API **binds to `127.0.0.1` only.** It is never on the network.
  The remote attack surface is the WireGuard data plane (kernel WireGuard) and,
  optionally, SSH — not the API.
- Cross-origin browser requests are rejected (Origin check). The realistic
  browser threat is a malicious local tab making CSRF-style calls to localhost.
- Privileged API operations require an **unlocked vault** (the passphrase) and,
  for sensitive actions, an **admin role + TOTP/passphrase re-confirmation.**
- An attacker who is already **root on the host** is out of scope — they own the
  machine, the vault process memory, and every file regardless of WireSeal.

Findings are therefore rated by what an attacker can do **without** already
holding root or the vault passphrase, and by defense-in-depth value.

## 2. Summary

| Severity | Found | Fixed in 1.0.0 | Mitigated / Accepted | Roadmap |
|----------|-------|----------------|----------------------|---------|
| CRITICAL | 3 | 1 | 1 | 1 |
| HIGH | 9 | 5 | 2 | 2 |
| MEDIUM | 17 | 4 | 9 | 4 |
| LOW / INFO | 12 | 1 | 11 | — |

**No remote code execution, authentication bypass, hardcoded secret, SQL
injection, or `shell=True` injection was found.** The encryption core, secret
handling, rate limiting, and audit-chain integrity were assessed as **strong**
(see §6). All issues were privilege/defense-in-depth gaps reachable only by an
already-authenticated admin or a local browser tab.

## 3. CRITICAL findings

### C-01 — systemd unit injection via `vault_dir` → root RCE — **FIXED**
`platform/linux.py`. `install_api_service()` validated `vault_dir` only with
`startswith("/")`, then interpolated it into the systemd unit `ExecStart=` line.
A newline in `vault_dir` could inject a second `ExecStart=` running an arbitrary
command as `User=root`. Reachable by an admin configuring the service — an admin
should not gain arbitrary root code execution from a path field.
**Fix:** `vault_dir` is now validated against a strict path charset
(`/[A-Za-z0-9._/-]*`), rejecting newlines and shell metacharacters.

### C-02 — SSH ticket token delivered in `ws://` URL query — **MITIGATED, roadmap fix**
`api/ssh.py`, `ssh/ws_bridge.py`. The one-time SSH token is passed as a
`?token=` query parameter, which can land in browser history / logs.
**Risk in context:** the bridge is **loopback-only**, the token is **single-use
with a 60-second TTL**, and the response is not cross-origin readable.
**Status:** accepted for 1.0.0 as low-real-risk; the planned fix (deliver the
token in the REST body and send it as the first authenticated WebSocket frame)
is on the roadmap and tracked. Documented here for transparency.

### C-03 — WebDAV backup password stored plaintext in `backup.env` — **ACCEPTED (documented)**
`backup/scheduler.py`. For unattended scheduled backups, the WebDAV password is
written to `/etc/wireseal/backup.env` (`0600`, root-owned). This mirrors the
existing DuckDNS-token pattern: a secret needed by a non-interactive cron job
must live in a root-only file because the job has no passphrase.
**Risk in context:** readable only by root, who already controls the host.
**Status:** accepted and **documented** (SECURITY.md). Roadmap: optional OS
keyring storage / token-based WebDAV auth. Local-filesystem and SSH-key backup
destinations have **no** stored secret and are recommended for the strict.

## 4. HIGH findings

| ID | Issue | Status |
|----|-------|--------|
| H-02 | WebDAV PUT followed 3xx redirects, bypassing the SSRF guard | **FIXED** — redirects now rejected (`_NoRedirect` opener) |
| H-03 | SFTP read ops (`list/read/stat/exists`) lacked admin-role gate | **FIXED** — all now `_require_admin_role()` |
| H-05 | SFTP paths not required absolute (empty/relative resolved vs CWD) | **FIXED** — absolute path now required |
| H-01 | Cron command didn't shell-quote the executable path | **FIXED** — `shlex.quote` applied |
| MTU-iface | Interface name from `ip route` used unvalidated in a `/sys` path | **FIXED** — validated to `[A-Za-z0-9_.-]{1,15}` |
| H1(auth) | Cross-origin GET with `?code=` can consume a TOTP code (code DoS) | **MITIGATED** — loopback + Origin policy; roadmap: same-origin on reveal GETs |
| H2(auth) | Windows admin-mode grants on passphrase without OS elevation check | **ACCEPTED** — still requires the vault passphrase; documented; roadmap: token-membership check |
| H-04 | SSH `key_pem` held as plain `str`, not zeroized on wipe | **ROADMAP** — wrap in `SecretBytes` (Python str immutability limits impact) |
| H-06 | macOS `/etc/resolver/<label>` filename from user-set DNS mapping | **ROADMAP** — macOS-only, admin-set; strict-label + reserved-name guard planned |

## 5. MEDIUM / LOW (selected)

**Fixed in 1.0.0:**
- Notification dispatch accepted non-HTTP schemes (`file://`, `ftp://`) →
  **scheme now restricted to http/https** (private/LAN hosts still allowed for
  self-hosted ntfy).
- Notification test returned raw exception text (SMTP banners, host info) →
  **generic error returned, full detail logged server-side only.**
- Email `From/To` header-injection via stored values → **modern SMTP policy +
  CR/LF stripping.**
- Audit-log endpoints read the entire file into memory → **one-pass,
  memory-bounded `deque` tail read.**

**Accepted / mitigated (with rationale):** channel-field type/length validation
(admin-gated config), TOTP used-code persistence best-effort (`pass`), several
TOCTOU windows on `_session`/`_admin_session` reads (GIL + loopback + narrow
windows), `AuditLog` class-level session state (singleton usage), audit file
`0o600` vs `0o640` (more restrictive, not less), SFTP rate-limiter state cleanup,
env-file `#` handling, DuckDNS token format check, `restore_backup` path
constraint (the API layer already allowlists backup roots — verified), WebDAV
explicit SSL context, `append_known_host` local newline guard (upstream regex
already blocks it).

**Roadmap:** typed session dataclass, TOTP used-code original-timestamp
tracking, clearing `_totp_session_verified` on lock, per-channel schema
validation.

## 6. Areas assessed as STRONG (no change required)

- **Vault encryption.** Dual-layer AEAD (ChaCha20-Poly1305 inner + AES-256-GCM
  outer) with HKDF-SHA512 key separation and **Argon2id** KDF at production
  parameters (256 MiB, high time cost), with parameter-bounds validation to
  prevent KDF-inflation DoS. Atomic writes (tmp + fsync + replace) throughout.
- **Secret handling.** `SecretBytes` uses mlock/VirtualLock, zero-random-zero
  wipe, `MADV_DONTDUMP`, constant-time `__eq__`, and anti-pickle/anti-copy
  guards. `os.register_at_fork` wipes secrets in forked children.
- **Constant-time comparisons** (`hmac.compare_digest`) used consistently for
  passphrase, TOTP, fresh-start tokens, and keyslot lookups. No `==` on secrets.
- **Rate limiting.** Per-IP sliding windows with escalating lockout on unlock,
  PIN, TOTP, admin auth, and backup-code endpoints.
- **Tamper-evident audit log (SEC-025).** SHA-256 hash chain with genesis
  sentinel detects truncation/reordering; secrets scrubbed before write.
- **Injection safety.** ACL/firewall/DNS rule generation validates all inputs
  through `ipaddress`/allowlists; `subprocess` uses argument lists, never
  `shell=True`; minimal subprocess environment.
- **Path traversal.** Admin file access and static serving resolve symlinks and
  enforce allowlist roots, failing closed.
- **Zero telemetry.** No analytics/phone-home; every outbound call is a
  user-enabled feature to a user-controlled endpoint (verified — see SECURITY.md).

## 7. Conclusion

WireSeal v1.0.0 ships with a **strong cryptographic and authentication core** and
**no critical remotely-exploitable vulnerability.** All issues found were
reachable only by an already-authenticated local admin or a local browser tab,
and the genuinely exploitable, low-cost ones were fixed for 1.0.0. The remaining
items are documented here with rationale and tracked on the roadmap — published
openly because a security product earns trust by showing its work, not by hiding
it.

*Reviewer methodology and per-file findings are retained with the maintainer and
available to a future independent auditor on request.*
