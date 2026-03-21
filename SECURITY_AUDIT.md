# Security Audit Report

**Date:** 2026-03-21
**Auditor:** Expert Security Review (20yr vulnerability research, cryptography)
**Scope:** Full codebase audit of wg-automate WireGuard automation CLI
**Core invariant under test:** Zero plaintext secrets on disk, ever.

---

## Executive Summary

The codebase demonstrates strong security fundamentals: proper AES-256-GCM usage with AAD, Argon2id with correct parameters, SecretBytes lifecycle management, atomic writes, and a clear separation of concerns. However, the audit identified **3 CRITICAL**, **4 HIGH**, **5 MEDIUM**, and **6 LOW/INFO** issues. All CRITICAL and HIGH issues have been fixed in-tree.

| Severity | Count | Fixed |
|----------|-------|-------|
| CRITICAL | 3     | 3     |
| HIGH     | 4     | 4     |
| MEDIUM   | 5     | 0 (documented) |
| LOW/INFO | 6     | 0 (documented) |

---

## Critical Issues (fixed)

### CRIT-01: `shell=True` with user-influenced path in `_reload_wireguard` and rotation commands

**File:** `src/wg_automate/main.py:562-567, 1135-1141, 1339-1345`

**Vulnerable code:**
```python
subprocess.run(
    f"wg syncconf {interface} <(wg-quick strip {config_path})",
    shell=True,
    executable="/bin/bash",
    check=True,
    capture_output=True,
)
```

**Impact:** `config_path` is derived from `get_config_path(interface)` where `interface` defaults to `"wg0"` but the parameter is a string. If an attacker controlled the interface name (or the config path contained shell metacharacters), this would be a command injection vector. Even with the current defaults, `shell=True` with string interpolation is categorically forbidden in security-critical code. The process-substitution pattern `<(...)` forces the use of bash, but it can be replaced by a two-step approach: run `wg-quick strip` first, then pipe stdin to `wg syncconf`.

**Fix applied:** Replaced `shell=True` with a two-step `subprocess.run` pipeline using `shell=False`. `wg-quick strip` is run first to get the stripped config, then the output is piped to `wg syncconf` via `stdin`.

---

### CRIT-02: `SecretBytes.__reduce__` not blocked — pickle bypass via `__reduce__`

**File:** `src/wg_automate/security/secret_types.py`

**Vulnerable code:** `__getstate__` raises TypeError, but `__reduce__` is not overridden. Python's pickle protocol can use `__reduce__` (which by default returns enough information to reconstruct the object, including the internal `_data` bytearray) to exfiltrate secrets even when `__getstate__` blocks.

**Impact:** An attacker who can trigger `pickle.dumps()` on a `SecretBytes` instance (e.g., via multiprocessing, shelve, or any framework that auto-serializes) can extract the raw secret material. This violates SEC-01.

**Fix applied:** Added `__reduce__` and `__reduce_ex__` methods that raise `TypeError("SecretBytes cannot be pickled")`.

---

### CRIT-03: Derived key from Argon2id stored in immutable `bytes` — never wiped

**File:** `src/wg_automate/security/vault.py:91-99, 180-184, 241-243`

**Vulnerable code:**
```python
def _derive_key(...) -> bytes:
    return hash_secret_raw(...)  # returns immutable bytes

# In _encrypt_vault / _decrypt_vault:
key = _derive_key(passphrase, salt)
try:
    ...
finally:
    key_arr = bytearray(key)  # copies the bytes, original still in memory
    wipe_bytes(key_arr)       # wipes the COPY, not the original
    del key_arr               # deletes the copy reference
```

**Impact:** The 256-bit AES key derived from Argon2id is stored as immutable `bytes`. The "wipe" in the finally block creates a *copy* as `bytearray`, wipes the copy, then deletes it. The original `bytes` object remains in memory until garbage collected. A memory-scraping attacker can recover the AES key.

**Fix applied:** Changed `_derive_key` to return `bytearray` directly, so `wipe_bytes` operates on the actual key material. Updated callers to wipe the returned bytearray in-place.

---

## High Issues (fixed)

### HIGH-01: `validate_subnet` uses `is_private` which includes link-local and loopback

**File:** `src/wg_automate/security/validator.py:124, 146, 269`

**Vulnerable code:**
```python
if not net.is_private:
    raise ValueError(...)
```

**Impact:** `ipaddress.ip_network.is_private` returns `True` for RFC 1918 ranges, but also for `127.0.0.0/8` (loopback), `169.254.0.0/16` (link-local), and `100.64.0.0/10` (CGNAT). A user could configure a VPN subnet of `127.0.0.0/24` or `169.254.0.0/16`, which would cause routing chaos or security issues. The project documentation says "RFC 1918 only."

**Fix applied:** Added explicit RFC 1918 range check (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) instead of relying on `is_private`.

---

### HIGH-02: Hint file written without restrictive permissions

**File:** `src/wg_automate/security/vault.py:434`

**Vulnerable code:**
```python
hint_path.write_text(hint, encoding="utf-8")
```

**Impact:** The hint file is written with the default umask permissions (typically 0o644 on Unix), making it world-readable. While the hint is intentionally plaintext, it should still be owner-only since it is a clue to the vault passphrase. An attacker with read access to the filesystem gets a free passphrase hint.

**Fix applied:** Applied `set_file_permissions(hint_path, mode=0o600)` after writing the hint file, and used `atomic_write` for crash safety.

---

### HIGH-03: Audit log injection via newlines in metadata values

**File:** `src/wg_automate/security/audit.py:243-244`

**Vulnerable code:**
```python
fh.write(json.dumps(entry.to_dict()) + "\n")
```

**Impact:** While `json.dumps` will escape newlines inside string values, the `action` parameter is a plain string that is not scrubbed. If an attacker controlled the `action` string (unlikely but defensive depth requires it) or if any metadata value contained raw newlines that survived `_scrub_secrets` (which does not strip newlines), a malformed JSON line could be injected. More importantly, the `error` field passes exception messages verbatim which could contain newlines, corrupting the NDJSON format.

**Fix applied:** Added newline sanitization for `action` and `error` fields before writing, replacing `\n` and `\r` with spaces.

---

### HIGH-04: Interface name not validated before use in subprocess commands and firewall rules

**File:** `src/wg_automate/platform/linux.py:362, 473` and `src/wg_automate/platform/windows.py:264-290` and `src/wg_automate/main.py:562`

**Vulnerable code:**
```python
service = f"wg-quick@{interface}"
subprocess.run(["systemctl", "enable", service], ...)
# Also:
path = _WIREGUARD_DIR / f"{interface}.conf"
```

**Impact:** The `interface` parameter flows into subprocess arguments, file paths, and firewall rule names without validation. While the default is `"wg0"`, an attacker-controlled interface name like `wg0; rm -rf /` could inject commands if `shell=True` were ever used upstream (CRIT-01 was one such case). Even with `shell=False`, path traversal via `../../etc/shadow` in the interface name is a risk for `get_config_path`.

**Fix applied:** Added `validate_interface_name()` to the validator module, enforcing `^[a-zA-Z0-9_-]{1,15}$` (matching Linux IFNAMSIZ limit). Called at every entry point where `interface` is used.

---

## Medium Issues (documented only)

### MED-01: `keygen.py` creates intermediate immutable `bytes` for base64-encoded private key

**File:** `src/wg_automate/core/keygen.py:38`

```python
private_b64 = base64.b64encode(bytes(raw_private))  # immutable bytes
```

The `base64.b64encode` call returns immutable `bytes`. This is immediately copied into a `bytearray` for `SecretBytes`, but the intermediate `bytes` object lingers until GC. Consider using a custom base64 encoder that operates on `bytearray` directly.

### MED-02: `psk.py` same issue — immutable `bytes` from `base64.b64encode`

**File:** `src/wg_automate/core/psk.py:28`

Same pattern as MED-01.

### MED-03: `duckdns.py` token string lives in Python `str` (immutable) during request

**File:** `src/wg_automate/dns/duckdns.py:86`

```python
token_str = bytes(token.expose_secret()).decode("ascii")
```

The token is decoded to an immutable `str` which Python may intern. The `del` on line 133 removes the reference but does not zero the memory. `wipe_string` from `secrets_wipe.py` should be called.

### MED-04: `_derive_key` accepts `passphrase: bytearray` but calls `bytes(passphrase)` — creates immutable copy

**File:** `src/wg_automate/security/vault.py:92`

```python
return hash_secret_raw(secret=bytes(passphrase), ...)
```

The `bytes()` call creates an immutable copy of the passphrase that Argon2 retains for the duration of hashing. This is unavoidable due to the argon2-cffi API, but should be documented.

### MED-05: `qr_generator.save_qr` writes QR to disk with permissions set AFTER write (TOCTOU)

**File:** `src/wg_automate/core/qr_generator.py:91-94`

```python
path.write_text(qr_ascii, encoding="utf-8")
set_file_permissions(path, mode=0o600)
```

The file is created with default umask, then permissions are tightened. There is a brief window where the file is world-readable. Should use `atomic_write` instead.

---

## Low / Info

### LOW-01: GitHub Actions not pinned to SHA digests

**File:** `.github/workflows/build.yml`, `.github/workflows/release.yml`

Actions like `actions/checkout@v4` and `actions/setup-python@v5` use tag references, not SHA-pinned commits. A compromised tag could inject malicious code into the CI pipeline. Recommended: pin to full SHA, e.g., `actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`.

### LOW-02: `requirements-dev.txt` referenced in CI but not audited here

**File:** `.github/workflows/build.yml:18`

CI installs from `requirements-dev.txt` with `--require-hashes`, which is correct. But we could not verify the file exists or has hashes since it was not in the audit scope.

### LOW-03: `wipe_string` relies on CPython internals

**File:** `src/wg_automate/security/secrets_wipe.py:39-59`

The `wipe_string` function uses `ctypes.memset(id(s) + header_size, 0, length)` to zero a string's internal buffer. This is fragile and CPython-specific. On PyPy, GraalPy, or future CPython versions with different string layouts, this silently does nothing. Documented as best-effort, which is acceptable.

### LOW-04: `validate_subnet` uses `strict=False` allowing host-bit confusion

**File:** `src/wg_automate/security/validator.py:120`

```python
net = ipaddress.ip_network(subnet, strict=False)
```

This silently masks host bits: `10.0.0.5/24` becomes `10.0.0.0/24`. Users may not realize their input was modified. Consider warning or rejecting.

### LOW-05: `assert` used for security check in `status` command

**File:** `src/wg_automate/main.py:243-245`

```python
assert "PrivateKey" not in output, (...)
```

In production, Python can be run with `-O` which disables assertions. This security check would be silently removed. Should use an explicit `if` check.

### INFO-01: Audit log scrub pattern may miss non-standard key formats

**File:** `src/wg_automate/security/audit.py:30`

```python
_KEY_PATTERN = re.compile(r'^[A-Za-z0-9+/]{42,43}=$')
```

This only catches base64 strings of exactly 43 or 44 chars ending with `=`. WireGuard keys with `==` padding (uncommon but valid base64) would not be caught.

---

## Verified Correct

The following security properties were verified and found to be correctly implemented:

1. **AES-256-GCM**: 12-byte nonce via `os.urandom(12)`, fresh per encryption. Header used as AAD. Tag size is the default 16 bytes from the `cryptography` library. No nonce reuse possible due to `os.urandom`.

2. **Argon2id parameters**: `memory_cost=262144` (256 MiB in KiB), `time_cost=4`, `parallelism=4`, `hash_len=32`. Salt is 16 bytes from `os.urandom`. Parameters stored in vault header so future vaults can use different params.

3. **X25519 key generation**: In-process via `cryptography` library (never `wg genkey` subprocess). Standard base64 encoding (not URL-safe). Key size validated at 32 bytes after decode.

4. **PSK generation**: `os.urandom(32)` — full 256-bit entropy, no weak fallback.

5. **No homegrown crypto**: All primitives from `cryptography` library and `argon2-cffi`. No manual XOR, ECB, or CBC.

6. **Constant-time comparison**: `hmac.compare_digest` used in `SecretBytes.__eq__` and `verify_config_integrity`.

7. **SecretBytes**: Uses `bytearray` (mutable), `__repr__`/`__str__` redacted, `__eq__` constant-time, `__hash__` raises TypeError, `__getstate__` blocks pickling. Context manager wipes in `__exit__`.

8. **mlock/VirtualLock**: Called on buffer creation, munlock on wipe. Errors suppressed (best-effort). Cross-platform support.

9. **Wipe pattern**: Zero-random-zero three-pass overwrite. Called in `finally` blocks and `__exit__`.

10. **Vault header integrity**: 47-byte header with magic, version, Argon2 params, salt, nonce. Used as AAD — any header tamper invalidates GCM tag.

11. **Atomic write**: `tempfile.mkstemp` in same directory, `os.fsync`, `os.chmod` BEFORE `os.replace`, directory fsync on POSIX, `BaseException` cleanup.

12. **Passphrase minimum**: 12-character minimum enforced BEFORE key derivation in both `Vault.create` and `change_passphrase`.

13. **Generic error on unlock failure**: Wrong passphrase and GCM tag failure both raise `VaultUnlockError("Vault unlock failed")` — no distinguishing oracle.

14. **INI injection**: `[\]=\n\r` blocked via regex in `validate_no_injection`.

15. **Path traversal**: Client name validated as `[a-zA-Z0-9-]{1,32}` — no `/`, `\`, or `..` possible.

16. **Passphrase input**: `click.prompt(hide_input=True)` used consistently. Never in `sys.argv`, never as environment variable.

17. **DuckDNS HTTPS**: `ssl.create_default_context()` used, no `verify=False`. Token as query parameter (not URL path). Response body truncated before logging.

18. **IP consensus**: Private/loopback/multicast/link-local/reserved all rejected. 2-of-3 consensus required, fail-closed on disagreement.

19. **Supply chain**: `requirements.txt` has `--hash=sha256:` entries. CI uses `pip install --require-hashes`. `pip-audit` run against `requirements.txt`.

20. **No secrets in argv**: Passphrase collected via `click.prompt`, DuckDNS token via `click.prompt(hide_input=True)`. No `--passphrase` CLI option.

21. **Lock command**: Wipes temp artifacts without requiring passphrase. Audit log failure does not prevent lock.

22. **Privilege check**: Called at startup before vault interaction on all platforms. Linux: `os.geteuid()`, macOS: `os.geteuid()`, Windows: `IsUserAnAdmin()`.

23. **No `shell=True` in platform adapters**: All subprocess calls in `linux.py`, `macos.py`, and `windows.py` use `shell=False` with list args. (The `shell=True` violations were only in `main.py`.)

24. **Firewall deny-by-default**: Linux nftables `policy drop` on input and forward chains. Rate limiting (5/s burst 10). NAT scoped to detected outbound interface only.
