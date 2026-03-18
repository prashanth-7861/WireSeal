---
phase: 01-secure-core-engine
verified: 2026-03-17T00:00:00Z
status: passed
score: 38/38 must-haves verified
re_verification: null
gaps: []
human_verification:
  - test: "mlock actually pins pages on target OS"
    expected: "On Linux/macOS, mlock() does not raise; on Windows, VirtualLock() does not raise"
    why_human: "mlock is best-effort/silently ignored on failure -- cannot verify the OS actually honored the lock without root+inspection of /proc/PID/maps or kernel debug output"
  - test: "Argon2id KDF takes at least 500ms with production parameters (262144 KiB / 4 iter / 4 par)"
    expected: "Vault.create() and Vault.open() each take >= 500ms on target hardware"
    why_human: "Cannot benchmark without executing code; TEST-04 in REQUIREMENTS.md explicitly requires this benchmark"
  - test: "wg syncconf is the correct reload mechanism (CONFIG-05)"
    expected: "Phase 4 CLI uses wg syncconf, not wg setconf, to preserve active sessions"
    why_human: "wg syncconf integration is a Phase 4 concern; this phase only provides the atomic write + FileLock plumbing. Verify at Phase 4."
---

# Phase 1: Secure Core Engine Verification Report

**Phase Goal:** Users have a cryptographically sound foundation where secrets are type-safe, vault-encrypted, and never exposed -- all downstream phases build on this proven base
**Verified:** 2026-03-17
**Status:** passed
**Re-verification:** No -- initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | SecretBytes wraps bytearray and never leaks content via repr, str, eq, hash, or pickle | VERIFIED | `__repr__` and `__str__` return `"SecretBytes(***)"`. `__hash__` raises TypeError. `__getstate__` raises TypeError. `__eq__` uses `hmac.compare_digest`. |
| 2 | SecretBytes calls mlock on its buffer at creation (best-effort, no crash on failure) | VERIFIED | `_mlock()` called in `__init__`; wraps in `try/except Exception: pass`; handles win32/darwin/linux via `sys.platform`. |
| 3 | wipe_bytes zeroes a bytearray using the zero-random-zero pattern | VERIFIED | Three explicit loop passes: zeros, `os.urandom`, zeros. No-op on empty. |
| 4 | wipe_string zeroes a string's internal buffer via ctypes (best-effort) | VERIFIED | Uses `sys.getsizeof(s) - len(s)` to compute header offset; `ctypes.memset` into string buffer; wrapped in `try/except`. |
| 5 | All key material is held in bytearray/SecretBytes, never in immutable str/bytes | VERIFIED | `SecretBytes.__init__` converts `bytes -> bytearray` immediately. `generate_keypair` uses `bytearray(private_bytes_raw())`. `generate_psk` uses `bytearray(os.urandom(32))`. |
| 6 | Exception handlers wipe secrets in finally blocks and use raise X from None | VERIFIED | `_encrypt_vault` and `_decrypt_vault` both wipe derived key in `finally` blocks. `VaultUnlockError` raised with `from None`. `validate_wg_key` uses `from None`. |
| 7 | Vault encrypts with AES-256-GCM using Argon2id-derived key (256 MiB / 4 iter / 4 par) | VERIFIED | `ARGON2_MEMORY_COST_KIB = 262144` (256 MiB in KiB, correctly stated). `ARGON2_TIME_COST = 4`, `ARGON2_PARALLELISM = 4`. `AESGCM(key).encrypt(nonce, plaintext, header)` called in `_encrypt_vault`. Critical-unit comment present: `# CRITICAL: memory_cost is in KiB`. |
| 8 | Vault decrypts successfully with correct passphrase and returns state dict | VERIFIED | `_decrypt_vault` parses header, derives key from header-embedded params, decrypts with `AESGCM`, returns `json.loads(plaintext)`. |
| 9 | Wrong passphrase raises VaultUnlockError with generic message "Vault unlock failed" | VERIFIED | `except InvalidTag: raise VaultUnlockError("Vault unlock failed") from None` in `_decrypt_vault`. |
| 10 | Tampered vault file (any byte modified) raises VaultUnlockError via GCM tag failure | VERIFIED | Header is AAD; ciphertext byte flip fails GCM tag -> `InvalidTag` -> `VaultUnlockError`. Magic-byte tampering raises `VaultTamperedError` (subclass of `VaultError`). |
| 11 | Vault state is only accessible inside a context manager; wiped in finally on exit | VERIFIED | `VaultState.__exit__` calls `self.wipe()`. `wipe()` zeros all `SecretBytes` fields. `Vault.open()` returns bare `VaultState` (caller uses `with` -- by design). |
| 12 | Vault file is written atomically (tmp + fsync + os.replace) with 600 permissions | VERIFIED | `atomic_write` in `security/atomic.py`: `mkstemp`, `os.write`, `os.fsync`, `os.close`, `os.chmod(tmp, mode)`, `os.replace`, parent-dir fsync on Unix. Used by both `vault.py` and `config_builder.py`. |
| 13 | Vault directory is created with 700 permissions | VERIFIED | `_ensure_vault_dir`: `dir_path.mkdir(parents=True, exist_ok=True)`, then `os.chmod(dir_path, 0o700)` on non-Windows; icacls on Windows. |
| 14 | AES-GCM nonce is os.urandom(12) per encryption -- never reused | VERIFIED | `nonce = os.urandom(GCM_NONCE_LEN)` called inside `_encrypt_vault` every invocation. No counter, no timestamp. Comment: `# SEC-06: fresh nonce per encryption`. |
| 15 | Passphrase change decrypts with old, re-encrypts with new, writes atomically | VERIFIED | `change_passphrase` decrypts, re-encrypts with `_encrypt_vault` (new salt + nonce), calls `atomic_write`. Intermediate dict cleared in `finally`. New passphrase also validated >= 12 chars. |
| 16 | Vault integrity is verifiable on demand | VERIFIED | `verify_integrity` calls `_decrypt_vault`; catches `VaultUnlockError`, returns False; on success wipes state and returns True. |
| 17 | Passphrase hint stored as plaintext .hint file beside vault (optional) | VERIFIED | `hint_path = vault_path.with_suffix(".hint")`, `hint_path.write_text(hint)`. Warning printed: `"WARNING: The passphrase hint is stored as plain text and is not protected."` |
| 18 | Vault.create() rejects passphrases shorter than 12 characters with ValueError | VERIFIED | `if len(raw) < 12: raise ValueError("Passphrase must be at least 12 characters")` before any file I/O. |
| 19 | X25519 key pairs are generated in-process via cryptography library, never via subprocess | VERIFIED | `X25519PrivateKey.generate()` called in `keygen.py`. Comment: `# KEYGEN-01: Never call wg genkey subprocess`. No subprocess import in keygen.py or psk.py. |
| 20 | Private keys are extracted as bytearray, base64-encoded, and wrapped in SecretBytes immediately | VERIFIED | `raw_private = bytearray(private_key.private_bytes_raw())`, encoded, then `SecretBytes(bytearray(private_b64))`. |
| 21 | PSKs are 32 bytes from os.urandom, base64-encoded, unique per peer | VERIFIED | `raw_psk = bytearray(os.urandom(32))`, base64-encoded, wrapped in `SecretBytes`. Uniqueness guaranteed by `os.urandom`. |
| 22 | All intermediate key bytes are wiped after use via secrets_wipe.wipe_bytes() | VERIFIED | `wipe_bytes(raw_private)` in `keygen.py` after base64 encoding. `wipe_bytes(raw_psk)` in `psk.py` after base64 encoding. Vault derived key wiped in `finally` blocks. |
| 23 | VPN subnet is configurable with default 10.0.0.0/24; server gets .1; clients get sequential .2+ | VERIFIED | `IPPool.__init__` sets `self.server_ip = str(next(self.network.hosts()))`. `allocate()` iterates hosts, skips server_ip, skips allocated, assigns next free. |
| 24 | IP allocation table tracks assigned IPs; conflict check prevents duplicate assignment | VERIFIED | `self._allocated: dict[str, str]` checked in `allocate()` before assignment. `is_allocated()` available. |
| 25 | IPs are released immediately on client removal (no grace period) | VERIFIED | `release()` calls `self._allocated.pop(ip, None)` -- immediate, no timer. |
| 26 | Only RFC 1918 private ranges are accepted for VPN subnets | VERIFIED | `if not self.network.is_private: raise ValueError(...)` in `IPPool.__init__`. |
| 27 | Config templates use Jinja2 with StrictUndefined and autoescape=False | VERIFIED | `Environment(loader=FileSystemLoader(...), undefined=StrictUndefined, autoescape=False, ...)` in `ConfigBuilder.__init__`. autoescape=False is correct for WireGuard plain-text INI files (autoescape=True would corrupt base64 `=` chars). REQUIREMENTS.md CONFIG-01 text incorrectly states `autoescape=True` -- this is a documentation typo; all plans, research, SUMMARY, and code agree on `autoescape=False`. |
| 28 | Generated configs have header "# Managed by wg-automate -- do not edit manually" | VERIFIED | First line of both `server.conf.j2` and `client.conf.j2`. |
| 29 | Client configs include DNS = <server> line | VERIFIED | `DNS = {{ dns_server }}` in `client.conf.j2`. |
| 30 | Pre-apply validator checks: key format, PSK, IP validity, port range 1024-65535, client name, AllowedIPs, INI injection | VERIFIED | `validate_wg_key` (44 chars, 32 bytes decoded), `validate_port` (1024-65535), `validate_subnet` (RFC 1918), `validate_ip`, `validate_client_name` (alphanumeric+hyphens, max 32), `validate_no_injection` (`[\[\]=\n\r]`), `validate_allowed_ips`. |
| 31 | Validation errors include exact field name, character, and position | VERIFIED | `validate_client_name` iterates chars with `enumerate`; error message includes `'{ch}' at position {i}`. `validate_wg_key` includes field name and lengths. `validate_no_injection` includes `repr(char)` and `pos`. |
| 32 | Config files are written atomically with 600 permissions | VERIFIED | `ConfigBuilder.write_config` calls `atomic_write(path, encoded, mode=0o600)`. |
| 33 | SHA-256 hash of deployed config is computed and stored for integrity tracking | VERIFIED | `compute_config_hash` returns `hashlib.sha256(config_path.read_bytes()).hexdigest()`. `verify_config_integrity` uses `hmac.compare_digest`. `store_hash_in_state` stores hash + UTC timestamp in vault state. |
| 34 | Config tampering is detected by comparing SHA-256 hash before reload | VERIFIED | `verify_config_integrity(path, stored_hash)` returns False on mismatch. Caller is documented as responsible for the security alert. |
| 35 | Config writes use FileLock to prevent TOCTOU races | VERIFIED | `from filelock import FileLock` (not SoftFileLock). `with FileLock(lock_path, timeout=30):` wraps `atomic_write` in `write_config`. |
| 36 | Client names: alphanumeric + hyphens only, max 32 chars | VERIFIED | `_CLIENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9-]{1,32}$")` used in `validate_client_name`. |
| 37 | render_server_config() and render_client_config() call validate_*() before rendering | VERIFIED | Both methods call `validate_server_config` / `validate_client_config` via local imports before calling `template.render(...)`. ValueError propagates without rendering. |
| 38 | Python minimum version 3.12 in pyproject.toml | VERIFIED | `requires-python = ">=3.12,<3.15"`. Note: plan specified `<3.14`; code uses `<3.15` (slightly wider upper bound). HARD-01 requires minimum 3.12 -- satisfied. Upper bound difference is benign. |

**Score:** 38/38 truths verified

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/wg_automate/security/secret_types.py` | SecretBytes class with mlock support | VERIFIED | 173 lines; SecretBytes with all required methods including _mlock, _munlock, wipe, __repr__, __str__, __eq__, __hash__, __getstate__, context manager |
| `src/wg_automate/security/secrets_wipe.py` | Memory wiping functions | VERIFIED | wipe_bytes (zero-random-zero), wipe_string (ctypes, best-effort) |
| `src/wg_automate/security/exceptions.py` | Custom exceptions for vault operations | VERIFIED | VaultError, VaultUnlockError, VaultTamperedError |
| `src/wg_automate/security/vault.py` | Encrypted vault with context manager, atomic writes, passphrase management | VERIFIED | 539 lines; full implementation including Vault, VaultState, _encrypt_vault, _decrypt_vault, _derive_key |
| `src/wg_automate/core/keygen.py` | X25519 key pair generation with SecretBytes wrapping | VERIFIED | generate_keypair() -> (SecretBytes, bytes) |
| `src/wg_automate/core/psk.py` | Pre-shared key generation | VERIFIED | generate_psk() -> SecretBytes |
| `src/wg_automate/core/ip_pool.py` | IP allocation and release within a VPN subnet | VERIFIED | IPPool with allocate, release, is_allocated, get_client_ip, load_state, get_allocated |
| `src/wg_automate/core/config_builder.py` | Jinja2-based WireGuard config renderer | VERIFIED | ConfigBuilder with render_server_config, render_client_config, write_config |
| `src/wg_automate/security/validator.py` | Pre-apply config validation | VERIFIED | All 8 required functions present and substantive |
| `src/wg_automate/security/integrity.py` | SHA-256 config integrity tracking | VERIFIED | compute_config_hash, verify_config_integrity (hmac.compare_digest), store_hash_in_state |
| `src/wg_automate/security/permissions.py` | Cross-platform file permission enforcement | VERIFIED | set_file_permissions, set_dir_permissions, check_file_permissions; Unix chmod + Windows icacls |
| `src/wg_automate/security/atomic.py` | Shared atomic file write helper | VERIFIED | atomic_write: mkstemp, fsync, chmod-before-rename (Unix), os.replace, parent-dir fsync, BaseException cleanup |
| `src/wg_automate/templates/server.conf.j2` | Server config Jinja2 template | VERIFIED | Header comment, [Interface], [Peer] per client, AllowedIPs /32, conditional PostUp/PostDown |
| `src/wg_automate/templates/client.conf.j2` | Client config Jinja2 template | VERIFIED | Header comment, DNS line, Endpoint, AllowedIPs 0.0.0.0/0, PersistentKeepalive 25 |
| `pyproject.toml` | Project configuration with Python >=3.12 | VERIFIED | requires-python = ">=3.12,<3.15"; all 5 deps with version bounds |
| `requirements.in` | Dependency list with pip-compile/pip-audit comments | VERIFIED | All 5 deps; HARD-02 comment; HARD-03 comment |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `secret_types.py` | `secrets_wipe.py` | SecretBytes.wipe() calls wipe_bytes() | WIRED | `from .secrets_wipe import wipe_bytes` at top; `wipe_bytes(self._data)` in `wipe()` |
| `secret_types.py` | ctypes | mlock/VirtualLock at construction | WIRED | `import ctypes`; `ctypes.windll.kernel32.VirtualLock` on win32; `ctypes.CDLL("libc.so.6").mlock` on Linux |
| `vault.py` | `secret_types.py` | Passphrase held as SecretBytes; VaultState wraps keys | WIRED | `from .secret_types import SecretBytes`; `_wrap_secrets` converts `*_key`/`psk` fields to SecretBytes |
| `vault.py` | `secrets_wipe.py` | Derived key wiped after use | WIRED | `from .secrets_wipe import wipe_bytes`; `wipe_bytes(key_arr)` in `finally` blocks of `_encrypt_vault` and `_decrypt_vault` |
| `vault.py` | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` | AES-256-GCM encrypt/decrypt | WIRED | `from cryptography.hazmat.primitives.ciphers.aead import AESGCM`; used in both `_encrypt_vault` and `_decrypt_vault` |
| `vault.py` | `argon2.low_level.hash_secret_raw` | Argon2id KDF | WIRED | `from argon2.low_level import Type, hash_secret_raw`; called in `_derive_key` with `Type.ID` |
| `vault.py` | `atomic.py` | Atomic writes for vault file | WIRED | `from .atomic import atomic_write`; called in `create`, `save`, `change_passphrase` |
| `keygen.py` | `X25519PrivateKey` | Key generation | WIRED | `from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey`; `X25519PrivateKey.generate()` called |
| `keygen.py` | `secret_types.py` | Private keys wrapped in SecretBytes | WIRED | `from wg_automate.security.secret_types import SecretBytes`; `SecretBytes(bytearray(private_b64))` returned |
| `keygen.py` | `secrets_wipe.py` | Intermediate raw bytes wiped | WIRED | `from wg_automate.security.secrets_wipe import wipe_bytes`; `wipe_bytes(raw_private)` after base64 encoding |
| `config_builder.py` | `templates/` | Jinja2 FileSystemLoader loads templates | WIRED | `FileSystemLoader(str(template_dir))`; `template_dir = Path(__file__).parent.parent / "templates"` |
| `config_builder.py` | `validator.py` | Validates config data before rendering | WIRED | Local imports `validate_server_config`, `validate_client_config` called before `template.render(...)` |
| `integrity.py` | hashlib | SHA-256 hash computation | WIRED | `import hashlib`; `hashlib.sha256(...)` in `compute_config_hash` |
| `config_builder.py` | `filelock.FileLock` | Locks config during write-apply cycle | WIRED | `from filelock import FileLock`; `with FileLock(lock_path, timeout=30):` in `write_config` |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|---------|
| SEC-01 | 01-01 | SecretBytes blocks repr/str/hash/pickle/eq-timing leaks | SATISFIED | `__repr__`, `__str__` return `"SecretBytes(***)"`. `__hash__` raises TypeError. `__getstate__` raises TypeError. `__eq__` uses `hmac.compare_digest`. |
| SEC-02 | 01-01 | SecretBytes calls mlock() best-effort | SATISFIED | `_mlock()` in `__init__`; `try/except Exception: pass`; all three platforms handled. |
| SEC-03 | 01-01 | wipe_bytes: zero-random-zero; wipe_string: ctypes best-effort | SATISFIED | `wipe_bytes` has three explicit passes. `wipe_string` uses `ctypes.memset` with header offset. |
| SEC-04 | 01-01 | Secrets never held in immutable str/bytes longer than necessary | SATISFIED | Constructor converts `bytes -> bytearray`. All key generation paths use `bytearray`. |
| SEC-05 | 01-01 | Exception handlers wipe in finally; raise X from None | SATISFIED | `_encrypt_vault` and `_decrypt_vault` wipe derived key in `finally`. `VaultUnlockError` raised `from None`. Module docstring documents the pattern. |
| SEC-06 | 01-02 | AES-GCM nonce: os.urandom(12) per encryption, never reused | SATISFIED | `nonce = os.urandom(GCM_NONCE_LEN)` inside `_encrypt_vault`, called every invocation. No counter or timestamp. |
| VAULT-01 | 01-02 | AES-256-GCM with Argon2id (256MB/4iter/4par), vault at ~/.wg-automate/vault.enc | SATISFIED | `ARGON2_MEMORY_COST_KIB = 262144` (256 MiB). `DEFAULT_VAULT_PATH = Path.home() / ".wg-automate" / "vault.enc"`. |
| VAULT-02 | 01-02 | Vault directory 700 permissions; Windows ACL via icacls/pywin32 | SATISFIED | `_ensure_vault_dir`: `os.chmod(dir_path, 0o700)` on Unix; `icacls` on Windows with warning on failure. |
| VAULT-03 | 01-02 | Passphrase minimum 12 characters; collected via getpass (getpass is Phase 4 CLI) | SATISFIED | `if len(raw) < 12: raise ValueError("Passphrase must be at least 12 characters")`. getpass is Phase 4 CLI concern. |
| VAULT-04 | 01-02 | Vault state decrypted to memory only; wiped in finally even on exception | SATISFIED | `VaultState.__exit__` calls `wipe()`. Context manager pattern documented. |
| VAULT-05 | 01-02 | Atomic writes: .tmp + fsync + os.replace() | SATISFIED | `atomic_write` in `security/atomic.py`. Used by vault and config builder. |
| VAULT-06 | 01-02 | Tampered vault detected and rejected via GCM authentication tag | SATISFIED | `InvalidTag` exception caught, raises `VaultUnlockError("Vault unlock failed") from None`. |
| VAULT-07 | 01-02 | change_passphrase(old, new): decrypt, re-encrypt, atomic write | SATISFIED | `change_passphrase` method verified. |
| VAULT-08 | 01-02 | verify_integrity(): checks AES-GCM tag + Argon2 salt integrity | SATISFIED | `verify_integrity` method attempts decryption and wipes on success. |
| KEYGEN-01 | 01-03 | X25519 key pairs via cryptography library; no wg genkey subprocess | SATISFIED | `X25519PrivateKey.generate()` used; comment and no subprocess import. |
| KEYGEN-02 | 01-03 | Private keys extracted as bytearray; base64-encoded in memory; never touch disk unencrypted | SATISFIED | `bytearray(private_key.private_bytes_raw())`; wrapped in SecretBytes before return. |
| KEYGEN-03 | 01-03 | PSKs via os.urandom(32); 256-bit; unique per peer | SATISFIED | `bytearray(os.urandom(32))` in `generate_psk`. |
| KEYGEN-04 | 01-03 | Key bytes wiped via wipe_bytes() after use | SATISFIED | `wipe_bytes(raw_private)` and `wipe_bytes(raw_psk)` called immediately after base64 encoding. |
| IP-01 | 01-03 | Configurable subnet (default 10.0.0.0/24); server gets .1; clients from .2 | SATISFIED | `IPPool(subnet)` with default example `10.0.0.0/24`. Server gets `next(network.hosts())`. |
| IP-02 | 01-03 | IP allocation table in vault; conflicts validated; RFC 1918 subnet | SATISFIED | `self._allocated` dict; conflict check in `allocate()`. `is_private` check in `__init__`. `load_state` for vault persistence. |
| IP-03 | 01-03 | IP released immediately on client removal | SATISFIED | `release()` calls `pop(ip, None)` immediately. |
| CONFIG-01 | 01-04 | Jinja2 with StrictUndefined; autoescape correct for plain text | SATISFIED | `StrictUndefined` confirmed. `autoescape=False` is correct for WireGuard INI files. REQUIREMENTS.md has a documentation typo (`autoescape=True`) that contradicts research, plans, and all other docs. |
| CONFIG-02 | 01-04 | Pre-apply validator on every generated config; comprehensive checks | SATISFIED | validator.py covers: key format, PSK format, IP validity, port range, duplicate peer names (via validate_client_name), INI injection, AllowedIPs. |
| CONFIG-03 | 01-04 | Atomic writes; configs at 600 permissions (Unix) / SYSTEM+Admins (Windows) | SATISFIED | `atomic_write(..., mode=0o600)` in `write_config`. `permissions.py` provides cross-platform enforcement. |
| CONFIG-04 | 01-04 | SHA-256 hash computed after write; verified before reload | SATISFIED | `compute_config_hash`, `verify_config_integrity`, `store_hash_in_state` all present and wired. |
| CONFIG-05 | 01-04 | FileLock (not SoftFileLock) for TOCTOU protection | SATISFIED | `from filelock import FileLock`; used in `write_config`. Note: wg syncconf integration is Phase 4 CLI. |
| CONFIG-06 | 01-04 | Client names: alphanumeric + hyphens only, max 32 chars | SATISFIED | `_CLIENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9-]{1,32}$")` enforced with exact position errors. |
| HARD-01 | 01-01 | Python minimum version 3.12 | SATISFIED | `requires-python = ">=3.12,<3.15"` in pyproject.toml. |
| HARD-02 | 01-01 | Dependencies pinned with SHA-256 hashes in requirements.txt (via pip-tools) | PARTIAL -- BY DESIGN | `requirements.in` exists with pip-compile comment. Actual `requirements.txt` with hashes deferred to Phase 5 packaging per explicit plan decision: "Do NOT run pip-compile yet -- The .in file documents intent." |
| HARD-03 | 01-01 | pip-audit run against pinned requirements | PARTIAL -- BY DESIGN | `# Audit with: pip-audit` comment in `requirements.in`. Actual CI integration deferred to Phase 5. Same rationale as HARD-02. |

**Notes on HARD-02 and HARD-03:** Both are explicitly deferred to Phase 5 packaging in the plan (`01-01-PLAN.md`: "Do NOT run pip-compile yet (requirements.txt with hashes will be generated in Phase 5 packaging). The .in file documents intent."). This is a planned deferral, not an oversight. Requirements coverage for these two items is satisfied at the Phase 1 scope (intent documented).

**Requirements Coverage Summary:** 28/30 fully satisfied; 2/30 intentionally deferred to Phase 5.

---

## Anti-Patterns Found

No blockers or substantive stubs detected.

| File | Pattern | Severity | Assessment |
|------|---------|----------|------------|
| `atomic.py:72,77` | `pass` in except blocks | Info | Intentional -- best-effort cleanup in `BaseException` handler. Error already raised via `raise` at end of block. |
| `secrets_wipe.py:59` | `pass` in except block | Info | Intentional -- `wipe_string` is documented best-effort. |
| `secret_types.py:68,86` | `pass` in except blocks | Info | Intentional -- `_mlock` and `_munlock` are documented best-effort. |

---

## Documentation Discrepancy (Not a Code Gap)

**REQUIREMENTS.md CONFIG-01** states `autoescape=True` but every other authoritative source (01-RESEARCH.md, 01-04-PLAN.md, 01-04-SUMMARY.md, STATE.md, config_builder.py) confirms `autoescape=False` is the correct and intentional choice for WireGuard plain-text INI files. The REQUIREMENTS.md text contains a copy-paste error from an earlier draft. The code is correct.

**Recommendation:** Update REQUIREMENTS.md CONFIG-01 to read `autoescape=False` to match the research decision and implementation.

---

## Human Verification Required

### 1. mlock Memory Pinning

**Test:** On Linux, create a `SecretBytes` with a large buffer and check `/proc/<PID>/maps` or use `strace` to confirm `mlock` syscall succeeds.
**Expected:** The memory region appears in locked pages; no ENOMEM error (within system ulimit).
**Why human:** `_mlock()` silently swallows all exceptions; whether the OS actually pinned the pages cannot be determined from Python without privilege-level inspection.

### 2. Argon2id KDF Timing (TEST-04)

**Test:** Time `Vault.create()` and `Vault.open()` on target hardware (e.g., `time python -c "..."` with the round-trip test).
**Expected:** Each call takes at least 500ms (REQUIREMENTS.md TEST-04).
**Why human:** Cannot benchmark without executing the code; benchmark depends on hardware and OS memory limits.

### 3. wg syncconf (CONFIG-05 -- Phase 4 scope)

**Test:** When Phase 4 CLI is built, verify `wg syncconf` is used (not `wg setconf`) for live peer updates.
**Expected:** Active WireGuard sessions survive a peer config update.
**Why human:** The FileLock + atomic write plumbing is Phase 1; wg syncconf integration is Phase 4. Flag for Phase 4 verification.

---

## Summary

Phase 1 goal is fully achieved. All 38 must-have truths are verified against the actual codebase:

- **`SecretBytes`** is a complete, substantive implementation with mlock, zero-random-zero wipe, context manager, and full leak prevention (repr/str/hash/pickle/eq all hardened).
- **`Vault`** implements AES-256-GCM with Argon2id KDF at correct 256 MiB memory cost (262144 KiB -- the unit-error trap is documented and avoided), fresh nonces, atomic writes, GCM tamper detection, passphrase enforcement, and context-managed state with wiping.
- **`keygen` and `psk`** generate X25519 keys and PSKs in-process, hold intermediates only in bytearrays, wipe immediately after base64 encoding.
- **`IPPool`** manages RFC 1918 subnets with conflict detection and immediate IP release.
- **`ConfigBuilder`** validates before rendering (never produces partial configs), uses Jinja2 with StrictUndefined + autoescape=False (correct for plain text), writes atomically with FileLock.
- **`validator`, `integrity`, `permissions`, `atomic`** are all substantive, individually testable modules, properly wired.

All downstream phases can build on this foundation.

---

_Verified: 2026-03-17_
_Verifier: Claude (gsd-verifier)_
