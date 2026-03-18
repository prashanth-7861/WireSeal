# Phase 1: Secure Core Engine - Research

**Researched:** 2026-03-17
**Domain:** Python cryptographic primitives, encrypted vault, key generation, config templating, IP allocation
**Confidence:** HIGH (crypto APIs verified against official docs; patterns verified against prior ecosystem research)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Passphrase Policy**
- Hard enforce minimum 12 characters — tool rejects shorter passphrases with no override option
- Optional passphrase hint: user may store a plaintext hint alongside vault during `init` (hint is NOT encrypted, just a memory aid — tool warns user of this)
- Passphrase confirmation: user types passphrase twice during vault creation; mismatch → retry (standard confirm)
- After 3 wrong passphrase attempts, tool exits cleanly (brute-force protection; Argon2id's ~500ms delay is additional protection)

**Error Verbosity**
- Wrong passphrase → generic message only: `"Vault unlock failed"` — never confirm whether passphrase or ciphertext is wrong
- Config validation failures → full detail: show exactly which field and why (e.g., `"Client name 'bad=name' contains invalid character '=' at position 4"`) — precise errors help legitimate users fix issues
- No `--verbose` / `--debug` flag — tool output is always minimal; secrets never appear in any output mode
- Config tampering detected (SHA-256 mismatch) → hard stop with `"SECURITY ALERT: Config file tampered — aborting. Do not reload WireGuard."` then exit — no prompt, no diff, no recovery path from this command

**Config Template Style**
- Server and client configs: minimal, no field-level comments
- Single standard header on all generated configs: `# Managed by wg-automate — do not edit manually`
- Client configs include `DNS = <server>` line; DNS server address is collected from user during `init` and stored in vault
- Firewall rules (PostUp/PostDown) placement: Claude's Discretion — pick the cleaner approach between embedding in wg0.conf vs platform adapter management

**Vault State Schema**
- Vault stores: server keypair, per-client (keypair + PSK + allocated IP), server port, VPN subnet, DNS server address — all encrypted, single source of truth
- Client records: keys + IP only — no metadata (no creation dates, labels, last-seen timestamps) in Phase 1
- Removed clients: fully purged immediately from vault — no tombstoning, no historical record
- Schema versioning: Claude's Discretion — decide whether to include a `schema_version` field for future migration support

### Claude's Discretion
- Firewall rule placement: PostUp/PostDown in wg0.conf vs managed by platform adapter (Phase 2 concern — planner should coordinate)
- Schema versioning: include `schema_version` field or not — Claude picks what future-proofs best at minimal cost
- Exact error retry UX flow for passphrase (prompt text, spacing)
- Argon2id parameter tuning (256MB/4iter/4par from requirements, but exact benchmarking approach)

### Deferred Ideas (OUT OF SCOPE)
- None — discussion stayed within Phase 1 scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| SEC-01 | `SecretBytes` wrapper type using `bytearray`, overrides `__repr__`, `__str__`, `__eq__`, `__hash__`, `__getstate__` | Architecture docs + full implementation pattern available |
| SEC-02 | `SecretBytes` calls `mlock()` via ctypes (best-effort) | ctypes mlock pattern documented with Linux/macOS/Windows variants |
| SEC-03 | `secrets_wipe.wipe_bytes(bytearray)` overwrites with zeros/random/zeros before release | wipe pattern documented; `ctypes.memmove` or loop approach |
| SEC-04 | All secrets use `bytearray`/`SecretBytes` — never held in `str` or `bytes` longer than necessary | Key design rationale documented throughout |
| SEC-05 | Exception handlers wipe secrets in `finally` blocks; traceback suppressed with `raise X from None` | Documented as CRIT-5 pitfall with prevention patterns |
| SEC-06 | AES-GCM nonces via `os.urandom(12)` per encryption — nonce reuse architecturally impossible | Verified: AESGCM API confirmed, nonce handling documented |
| VAULT-01 | AES-256-GCM + Argon2id vault at `~/.wg-automate/vault.enc` (chmod 600) | AESGCM and argon2-cffi APIs fully documented |
| VAULT-02 | Vault dir `~/.wg-automate/` created with 700 permissions; Windows ACL via icacls/pywin32 | File permission patterns documented; Windows ACL approach confirmed |
| VAULT-03 | Passphrase via `getpass`/`click.prompt(hide_input=True)`, min 12 chars enforced | `click.prompt(hide_input=True, confirmation_prompt=True)` API confirmed |
| VAULT-04 | Vault decrypted to memory only inside context manager; wiped in `finally` even on exception | Full VaultState context manager pattern documented |
| VAULT-05 | Atomic vault writes via `.tmp` + O_CREAT|O_EXCL + fsync + `os.replace()` | `atomic_write()` pattern fully documented |
| VAULT-06 | Tampered vault detected/rejected immediately via GCM authentication tag | AESGCM raises `InvalidTag` on any tamper/wrong key — no partial decryption |
| VAULT-07 | Passphrase change: decrypt with old, re-encrypt with new, atomic write | `change_passphrase()` pattern is straightforward vault decrypt/re-encrypt |
| VAULT-08 | Vault integrity verifiable on demand | GCM tag + Argon2 salt integrity check documented |
| KEYGEN-01 | X25519 key pairs via `cryptography.X25519PrivateKey.generate()` — no subprocess | Exact API confirmed: `X25519PrivateKey.generate()`, `private_bytes_raw()`, `public_key()` |
| KEYGEN-02 | Private keys extracted as `bytearray`, base64-encoded in memory, stored to vault only | `private_bytes_raw()` returns bytes; wrap in `bytearray` immediately; `base64.b64encode()` |
| KEYGEN-03 | PSK via `os.urandom(32)` — 256-bit, unique per peer | Standard: `os.urandom(32)` then `base64.b64encode()` |
| KEYGEN-04 | After use, key bytes wiped via `secrets_wipe.wipe_bytes()` | Wipe pattern documented |
| CONFIG-01 | Jinja2 with `StrictUndefined` and `autoescape=False` | Confirmed: `autoescape=False` correct for plain-text WireGuard configs |
| CONFIG-02 | Pre-apply validator: key format (base64, 44 chars, 32 bytes), PSK, IP, port, no injection | WireGuard key validation pattern documented; `base64.b64decode(validate=True)` |
| CONFIG-03 | Atomic config writes with 600/ACL permissions | `atomic_write()` pattern applies |
| CONFIG-04 | SHA-256 hash stored in vault; verified before WireGuard reload | `hashlib.sha256()` pattern documented |
| CONFIG-05 | `wg syncconf` with filelock to prevent TOCTOU race | `filelock.FileLock` ≥ 3.20.3 documented (CVE-2026-22701 patched) |
| CONFIG-06 | Client names: alphanumeric + hyphens only, max 32 chars | Regex validation pattern documented |
| IP-01 | VPN subnet configurable; server gets .1; clients get sequential .2+ | `ipaddress.ip_network().hosts()` iterator documented |
| IP-02 | IP allocation table in vault; conflict validation before assign | Set-based free list pattern in vault state documented |
| IP-03 | IP released immediately on client removal | Vault state update pattern documented |
| HARD-01 | Python minimum 3.12 | Confirmed in prior research: 3.12 is the target |
| HARD-02 | All deps pinned with SHA-256 hashes in requirements.txt via pip-tools | `pip-compile --generate-hashes` pattern documented |
| HARD-03 | `pip-audit` in CI | Tool documented in prior research |
</phase_requirements>

---

## Summary

Phase 1 builds the security foundation that every downstream phase depends on. The good news: every API needed for this phase is well-documented and stable. The `cryptography` library (AESGCM, X25519), `argon2-cffi`, Python's `ipaddress` stdlib, `Jinja2` with `StrictUndefined`, and `filelock` all have verified, stable APIs. No "figure it out as you go" areas exist in the core cryptographic path.

The vault binary format is the one design decision with lasting consequences: once vault.enc files exist in users' hands, the format cannot change without migration logic. The recommendation is to use a simple length-prefixed binary layout (magic bytes + version byte + argon2 salt + GCM nonce + ciphertext) with JSON as the inner plaintext representation. JSON is human-debuggable during development and incurs negligible overhead since the vault is encrypted as a single blob, not streamed.

One actionable security finding from this research: `filelock` had a TOCTOU CVE (CVE-2026-22701) that was patched in version 3.20.3. The requirements must pin `filelock>=3.20.3`. Use `FileLock` (not `SoftFileLock`) since all wg-automate processes run on the same host. The `autoescape` decision for Jinja2 also needs a clear call: use `autoescape=False` for WireGuard config files (plain text, not HTML — autoescape would corrupt base64 keys by escaping `=` and `+`).

**Primary recommendation:** Build in the order `secret_types.py` → `secrets_wipe.py` → `vault.py` → `permissions.py` → `keygen.py` + `psk.py` → `ip_pool.py` → templates + `config_builder.py` → `validator.py` → `integrity.py`. Unit tests accompany each module before moving to the next.

---

## Standard Stack

### Core (Phase 1 only)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| cryptography | >=46.0,<47 | X25519 key generation + AES-256-GCM vault encryption | pyca-maintained, OpenSSL-backed, the Python standard for production crypto |
| argon2-cffi | >=25.1,<26 | Argon2id KDF for vault passphrase | Reference Argon2 Python binding; `hash_secret_raw()` for KDF use case |
| Jinja2 | >=3.1.6,<4 | WireGuard config file rendering | StrictUndefined catches missing variables at render time, not at WireGuard load time |
| filelock | >=3.20.3 | Config read-modify-write-apply locking | CVE-2026-22701 patched in 3.20.3; FileLock uses OS primitives on all platforms |
| click | >=8.3.1,<9 | Passphrase prompts (vault unlock flow) | `click.prompt(hide_input=True)` is the correct cross-platform secure prompt API |

### Supporting (Phase 1 stdlib, no install)

| Module | Purpose | Notes |
|--------|---------|-------|
| `os` | `os.urandom()`, `os.replace()`, `os.fsync()`, `os.chmod()` | All atomic write and permission primitives |
| `ctypes` | `mlock`/`munlock`/`VirtualLock` for memory pinning | Best-effort; no exception on failure |
| `base64` | WireGuard key encoding/decoding | Use `b64decode(validate=True)` for key validation |
| `hashlib` | SHA-256 config integrity hashes | `hashlib.sha256(data).hexdigest()` |
| `json` | Vault inner plaintext serialization | Simple, human-readable during development |
| `hmac` | Constant-time comparison in SecretBytes | `hmac.compare_digest()` |
| `ipaddress` | Subnet iteration, IP validation, RFC 1918 checks | `ip_network().hosts()`, `.is_private` |
| `getpass` | Fallback passphrase input if click unavailable | Prefer `click.prompt(hide_input=True)` |
| `tempfile` | Temp file for atomic writes | `tempfile.mkstemp(dir=parent_dir)` |
| `struct` | Vault binary header packing | `struct.pack('>BH', version, salt_len)` for header |
| `pathlib` | Path manipulation throughout | `Path.mkdir(parents=True, exist_ok=True)` |

**Installation (Phase 1 dependencies only):**

```bash
pip install --require-hashes -r requirements.txt
# requirements.in for Phase 1:
cryptography>=46.0,<47
argon2-cffi>=25.1,<26
jinja2>=3.1.6,<4
filelock>=3.20.3,<4
click>=8.3.1,<9
```

---

## Architecture Patterns

### Recommended Project Structure (Phase 1 scope)

```
wg-automate/
├── src/
│   └── wg_automate/
│       ├── security/
│       │   ├── secret_types.py      # SecretBytes, SecretStr — build FIRST
│       │   ├── secrets_wipe.py      # mlock, zero, random, zero wipe
│       │   ├── vault.py             # AES-256-GCM + Argon2id KDF + context manager
│       │   ├── permissions.py       # 600/700 enforcement (Unix + Windows)
│       │   ├── validator.py         # Pre-apply config validation
│       │   └── integrity.py         # SHA-256 hash tracking
│       ├── core/
│       │   ├── keygen.py            # X25519 + PSK generation
│       │   ├── ip_pool.py           # VPN IP allocation/release
│       │   └── config_builder.py    # Jinja2 config renderer
│       └── templates/
│           ├── server.conf.j2
│           └── client.conf.j2
├── tests/
│   ├── security/
│   │   ├── test_secret_types.py
│   │   ├── test_secrets_wipe.py
│   │   ├── test_vault.py
│   │   ├── test_permissions.py
│   │   ├── test_validator.py
│   │   └── test_integrity.py
│   └── core/
│       ├── test_keygen.py
│       ├── test_ip_pool.py
│       └── test_config_builder.py
├── pyproject.toml
├── requirements.in
└── requirements.txt          # pip-compile --generate-hashes output
```

**Why `src/` layout:** Prevents pytest from accidentally importing the package from the project root instead of the installed version. Ensures tests always run against the installed package, catching missing `__init__.py` files and import issues early.

---

### Pattern 1: Vault Binary File Format

**Decision (Claude's Discretion):** Use a self-describing binary header with JSON inner plaintext.

**Rationale:** JSON for the plaintext is debuggable during development and supports forward-compatible field additions. The binary header carries the crypto parameters needed to decrypt, so the file is self-contained.

**Format layout (big-endian):**

```
Offset  Size   Field
------  ----   -----
0       4      Magic: b'WGAV' (WireGuard Automate Vault)
4       1      Format version: 0x01
5       1      Argon2 version: 0x13 (19 = ARGON2_VERSION)
6       4      Argon2 memory_cost (uint32, in KiB — e.g., 262144 for 256 MiB)
10      4      Argon2 time_cost (uint32 — e.g., 4)
14      4      Argon2 parallelism (uint32 — e.g., 4)
18      1      Salt length (uint8 — always 16)
19      16     Argon2 salt (random bytes)
35      1      Nonce length (uint8 — always 12)
36      12     AES-GCM nonce (random bytes per encrypt)
48      4      Ciphertext length (uint32)
52      N      AES-256-GCM ciphertext (includes 16-byte GCM tag appended by AESGCM)
52+N    M      Hint (optional plaintext UTF-8 string; 0 bytes if no hint)
```

**AAD (Additional Authenticated Data):** The header bytes 0–47 (everything before the ciphertext) are passed as AAD to AESGCM. This means any tampering with version, Argon2 parameters, salt, or nonce is detected by the GCM tag — not just ciphertext tampering.

**Schema versioning decision (Claude's Discretion):** Include `"schema_version": 1` as the first field of the inner JSON object. Cost: 2 bytes in the plaintext. Benefit: enables vault migration in v2 without re-prompting the user for the passphrase unnecessarily. Recommended: include it.

**Inner JSON structure:**

```json
{
  "schema_version": 1,
  "server": {
    "private_key": "<base64-44-chars>",
    "public_key": "<base64-44-chars>",
    "port": 51820,
    "subnet": "10.0.0.0/24",
    "interface": "wg0",
    "dns_server": "1.1.1.1"
  },
  "clients": {
    "alice": {
      "private_key": "<base64-44-chars>",
      "public_key": "<base64-44-chars>",
      "psk": "<base64-44-chars>",
      "ip": "10.0.0.2"
    }
  },
  "ip_pool": {
    "subnet": "10.0.0.0/24",
    "server_ip": "10.0.0.1",
    "allocated": {"10.0.0.2": "alice"}
  },
  "integrity": {
    "server_config_hash": "<sha256-hex-64-chars>",
    "last_verified": "2026-03-17T00:00:00Z"
  }
}
```

**During deserialization:** All `*_key` and `*_psk` fields are immediately wrapped in `SecretBytes` before `VaultState.__init__()` returns. The raw JSON dict never escapes the vault module.

---

### Pattern 2: Exact argon2-cffi KDF API

**Use `argon2.low_level.hash_secret_raw()` — NOT `PasswordHasher`.**

`PasswordHasher` is designed for password hashing (stores the salt in the output string for later verification). For KDF use (deriving an encryption key), use `hash_secret_raw()` which returns raw bytes.

```python
# Source: https://argon2-cffi.readthedocs.io/en/stable/api.html
from argon2.low_level import hash_secret_raw, Type

# CRITICAL: memory_cost is in KIBIBYTES (1 KiB = 1024 bytes)
# 256 MiB = 262144 KiB
ARGON2_MEMORY_COST_KIB = 262144   # 256 MiB
ARGON2_TIME_COST       = 4        # iterations
ARGON2_PARALLELISM     = 4        # threads
ARGON2_HASH_LEN        = 32       # bytes — produces a 256-bit AES key
ARGON2_SALT_LEN        = 16       # bytes — always generate fresh with os.urandom(16)

def derive_key(passphrase_bytes: bytearray, salt: bytes) -> bytes:
    """Derive 32-byte AES key from passphrase using Argon2id."""
    return hash_secret_raw(
        secret=bytes(passphrase_bytes),   # hash_secret_raw requires bytes, not bytearray
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,                     # Argon2id
    )
    # Caller is responsible for wiping the returned bytes after use
```

**CRITICAL unit note:** `memory_cost` is in **kibibytes (KiB)**, not bytes and not megabytes. 256 MiB = 262144 KiB. Passing 256 (thinking it means MB) would give 256 KiB — catastrophically weak.

**Benchmarking approach (Claude's Discretion):** At vault creation time, print a single line: `"Creating vault (this takes a moment)..."`. Do not benchmark or auto-tune — 256 MiB/4 iter is the fixed security parameter. If a user complains it's too slow, that's the design. Document this in the README. Do benchmark in the test suite (TEST-04 requires ≥500ms).

---

### Pattern 3: Exact AESGCM API

```python
# Source: https://cryptography.io/en/latest/hazmat/primitives/aead/
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key_bytes: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext. Returns (nonce, ciphertext_with_tag)."""
    aesgcm = AESGCM(key_bytes)          # key must be exactly 32 bytes for AES-256
    nonce = os.urandom(12)               # 96-bit nonce; NEVER reuse with same key
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    # ciphertext includes the 16-byte GCM authentication tag appended at the end
    return nonce, ciphertext

def decrypt(key_bytes: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt ciphertext. Raises cryptography.exceptions.InvalidTag on any tamper."""
    aesgcm = AESGCM(key_bytes)
    # InvalidTag is raised if key, nonce, ciphertext, OR aad are wrong/modified
    return aesgcm.decrypt(nonce, ciphertext, aad)
```

**Key facts:**
- `AESGCM(key)` accepts 16, 24, or 32-byte keys (128, 192, or 256 bit). Always use 32 bytes.
- `encrypt()` appends the 16-byte GCM tag to the ciphertext. You do not handle the tag separately.
- `decrypt()` raises `cryptography.exceptions.InvalidTag` — not a generic exception — when anything is wrong. Catch this specific exception, not `Exception`.
- The `aad` parameter authenticates but does not encrypt the associated data. Pass `None` if no AAD. For the vault, pass the header bytes as AAD (format version, Argon2 params, salt, nonce — bytes 0-47).
- `AESGCM.generate_key(bit_length=256)` can generate a key, but for the vault use the Argon2id-derived key, not a randomly generated one.

---

### Pattern 4: Exact X25519 Key Generation API

```python
# Source: https://cryptography.io/en/stable/hazmat/primitives/asymmetric/x25519/
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import base64

def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a Curve25519 key pair for WireGuard.
    Returns (private_key_b64, public_key_b64) as bytes objects.
    Caller must immediately wrap in SecretBytes and wipe source bytes.
    """
    private_key = X25519PrivateKey.generate()

    # private_bytes_raw() added in cryptography v40 — produces raw 32 bytes
    raw_private = bytearray(private_key.private_bytes_raw())

    # Public key is NOT secret — plain bytes is fine
    raw_public = private_key.public_key().public_bytes_raw()

    # WireGuard expects standard base64-encoded keys (NOT url-safe base64)
    private_b64 = base64.b64encode(bytes(raw_private))   # 44 chars ending in '='
    public_b64  = base64.b64encode(raw_public)            # 44 chars ending in '='

    # Wipe the intermediate raw private key buffer
    for i in range(len(raw_private)):
        raw_private[i] = 0

    return private_b64, public_b64
```

**Key facts:**
- `private_bytes_raw()` is a convenience method added in `cryptography` v40. It returns raw 32-byte `bytes`. Convert to `bytearray` immediately to enable zeroing.
- `public_key().public_bytes_raw()` also exists (v40+) and returns raw 32-byte `bytes`. The public key is not a secret — no need to wrap in SecretBytes.
- WireGuard keys are always standard Base64 (not URL-safe). The 44-character length with one trailing `=` is the canonical format. Keys that decode to anything other than 32 bytes are invalid.
- Never call `wg genkey` via subprocess. Keys would be visible in `/proc/PID/cmdline` and `ps aux` output on some systems.

---

### Pattern 5: WireGuard Key Validation

```python
import base64
import binascii

def validate_wg_key(key: str, field_name: str) -> None:
    """
    Validate a WireGuard key (public or private).
    Raises ValueError with precise error message on failure.
    """
    if len(key) != 44:
        raise ValueError(
            f"Field '{field_name}': expected 44-character base64 key, got {len(key)} characters"
        )
    try:
        decoded = base64.b64decode(key, validate=True)
    except binascii.Error as e:
        raise ValueError(
            f"Field '{field_name}': invalid base64 encoding — {e}"
        ) from None
    if len(decoded) != 32:
        raise ValueError(
            f"Field '{field_name}': key decodes to {len(decoded)} bytes, expected 32"
        )
```

**Why `validate=True` in b64decode:** Without it, `b64decode` silently discards characters outside the base64 alphabet. A key like `"AAAA...AA!!="` would silently strip `!!` and "succeed". With `validate=True`, any non-alphabet character raises `binascii.Error`.

---

### Pattern 6: Passphrase Prompt with 3-Attempt Limit

```python
import sys
import click
from .security.secret_types import SecretBytes

MAX_ATTEMPTS = 3
MIN_PASSPHRASE_LEN = 12

def prompt_passphrase_new() -> SecretBytes:
    """
    Prompt for a new vault passphrase (vault creation).
    Enforces minimum length and confirmation.
    Retries on mismatch, no limit (user is creating, not guessing).
    """
    while True:
        raw = click.prompt(
            "Enter new vault passphrase",
            hide_input=True,
            confirmation_prompt="Confirm vault passphrase",
        )
        if len(raw) < MIN_PASSPHRASE_LEN:
            click.echo(
                f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters. Try again."
            )
            continue
        result = SecretBytes(raw.encode('utf-8'))
        # Zero the string — best-effort (strings are immutable in Python)
        del raw
        return result

def prompt_passphrase_unlock() -> SecretBytes:
    """
    Prompt for vault passphrase (vault unlock).
    3 attempts then sys.exit(1).
    Error message is generic — never reveals whether passphrase or ciphertext is wrong.
    """
    for attempt in range(1, MAX_ATTEMPTS + 1):
        raw = click.prompt("Vault passphrase", hide_input=True)
        # Return immediately — caller validates against vault
        # On failure, caller calls this again up to MAX_ATTEMPTS times
        result = SecretBytes(raw.encode('utf-8'))
        del raw
        return result
    # Caller tracks attempt count and calls sys.exit(1) after 3 failures
```

**3-attempt logic pattern in the command handler:**

```python
def unlock_vault(vault_path: Path) -> tuple[Vault, SecretBytes]:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        passphrase = prompt_passphrase_unlock()
        try:
            vault = Vault.open(vault_path, passphrase)
            return vault, passphrase
        except VaultUnlockError:
            passphrase.wipe()
            if attempt < MAX_ATTEMPTS:
                click.echo("Vault unlock failed.")
            else:
                click.echo("Vault unlock failed.")
                sys.exit(1)
```

**Note:** Both failure messages are identical ("Vault unlock failed.") — this is the locked decision. The message does NOT say "wrong passphrase" or "incorrect key" — it never confirms which component failed.

---

### Pattern 7: Passphrase Hint Storage

The hint is stored as a plaintext `.hint` file alongside the vault. It is NOT encrypted.

```
~/.wg-automate/
├── vault.enc      # chmod 600 — encrypted vault
└── vault.hint     # chmod 644 — plaintext hint (optional, may not exist)
```

**During vault creation:**

```python
if hint_text:
    hint_path = vault_path.with_suffix('.hint')
    click.echo("WARNING: The passphrase hint is stored as plain text and is not protected.")
    hint_path.write_text(hint_text, encoding='utf-8')
    os.chmod(hint_path, 0o644)  # Readable; not a secret
```

**During vault unlock (on failure):**

```python
hint_path = vault_path.with_suffix('.hint')
if hint_path.exists():
    hint = hint_path.read_text(encoding='utf-8').strip()
    click.echo(f"Passphrase hint: {hint}")
```

Show the hint after the first failed attempt, not before. This avoids revealing the hint to someone who walks up to a logged-in terminal.

---

### Pattern 8: Atomic Write with Permission-First Ordering

```python
# Source: adapted from ARCHITECTURE.md pattern with Windows correction
import os
import sys
import tempfile
from pathlib import Path

def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """
    Write data to path atomically.
    Sets permissions BEFORE rename so the file is never world-readable.
    On Windows: skips parent dir fsync (NTFS journaling covers this).
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix='.tmp_')
    tmp_path_obj = Path(tmp_path)
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = None

        # Set permissions BEFORE rename — file is never visible as world-readable
        if sys.platform != 'win32':
            os.chmod(tmp_path, mode)
        # Windows: set ACL via icacls/pywin32 AFTER rename (permissions module handles this)

        os.replace(tmp_path, str(path))

        # fsync parent dir to persist the rename (Linux/macOS only)
        if sys.platform != 'win32':
            dir_fd = os.open(str(parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            tmp_path_obj.unlink(missing_ok=True)
        except OSError:
            pass
        raise
```

**Windows-specific note:** On Windows, `os.chmod()` only controls the read-only attribute — it does not set ACLs. Call the `permissions` module's Windows ACL function after `os.replace()` completes. The parent dir fsync is skipped on Windows (NTFS write-ahead log provides equivalent durability).

---

### Pattern 9: IP Pool Manager

```python
import ipaddress
from typing import Optional

class IPPool:
    """
    Manages VPN IP allocation within a subnet.
    Server always gets .1. Clients get sequential addresses starting at .2.
    Stored in vault as: {"allocated": {"10.0.0.2": "alice"}, "subnet": "10.0.0.0/24"}
    """

    def __init__(self, subnet: str):
        self.network = ipaddress.ip_network(subnet, strict=False)
        # Validate it's RFC 1918
        if not self.network.is_private:
            raise ValueError(f"Subnet {subnet} is not an RFC 1918 private range")
        self.server_ip = str(next(self.network.hosts()))   # Always .1
        self._allocated: dict[str, str] = {}               # ip -> client_name

    def load_state(self, allocated: dict[str, str]) -> None:
        """Restore allocation table from vault state."""
        self._allocated = dict(allocated)

    def allocate(self, client_name: str) -> str:
        """Allocate next available IP. Raises RuntimeError if pool exhausted."""
        for host in self.network.hosts():
            ip_str = str(host)
            if ip_str == self.server_ip:
                continue
            if ip_str not in self._allocated:
                self._allocated[ip_str] = client_name
                return ip_str
        raise RuntimeError(f"IP pool exhausted for subnet {self.network}")

    def release(self, ip: str) -> None:
        """Release an IP back to the pool. No-op if not allocated."""
        self._allocated.pop(ip, None)

    def is_allocated(self, ip: str) -> bool:
        return ip in self._allocated

    def get_allocated(self) -> dict[str, str]:
        """Return copy of allocation table for vault persistence."""
        return dict(self._allocated)
```

**Note on `ip_network(strict=False)`:** Using `strict=False` allows passing `10.0.0.1/24` (with a host bit set) without raising `ValueError`. This is friendlier for user input but the canonical stored form should always be the network address (`10.0.0.0/24`).

**Validation before assigning:** Before `allocate()`, the validator checks that the requested subnet is RFC 1918 (`is_private`) and that no existing client IP conflicts with the new allocation. The allocation table is the ground truth — do not trust WireGuard config for conflict detection.

---

### Pattern 10: Jinja2 Config Builder

```python
# Source: https://jinja.palletsprojects.com/en/stable/api/
from jinja2 import Environment, FileSystemLoader, StrictUndefined

def build_jinja_env(template_dir: str) -> Environment:
    """
    Build a Jinja2 environment for WireGuard config generation.
    autoescape=False: WireGuard configs are plain text, not HTML.
    StrictUndefined: missing variables raise immediately (not silently empty).
    """
    return Environment(
        loader=FileSystemLoader(template_dir),
        undefined=StrictUndefined,
        autoescape=False,           # CORRECT for plain-text .conf files
        keep_trailing_newline=True, # WireGuard convention: configs end with newline
        trim_blocks=True,           # Clean output: remove trailing newline after block tags
        lstrip_blocks=True,         # Clean output: remove leading whitespace before block tags
    )
```

**CRITICAL: `autoescape=False` for WireGuard configs.** Base64-encoded keys contain `=`, `+`, and `/`. With `autoescape=True`, these would be HTML-entity-escaped to `&#x3D;`, `&#x2B;`, `&#x2F;` — producing invalid WireGuard configs that would silently fail. The prior research recommendation of `autoescape=True` for WireGuard was incorrect (it was listed as defense-in-depth, but it would break key rendering). Use `autoescape=False`.

**Template files** (in `src/wg_automate/templates/`):

`server.conf.j2`:
```
# Managed by wg-automate — do not edit manually
[Interface]
PrivateKey = {{ server_private_key }}
Address = {{ server_ip }}/{{ prefix_length }}
ListenPort = {{ server_port }}
{% if post_up %}PostUp = {{ post_up }}
PostDown = {{ post_down }}
{% endif %}
{% for client in clients %}
[Peer]
# {{ client.name }}
PublicKey = {{ client.public_key }}
PresharedKey = {{ client.psk }}
AllowedIPs = {{ client.ip }}/32
{% endfor %}
```

`client.conf.j2`:
```
# Managed by wg-automate — do not edit manually
[Interface]
PrivateKey = {{ client_private_key }}
Address = {{ client_ip }}/32
DNS = {{ dns_server }}

[Peer]
PublicKey = {{ server_public_key }}
PresharedKey = {{ psk }}
Endpoint = {{ server_endpoint }}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**Firewall placement decision (Claude's Discretion):** Do NOT embed PostUp/PostDown in server.conf.j2 in Phase 1. The `{% if post_up %}` block is in the template for forward compatibility, but Phase 1 leaves it empty (post_up=""). Platform adapters in Phase 2 will manage firewall rules directly. This is cleaner than embedding platform-specific shell commands (nftables vs iptables vs pfctl) inside a WireGuard config file.

---

### Pattern 11: Config Validator

```python
import re
import ipaddress
import base64
import binascii

VALID_CLIENT_NAME = re.compile(r'^[a-zA-Z0-9-]{1,32}$')
WG_CONFIG_INJECTION_CHARS = re.compile(r'[\[\]=\n\r]')

def validate_client_name(name: str) -> None:
    """Per CONFIG-06: alphanumeric + hyphens only, max 32 chars."""
    if not VALID_CLIENT_NAME.match(name):
        # Find the first offending character and its position
        for i, ch in enumerate(name):
            if not (ch.isalnum() or ch == '-'):
                raise ValueError(
                    f"Client name '{name}' contains invalid character "
                    f"'{ch}' at position {i}"
                )
        if len(name) > 32:
            raise ValueError(
                f"Client name '{name}' exceeds 32-character limit ({len(name)} chars)"
            )
        if len(name) == 0:
            raise ValueError("Client name cannot be empty")

def validate_port(port: int, field_name: str = "port") -> None:
    if not (1024 <= port <= 65535):
        raise ValueError(
            f"Field '{field_name}': port {port} outside valid range 1024-65535"
        )

def validate_subnet(subnet: str, field_name: str = "subnet") -> None:
    try:
        net = ipaddress.ip_network(subnet, strict=True)
    except ValueError as e:
        raise ValueError(f"Field '{field_name}': invalid subnet '{subnet}' — {e}") from None
    if not net.is_private:
        raise ValueError(
            f"Field '{field_name}': subnet '{subnet}' is not an RFC 1918 private range"
        )

def validate_no_injection(value: str, field_name: str) -> None:
    """Reject characters that could break WireGuard INI format."""
    match = WG_CONFIG_INJECTION_CHARS.search(value)
    if match:
        char = match.group(0)
        pos = match.start()
        raise ValueError(
            f"Field '{field_name}': contains INI-injection character "
            f"'{repr(char)}' at position {pos}"
        )
```

---

### Pattern 12: filelock Usage for wg syncconf

```python
# Source: https://py-filelock.readthedocs.io/en/latest/api.html
# MUST use filelock >= 3.20.3 (CVE-2026-22701 patched)
from filelock import FileLock

WG_LOCK_PATH = "/var/run/wg-automate.lock"   # Linux/macOS
# Windows: use a path in %PROGRAMDATA% — see permissions module

def apply_config_atomic(config_path: str, interface: str) -> None:
    """
    Read-modify-write-apply cycle protected by file lock.
    Prevents TOCTOU race between concurrent wg-automate invocations.
    Use FileLock (not SoftFileLock) — all instances run on same host.
    """
    lock = FileLock(WG_LOCK_PATH, timeout=30)
    with lock:
        # Inside the lock: write config, verify integrity, then syncconf
        # ... atomic_write(config_path, new_content) ...
        # ... verify integrity hash ...
        # ... subprocess.run(['wg', 'syncconf', interface, config_path], check=True) ...
        pass
```

**Note on CVE-2026-22701:** The TOCTOU vulnerability was in `SoftFileLock`'s symlink handling, patched in 3.20.3. `FileLock` (OS-backed locking) is the correct choice here anyway — it uses `fcntl.flock()` on Unix and `msvcrt.locking()` on Windows, which are true advisory locks, not file-existence-based locks.

---

### Pattern 13: SHA-256 Config Integrity

```python
import hashlib
from pathlib import Path

def compute_config_hash(config_path: Path) -> str:
    """Compute SHA-256 of deployed config file. Returns hex string."""
    content = config_path.read_bytes()
    return hashlib.sha256(content).hexdigest()

def verify_config_integrity(config_path: Path, stored_hash: str) -> None:
    """
    Verify config file matches stored hash.
    On mismatch: prints SECURITY ALERT and raises SystemExit.
    """
    actual_hash = compute_config_hash(config_path)
    if not hmac.compare_digest(actual_hash, stored_hash):
        # Locked decision: exact message required
        click.echo(
            "SECURITY ALERT: Config file tampered — aborting. "
            "Do not reload WireGuard.",
            err=True
        )
        raise SystemExit(2)
```

**Why `hmac.compare_digest` for hash comparison:** Even though SHA-256 hashes are not secret, using constant-time comparison is a safe habit. It prevents any future timing-oracle attack if the comparison ever moves to secret data.

---

### Anti-Patterns to Avoid

| Anti-Pattern | What Goes Wrong | Correct Approach |
|---|---|---|
| `autoescape=True` in Jinja2 for WireGuard | Base64 keys have `=`, `+`, `/` — these get HTML-escaped, producing invalid configs | `autoescape=False` for plain-text configs |
| `PasswordHasher` for key derivation | Designed for password storage (encodes salt in output), not KDF; wrong API | `argon2.low_level.hash_secret_raw()` |
| Passing `memory_cost=256` to Argon2 thinking it means 256 MB | 256 KiB = catastrophically weak KDF | `memory_cost=262144` (KiB units) |
| `SoftFileLock` for the write lock | File-existence based, vulnerable to CVE-2026-22701 symlink attack | `FileLock` (OS-backed) |
| `b64decode(key)` without `validate=True` | Silently accepts keys with garbage characters, no error | `b64decode(key, validate=True)` |
| `bytes` for private key storage | Immutable — cannot be zeroed; survives GC arbitrarily | `bytearray` wrapped in `SecretBytes` |
| `os.rename()` for atomic writes on Windows | Fails when target exists | `os.replace()` which works cross-platform |
| Catching `Exception` on AESGCM decrypt | Misses the specific `InvalidTag` exception, creates broad error suppression | Catch `cryptography.exceptions.InvalidTag` specifically |
| Storing passphrase hint in vault | Hint purpose is memory aid when vault is locked; an encrypted hint is useless | Store hint as plaintext `.hint` file beside vault |
| `ip_network(strict=True)` for user input | Rejects `10.0.0.1/24` (host bits set); confusing for users | `ip_network(subnet, strict=False)` for input, `strict=True` for stored canonical form |

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Authenticated encryption | Custom AES + HMAC | `AESGCM` from `cryptography` | Encrypt-then-MAC ordering, tag management, nonce handling all error-prone |
| Memory-hard KDF | Custom PBKDF2 or bcrypt | `argon2.low_level.hash_secret_raw()` | Argon2id is OWASP-recommended; parameter selection is already done |
| Curve25519 key generation | Shell out to `wg genkey` | `X25519PrivateKey.generate()` | Subprocess args visible in process list; subprocess failure modes |
| IP address arithmetic | String splitting and integer math | `ipaddress.ip_network()` | RFC 1918 checking, host iteration, conflict detection all built in |
| File locking | `mkdir` as lock, or `open()` existence check | `filelock.FileLock` | Advisory locks are OS primitives; existence-based locks have TOCTOU issues |
| Base64 validation | Custom regex | `base64.b64decode(validate=True)` | RFC 4648 corner cases (padding, alphabet) are handled correctly |
| Config templating | String formatting with % or f-strings | Jinja2 with `StrictUndefined` | Missing variables silently produce empty fields in f-strings; Jinja2 fails loudly |

---

## Common Pitfalls

### Pitfall 1: Argon2 memory_cost Unit Error

**What goes wrong:** Developer sets `memory_cost=256` thinking it means 256 MB. Actual result: 256 KiB — essentially no memory hardening.
**Why it happens:** The argon2-cffi docs state the unit is "kibibytes" but this is easy to miss.
**How to avoid:** Define a named constant `ARGON2_MEMORY_COST_KIB = 262144` (262144 KiB = 256 MiB). Never use the raw number inline.
**Warning signs:** Vault unlock completes in <10ms instead of ~500ms.

### Pitfall 2: Jinja2 autoescape Corrupting WireGuard Keys

**What goes wrong:** `autoescape=True` HTML-escapes `=` in base64 keys (e.g., `AAAA...AA=` becomes `AAAA...AA&#x3D;`). WireGuard rejects the config with a cryptic parse error.
**Why it happens:** Security-minded developers default to `autoescape=True`. The prior ecosystem research also listed it as defense-in-depth (incorrectly for this use case).
**How to avoid:** Use `autoescape=False` explicitly. Add a code comment: `# Plain text config — autoescape would corrupt base64 keys`.
**Warning signs:** WireGuard logs "invalid key" despite keys looking correct in the file.

### Pitfall 3: filelock CVE-2026-22701 (SoftFileLock Symlink Race)

**What goes wrong:** Using `SoftFileLock` or `filelock < 3.20.3` allows a local attacker to create a symlink at the lock path, causing the lock to "acquire" while pointing at an attacker-controlled file, enabling a TOCTOU attack on the write cycle.
**Why it happens:** `SoftFileLock` uses file existence, not OS advisory locks. Symlink substitution between existence check and creation is the classic TOCTOU race.
**How to avoid:** Pin `filelock>=3.20.3`. Use `FileLock` (not `SoftFileLock`).
**Warning signs:** Running `pip show filelock` shows version < 3.20.3.

### Pitfall 4: InvalidTag vs Exception on Vault Decrypt

**What goes wrong:** `except Exception:` catches all errors including `InvalidTag`. Code shows "Vault unlock failed" for both wrong passphrase AND genuine Python exceptions (import errors, permission denied). Real errors are silently swallowed.
**Why it happens:** Developers catch `Exception` to be "safe."
**How to avoid:**
```python
from cryptography.exceptions import InvalidTag
try:
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
except InvalidTag:
    raise VaultUnlockError("Vault unlock failed") from None
# All other exceptions propagate — they're not vault unlock failures
```
**Warning signs:** Permission errors on the vault file appear as "Vault unlock failed."

### Pitfall 5: SecretBytes Wipe Not Called Before Scope Exit

**What goes wrong:** `SecretBytes.__del__` is a safety net, not a guarantee. If the object is placed in a local variable inside a try/except block that raises, and the caller catches the exception and continues, the `SecretBytes` may not be wiped until the GC runs much later.
**Why it happens:** `__del__` is triggered by GC, not by scope exit. Exception handlers can keep frames alive.
**How to avoid:** Always call `.wipe()` explicitly in `finally` blocks for any `SecretBytes` created in a function:
```python
passphrase = prompt_passphrase_unlock()
try:
    vault = Vault.open(vault_path, passphrase)
finally:
    passphrase.wipe()  # Explicit wipe — don't rely on GC
```

### Pitfall 6: JSON key Ordering in Vault Not Deterministic (Python 3.7+)

**What goes wrong:** Not a security issue, but if SHA-256 is computed over `json.dumps(state)` (not the encrypted vault), key ordering matters for hash stability. `json.dumps()` without `sort_keys=True` produces insertion-ordered output. If state is rebuilt from a dict in a different order, the hash changes even though the content is the same.
**Why it happens:** Dicts are ordered in Python 3.7+ but order depends on insertion sequence.
**How to avoid:** The SHA-256 is computed over the deployed config file content (the rendered WireGuard `.conf`), not over the JSON vault state. This is correct — it's the config file integrity that matters, not the vault contents.

---

## Code Examples

### Full Vault Encrypt/Decrypt Round-Trip

```python
import os
import struct
import json
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC = b'WGAV'
FORMAT_VERSION = 1
ARGON2_MEMORY_KIB = 262144   # 256 MiB
ARGON2_TIME_COST  = 4
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN   = 32

def vault_encrypt(plaintext_dict: dict, passphrase: bytearray) -> bytes:
    """Encrypt vault state dict to binary blob."""
    salt = os.urandom(16)
    nonce = os.urandom(12)

    # Derive AES key via Argon2id
    key = hash_secret_raw(
        secret=bytes(passphrase),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )

    # Build header (authenticated but not encrypted)
    header = (
        MAGIC
        + struct.pack('>BIII', FORMAT_VERSION, ARGON2_MEMORY_KIB,
                      ARGON2_TIME_COST, ARGON2_PARALLELISM)
        + struct.pack('>B', 16) + salt
        + struct.pack('>B', 12) + nonce
    )

    plaintext = json.dumps(plaintext_dict, separators=(',', ':')).encode('utf-8')

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, header)   # header is AAD

    return header + struct.pack('>I', len(ciphertext)) + ciphertext


def vault_decrypt(blob: bytes, passphrase: bytearray) -> dict:
    """Decrypt vault blob. Raises VaultUnlockError on any failure."""
    # Parse header
    if len(blob) < 52:
        raise ValueError("Vault file too short — corrupted")
    magic = blob[0:4]
    if magic != MAGIC:
        raise ValueError("Not a wg-automate vault file")

    version = blob[4]
    mem_cost, time_cost, parallelism = struct.unpack('>III', blob[5:17])
    salt_len = blob[17]
    salt = blob[18:18 + salt_len]       # 16 bytes
    nonce_len = blob[34]
    nonce = blob[35:35 + nonce_len]     # 12 bytes
    ct_len = struct.unpack('>I', blob[47:51])[0]
    ciphertext = blob[51:51 + ct_len]
    header = blob[0:47]                  # AAD: everything before ciphertext length field

    key = hash_secret_raw(
        secret=bytes(passphrase),
        salt=salt,
        time_cost=time_cost,
        memory_cost=mem_cost,
        parallelism=parallelism,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise VaultUnlockError("Vault unlock failed") from None

    return json.loads(plaintext.decode('utf-8'))
```

**Note:** The above is a reference implementation for the pattern. The actual vault module will have a `Vault` class with a context manager that wraps this, manages `VaultState`, and calls `atomic_write()`.

---

### pyproject.toml for Phase 1 Setup

```toml
[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "wg-automate"
version = "0.1.0"
requires-python = ">=3.12,<3.14"
dependencies = [
    "cryptography>=46.0,<47",
    "argon2-cffi>=25.1,<26",
    "jinja2>=3.1.6,<4",
    "filelock>=3.20.3,<4",
    "click>=8.3.1,<9",
]

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = ["--import-mode=importlib", "-ra"]
```

---

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|------------------|--------|
| `PasswordHasher` for KDF | `hash_secret_raw()` from `argon2.low_level` | Correct API: returns raw bytes, no encoded output |
| `private_bytes(encoding=Raw, format=Raw, ...)` | `private_bytes_raw()` (v40+) | Shorter, cleaner; same result |
| `SoftFileLock` | `FileLock` (OS-backed) + `filelock>=3.20.3` | CVE-2026-22701 mitigation |
| `autoescape=True` for all Jinja2 | `autoescape=False` for plain-text configs | Prevents key corruption |
| Setup.py / setup.cfg | `pyproject.toml` with `[tool.pytest.ini_options]` | Single config file |

**Deprecated/outdated in this context:**
- `argon2.hash_password_raw()`: deprecated alias since v16.0.0. Use `argon2.low_level.hash_secret_raw()`.
- `os.rename()` for atomic writes on Windows: replaced by `os.replace()` (cross-platform since Python 3.3).

---

## Open Questions

1. **Hint file encoding on Windows**
   - What we know: `path.write_text(text, encoding='utf-8')` works cross-platform
   - What's unclear: Whether Windows Notepad/Explorer opens UTF-8 files correctly without BOM
   - Recommendation: Write UTF-8 without BOM (default); add `# encoding: utf-8` as first line of hint file as documentation only

2. **Argon2id on low-RAM targets (Raspberry Pi, 512 MB VPS)**
   - What we know: 256 MiB will OOM or thrash on a system with 512 MB total RAM
   - What's unclear: Whether the tool needs to auto-detect available memory
   - Recommendation: Phase 1 hardcodes 256 MiB with no auto-tune. Document the minimum hardware requirement as 1 GB RAM in the README. This is a known limitation.

3. **VaultState thread safety**
   - What we know: wg-automate is a CLI tool — single process, single thread
   - What's unclear: Whether the context manager needs thread safety
   - Recommendation: No threading in Phase 1. VaultState is not thread-safe by design. Document this.

4. **Vault AAD boundary in binary format**
   - What we know: AAD should cover the header to detect tampering with Argon2 parameters
   - What's unclear: Exactly which bytes should be AAD (should ciphertext length field be included?)
   - Recommendation: Include bytes 0-47 (magic through nonce) as AAD. Exclude the 4-byte ciphertext length field — it's redundant with the ciphertext boundary. Verify in unit tests that modifying any header byte causes `InvalidTag`.

---

## Sources

### Primary (HIGH confidence)
- [cryptography.io AESGCM docs](https://cryptography.io/en/latest/hazmat/primitives/aead/) — AESGCM API, InvalidTag exception, nonce requirements
- [cryptography.io X25519 docs](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/x25519/) — private_bytes_raw(), public_bytes_raw(), from_private_bytes()
- [argon2-cffi API docs](https://argon2-cffi.readthedocs.io/en/stable/api.html) — hash_secret_raw() signature, memory_cost units (KiB), Type enum
- [Python ipaddress docs](https://docs.python.org/3/library/ipaddress.html) — ip_network(), hosts(), is_private
- [Python base64 docs](https://docs.python.org/3/library/base64.html) — b64decode(validate=True), binascii.Error
- [Jinja2 API docs](https://jinja.palletsprojects.com/en/stable/api/) — StrictUndefined, autoescape, from_string()
- [filelock docs](https://py-filelock.readthedocs.io/en/latest/api.html) — FileLock vs SoftFileLock, CVE-2026-22701
- Prior ecosystem research (.planning/research/STACK.md, ARCHITECTURE.md, PITFALLS.md) — verified HIGH confidence for all patterns cited

### Secondary (MEDIUM confidence)
- [filelock CVE-2026-22701 analysis](https://windowsnews.ai/article/python-filelock-toctou-vulnerability-cve-2026-22701-security-risks-patch-3203-analysis.402500) — CVE details and patch version
- [argon2-cffi parameters guide](https://argon2-cffi.readthedocs.io/en/stable/parameters.html) — tuning guidance, RFC 9106 profiles

### Tertiary (LOW confidence)
- None — all findings are HIGH or MEDIUM confidence

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all APIs verified against official docs on 2026-03-17
- Architecture: HIGH — vault format, crypto patterns, and component boundaries verified against official library docs
- Pitfalls: HIGH — Argon2 unit error and autoescape pitfall are concrete API behaviors, not heuristics; filelock CVE is a documented CVE
- Code examples: MEDIUM — patterns are correct but exact byte offsets in vault format should be verified against implementation (off-by-one in struct packing is possible)

**Research date:** 2026-03-17
**Valid until:** 2026-06-17 (90 days — crypto stdlib APIs are stable; filelock CVE status should be re-checked before Phase 5 packaging)
