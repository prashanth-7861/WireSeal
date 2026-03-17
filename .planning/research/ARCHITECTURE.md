# Architecture Patterns

**Domain:** Security-hardened cross-platform WireGuard VPN server automation CLI
**Researched:** 2026-03-17
**Overall confidence:** MEDIUM (training data for Python security patterns; web search unavailable for latest-version verification)

## Validation of Planned Architecture

The planned structure is sound. The separation into `core/`, `security/`, `platform/`, `dns/`, and `templates/` is the correct decomposition. Below are validations, corrections, and expansions.

### Red Flags in Current Plan: None Critical, Two Adjustments

1. **vault.py belongs in `security/`, not `core/`** -- The vault is the security boundary. Placing it in `core/` implies it is a utility rather than the security perimeter. Move `vault.py` to `security/vault.py`. Everything in `core/` should be "pure domain logic that receives already-decrypted data."

2. **Missing: a `types.py` or `models.py` for secret-carrying types** -- Without a dedicated `SecretBytes` wrapper type, secrets will be passed as plain `bytes` and accidentally logged, serialized, or compared in timing-unsafe ways. Add `security/secret_types.py` as the very first file built (even before vault).

### Revised Structure

```
wg-automate/
├── main.py                    # Entry point, click CLI group
├── core/
│   ├── keygen.py              # Curve25519 key generation (returns SecretBytes)
│   ├── psk.py                 # Pre-shared key generation (returns SecretBytes)
│   ├── config_builder.py      # Server and client .conf rendering (Jinja2)
│   ├── ip_pool.py             # VPN IP allocation (10.0.0.0/24)
│   └── qr_generator.py        # In-memory QR generation
├── security/
│   ├── secret_types.py        # SecretBytes, SecretStr — wipe-on-del, no __repr__
│   ├── vault.py               # AES-256-GCM encrypted state storage
│   ├── permissions.py         # File permission enforcement (600/700)
│   ├── firewall.py            # Firewall rule abstraction
│   ├── audit.py               # Append-only action logging
│   ├── validator.py           # Config validation before apply
│   ├── integrity.py           # Config file hash verification
│   └── secrets_wipe.py        # Secure memory/file wiping (ctypes mlock/munlock)
├── platform/
│   ├── base.py                # Abstract base class: PlatformAdapter
│   ├── detect.py              # OS detection, capability checks, adapter factory
│   ├── linux.py               # LinuxAdapter: systemd, nftables/iptables
│   ├── macos.py               # MacOSAdapter: launchd, pfctl
│   └── windows.py             # WindowsAdapter: WireGuard service, netsh, DPAPI
├── dns/
│   ├── duckdns.py             # DuckDNS HTTPS integration
│   └── ip_resolver.py         # Multi-source public IP consensus
└── templates/
    ├── server.conf.j2
    └── client.conf.j2
```

---

## Component Boundaries

| Component | Responsibility | Communicates With | Secrets Access |
|-----------|---------------|-------------------|----------------|
| `main.py` | CLI parsing, command dispatch, error display | All modules via function calls | NEVER holds secrets directly |
| `security/secret_types.py` | Defines `SecretBytes`/`SecretStr` wrappers | Used by all modules handling secrets | IS the secret container |
| `security/vault.py` | Encrypt/decrypt state, Argon2id KDF, atomic file I/O | `secret_types`, `secrets_wipe`, `permissions` | Sole gateway to persistent secrets |
| `security/secrets_wipe.py` | `mlock`/`munlock` via ctypes, zeroing bytearrays | Called by `secret_types` and `vault` | Handles raw memory operations |
| `security/permissions.py` | Enforce 600/700 on files/dirs, check before read | `vault`, `config_builder` | No secrets, only filesystem metadata |
| `security/audit.py` | Append-only structured log, never logs secret values | All command handlers | Receives action descriptions, NEVER secret values |
| `security/validator.py` | Validate config before apply (IP format, key format, INI injection) | `config_builder`, `vault` | Sees config values, not raw keys |
| `security/integrity.py` | SHA-256 hash tracking of deployed config files | `vault` (stores hashes), `platform/*` (checks before reload) | Stores hashes, not keys |
| `security/firewall.py` | Abstract firewall rule generation | `platform/*` for execution | No secrets |
| `core/keygen.py` | Generate X25519 key pairs via `cryptography` library | Returns `SecretBytes` | Generates secrets, immediately wraps |
| `core/psk.py` | Generate 256-bit pre-shared keys | Returns `SecretBytes` | Generates secrets, immediately wraps |
| `core/config_builder.py` | Render Jinja2 templates to WireGuard .conf | `vault` (reads decrypted state), `ip_pool` | Receives decrypted keys transiently |
| `core/ip_pool.py` | Allocate/release VPN IPs from subnet | `vault` (reads/writes allocation table) | No secrets |
| `core/qr_generator.py` | Generate QR in memory, display to terminal | `config_builder` (receives rendered config) | Transient: config contains keys |
| `platform/base.py` | ABC defining platform interface contract | Inherited by platform adapters | No secrets |
| `platform/detect.py` | OS detection, returns correct adapter instance | `platform/linux.py`, `macos.py`, `windows.py` | No secrets |
| `platform/linux.py` | systemd unit management, nftables/iptables rules | `firewall`, system commands via subprocess | No secrets, only config file paths |
| `platform/macos.py` | launchd plist management, pfctl rules | `firewall`, system commands via subprocess | No secrets |
| `platform/windows.py` | WireGuard Windows service, netsh rules, DPAPI | `firewall`, system commands, `vault` (DPAPI path) | DPAPI integration needs care |
| `dns/duckdns.py` | Update DuckDNS A record via HTTPS | `vault` (reads DuckDNS token), `ip_resolver` | DuckDNS token (wrapped in SecretStr) |
| `dns/ip_resolver.py` | Query 3 HTTPS sources, return 2-of-3 consensus IP | `requests` library | No secrets |

---

## Critical Architecture Patterns

### Pattern 1: SecretBytes Wrapper Type

**What:** A wrapper around `bytearray` (not `bytes` -- `bytes` is immutable and cannot be zeroed) that prevents accidental exposure and ensures cleanup.

**Why critical:** Without this, every `bytes` object containing key material is one `print()`, one `logging.debug()`, one JSON serializer, or one exception traceback away from leaking to logs or crash dumps.

**Confidence:** MEDIUM (well-established pattern in security libraries like `SecretStr` in Pydantic; ctypes mlock behavior verified via Python mmap docs confirming mmap does NOT provide memory locking)

```python
import ctypes
import sys
import os

class SecretBytes:
    """Mutable secret container. Zeroed on deletion. Never appears in repr/str."""

    __slots__ = ('_data', '_locked')

    def __init__(self, data: bytes | bytearray):
        # Store as bytearray (mutable, so we can zero it)
        self._data = bytearray(data)
        self._locked = False
        # Zero the source if it was a bytearray
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        # Attempt to mlock the buffer (best-effort)
        self._try_mlock()

    def _try_mlock(self):
        """Pin memory pages to prevent swapping to disk. Best-effort."""
        try:
            if sys.platform == 'linux':
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
                addr = ctypes.addressof(
                    (ctypes.c_char * len(self._data)).from_buffer(self._data)
                )
                if libc.mlock(ctypes.c_void_p(addr), len(self._data)) == 0:
                    self._locked = True
            elif sys.platform == 'darwin':
                libc = ctypes.CDLL('libSystem.B.dylib', use_errno=True)
                addr = ctypes.addressof(
                    (ctypes.c_char * len(self._data)).from_buffer(self._data)
                )
                if libc.mlock(ctypes.c_void_p(addr), len(self._data)) == 0:
                    self._locked = True
            # Windows: VirtualLock via ctypes.windll.kernel32
            elif sys.platform == 'win32':
                addr = ctypes.addressof(
                    (ctypes.c_char * len(self._data)).from_buffer(self._data)
                )
                ctypes.windll.kernel32.VirtualLock(
                    ctypes.c_void_p(addr), len(self._data)
                )
                self._locked = True
        except (OSError, ValueError):
            self._locked = False  # Best effort -- still zeroed on cleanup

    def reveal(self) -> bytearray:
        """Explicit access. Callers must document why they need raw bytes."""
        if not self._data:
            raise ValueError("Secret has been wiped")
        return self._data

    def wipe(self):
        """Zero the buffer and unlock memory."""
        if self._data:
            for i in range(len(self._data)):
                self._data[i] = 0
            if self._locked:
                self._try_munlock()
            self._data = bytearray()

    def _try_munlock(self):
        """Best-effort memory unlock."""
        try:
            if sys.platform in ('linux', 'darwin'):
                libc_name = 'libc.so.6' if sys.platform == 'linux' else 'libSystem.B.dylib'
                libc = ctypes.CDLL(libc_name, use_errno=True)
                # Buffer already zeroed, just unlock
                libc.munlock(ctypes.c_void_p(0), 0)  # Simplified
        except (OSError, ValueError):
            pass

    def __del__(self):
        self.wipe()

    def __repr__(self):
        return "SecretBytes(***)"

    def __str__(self):
        return "***"

    def __len__(self):
        return len(self._data)

    def __eq__(self, other):
        """Constant-time comparison to prevent timing attacks."""
        if not isinstance(other, SecretBytes):
            return NotImplemented
        import hmac
        return hmac.compare_digest(self._data, other._data)

    def __hash__(self):
        raise TypeError("SecretBytes is not hashable (prevents use as dict key)")

    # Prevent pickling
    def __getstate__(self):
        raise TypeError("Cannot serialize SecretBytes")

    def __reduce__(self):
        raise TypeError("Cannot serialize SecretBytes")
```

**Key design decisions in this type:**
- `bytearray` not `bytes` -- mutable, so we can zero it
- `__repr__` and `__str__` never reveal content -- safe in tracebacks
- `__eq__` uses `hmac.compare_digest` -- constant-time comparison
- `__hash__` raises -- prevents accidental use as dict key (which would keep references)
- `__getstate__`/`__reduce__` raise -- prevents pickling/serialization
- `reveal()` is explicit -- grep for `.reveal()` to audit all secret access points
- `mlock` is best-effort -- on failure, secrets are still zeroed but may swap
- `__del__` calls `wipe()` -- GC safety net (but never rely solely on `__del__`)

### Pattern 2: Vault Context Manager

**What:** A context manager that decrypts vault state into memory, provides access, re-encrypts on exit, and guarantees wipe even on exception.

**Why critical:** Without this, every command handler must remember to decrypt-use-encrypt-wipe manually. One missed path = plaintext keys in memory indefinitely.

```python
from contextlib import contextmanager
from typing import Generator

class VaultState:
    """In-memory decrypted vault contents. Only exists inside context manager."""
    def __init__(self, data: dict):
        self._data = data  # Contains SecretBytes values for keys
        self._sealed = False

    def get_server_private_key(self) -> SecretBytes:
        if self._sealed:
            raise RuntimeError("VaultState accessed after context exit")
        return self._data['server_private_key']

    def seal(self):
        """Wipe all secret values and mark as sealed."""
        for key, value in self._data.items():
            if isinstance(value, SecretBytes):
                value.wipe()
        self._data.clear()
        self._sealed = True


class Vault:
    def __init__(self, vault_path: str, passphrase: SecretBytes):
        self._vault_path = vault_path
        self._passphrase = passphrase
        # Derive key via Argon2id on init
        self._derived_key = self._derive_key(passphrase)

    @contextmanager
    def open(self) -> Generator[VaultState, None, None]:
        """Decrypt vault, yield state, re-encrypt and wipe on exit."""
        state = self._decrypt()
        try:
            yield state
        finally:
            # ALWAYS runs -- even on exception
            self._encrypt(state)
            state.seal()

    def _decrypt(self) -> VaultState:
        """Read vault file, decrypt with derived key, return VaultState."""
        # ... AES-256-GCM decryption ...
        pass

    def _encrypt(self, state: VaultState):
        """Re-encrypt state to vault file atomically."""
        # Write to .tmp, fsync, rename
        pass

    def _derive_key(self, passphrase: SecretBytes) -> SecretBytes:
        """Argon2id KDF."""
        pass
```

**Usage pattern in every command:**

```python
@cli.command()
@click.option('--name', required=True)
@click.pass_context
def add_client(ctx, name: str):
    vault: Vault = ctx.obj['vault']
    with vault.open() as state:
        # All secret access happens inside this block
        client_key = keygen.generate_keypair()
        psk = psk_module.generate_psk()
        state.add_client(name, client_key, psk)
        config = config_builder.render_client(state, name)
        qr_generator.display(config)
    # Here: state is sealed, all SecretBytes wiped
    audit.log('add-client', client=name)
```

### Pattern 3: Platform Abstraction via ABC (Not Duck Typing)

**Recommendation: Use `abc.ABC` with `@abstractmethod`, not Protocol or duck typing.**

**Rationale:**
- Duck typing fails silently at runtime if a method is missing -- in a security tool, "fail silently" is unacceptable
- `Protocol` (structural subtyping) is for third-party code you don't control; here we control all adapters
- ABC with `@abstractmethod` fails at *import time* if a method is unimplemented -- fail-fast, fail-loud

```python
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

class PlatformAdapter(ABC):
    """Contract for platform-specific operations. All methods must be implemented."""

    @abstractmethod
    def install_wireguard(self) -> None:
        """Install WireGuard if not present. Raise if impossible."""
        ...

    @abstractmethod
    def check_wireguard_installed(self) -> bool:
        """Check if WireGuard is available on this system."""
        ...

    @abstractmethod
    def deploy_config(self, config_content: str, interface: str) -> Path:
        """Write WireGuard config to platform-appropriate location. Returns path."""
        ...

    @abstractmethod
    def start_tunnel(self, interface: str) -> None:
        """Start WireGuard tunnel (systemd/launchd/service)."""
        ...

    @abstractmethod
    def stop_tunnel(self, interface: str) -> None:
        """Stop WireGuard tunnel."""
        ...

    @abstractmethod
    def reload_tunnel(self, interface: str) -> None:
        """Reload config without disconnecting (wg syncconf or equivalent)."""
        ...

    @abstractmethod
    def apply_firewall_rules(self, server_port: int, interface: str,
                              subnet: str) -> None:
        """Apply deny-by-default + allow WireGuard rules."""
        ...

    @abstractmethod
    def remove_firewall_rules(self, interface: str) -> None:
        """Remove WireGuard-specific firewall rules."""
        ...

    @abstractmethod
    def get_config_path(self, interface: str) -> Path:
        """Return platform-specific config file location."""
        ...

    @abstractmethod
    def check_privileges(self) -> bool:
        """Check if running with required privileges (root/admin)."""
        ...


def get_adapter() -> PlatformAdapter:
    """Factory function. Detects OS and returns correct adapter."""
    import sys
    if sys.platform == 'linux':
        from .linux import LinuxAdapter
        return LinuxAdapter()
    elif sys.platform == 'darwin':
        from .macos import MacOSAdapter
        return MacOSAdapter()
    elif sys.platform == 'win32':
        from .windows import WindowsAdapter
        return WindowsAdapter()
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform}")
```

**Why lazy imports in the factory:** Platform-specific modules import platform-specific libraries (e.g., `winreg` on Windows). Importing all platforms eagerly would fail on non-matching OSes.

### Pattern 4: Atomic File Writes

**What:** All file writes go through a single function that guarantees atomicity.

```python
import os
import tempfile
from pathlib import Path

def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write data to path atomically. Never leaves partial files."""
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    # Write to temp file in same directory (same filesystem = atomic rename)
    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix='.tmp_')
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = None  # Mark as closed

        # Set permissions before rename (so file is never world-readable)
        os.chmod(tmp_path, mode)

        # Atomic rename
        os.replace(tmp_path, str(path))

        # fsync parent directory to ensure rename is durable
        dir_fd = os.open(str(parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        if fd is not None:
            os.close(fd)
        # Clean up temp file on any failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
```

**Windows note:** `os.replace()` is atomic on Windows for NTFS since Python 3.3. The `os.open(dir, O_RDONLY)` for parent dir fsync does not work on Windows -- skip that step on win32 (NTFS metadata journaling provides equivalent durability guarantees for renames).

### Pattern 5: Audit Log That Never Logs Secrets

**What:** Structured audit logging with a type-level guarantee that secrets cannot be logged.

```python
import json
import time
from pathlib import Path

class AuditLog:
    """Append-only audit log. Accepts only str/int/float/bool values."""

    ALLOWED_TYPES = (str, int, float, bool, type(None))

    def __init__(self, log_path: Path):
        self._path = log_path

    def log(self, action: str, **kwargs) -> None:
        """Log an action. Raises TypeError if any value is SecretBytes."""
        for key, value in kwargs.items():
            if not isinstance(value, self.ALLOWED_TYPES):
                raise TypeError(
                    f"Audit log received non-primitive type for '{key}': "
                    f"{type(value).__name__}. This may indicate a secret leak."
                )

        entry = {
            'timestamp': time.time(),
            'iso_time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'action': action,
            **kwargs,
        }

        line = json.dumps(entry, separators=(',', ':')) + '\n'

        # Append atomically (O_APPEND is atomic for reasonable line sizes)
        with open(self._path, 'a') as f:
            f.write(line)
```

**Why type-check at the audit boundary:** The `SecretBytes` type lacks `__str__` that reveals content, so even accidental logging would show `***`. But the type check at the audit boundary is defense-in-depth: it catches the *attempt* to log a secret, not just masks it.

---

## Data Flow: Critical Paths

### Path 1: `init` (Server Setup)

```
User runs: wg-automate init --port 51820 --subnet 10.0.0.0/24
    |
    v
main.py: Parse args, prompt for vault passphrase (stdin, no echo)
    |
    v
secret_types.py: Wrap passphrase as SecretBytes
    |
    v
vault.py: Create new vault (Argon2id derive key from passphrase)
    |
    v
platform/detect.py: Detect OS, return PlatformAdapter
    |
    v
PlatformAdapter.check_privileges(): Verify root/admin
PlatformAdapter.check_wireguard_installed(): Verify or install
    |
    v
keygen.py: Generate server keypair -> (SecretBytes, SecretBytes)
    |                                   (private_key, public_key)
    v
vault.py: Store server keys + config in encrypted vault
    |
    v
config_builder.py: Render server.conf.j2 with vault data
    |                (keys decrypted only inside vault.open() context)
    v
validator.py: Validate rendered config (IP, key format, no injection)
    |
    v
PlatformAdapter.deploy_config(): Write to /etc/wireguard/wg0.conf (atomic)
    |
    v
permissions.py: Enforce 600 on config file
    |
    v
integrity.py: Compute SHA-256 of deployed config, store hash in vault
    |
    v
firewall.py -> PlatformAdapter.apply_firewall_rules()
    |
    v
PlatformAdapter.start_tunnel()
    |
    v
audit.py: Log "init" action (port=51820, subnet=10.0.0.0/24, NO keys)
    |
    v
secrets_wipe.py: All SecretBytes __del__ triggered on scope exit
```

**Secrets boundary:** Server private key exists as `SecretBytes` only between `keygen.generate()` and `vault.open().__exit__()`. It is never a `str`, never in a log, never in an exception message.

### Path 2: `add-client`

```
User runs: wg-automate add-client --name alice
    |
    v
main.py: Parse args, prompt for vault passphrase
    |
    v
vault.py context manager: Decrypt vault state
    |
    v
validator.py: Validate client name (alphanumeric + hyphen, max 32 chars)
    |
    v
ip_pool.py: Allocate next available IP from subnet
    |
    v
keygen.py: Generate client keypair -> SecretBytes pair
psk.py: Generate pre-shared key -> SecretBytes
    |
    v
vault state: Store client keys + PSK + allocated IP
    |
    v
config_builder.py: Render client.conf (needs server pubkey + client privkey + PSK)
    |
    v
config_builder.py: Re-render server.conf (add [Peer] block for new client)
    |
    v
validator.py: Validate both configs
    |
    v
qr_generator.py: Generate QR from client config, display to terminal
    |               (QR data exists only in terminal framebuffer)
    v
PlatformAdapter.deploy_config(): Update server config (atomic write)
    |
    v
integrity.py: Update config hash in vault
    |
    v
PlatformAdapter.reload_tunnel(): wg syncconf (no restart needed)
    |
    v
vault.open().__exit__(): Re-encrypt vault, wipe VaultState
    |
    v
audit.py: Log "add-client" (name=alice, ip=10.0.0.2, NO keys)
```

### Path 3: `remove-client`

```
User runs: wg-automate remove-client --name alice
    |
    v
main.py: Parse args, prompt for vault passphrase
    |
    v
vault.py context manager: Decrypt vault state
    |
    v
vault state: Look up client "alice", verify exists
    |
    v
ip_pool.py: Release alice's IP back to pool
    |
    v
vault state: Remove client entry (keys will be wiped on seal)
    |
    v
config_builder.py: Re-render server.conf (remove alice's [Peer] block)
    |
    v
validator.py: Validate updated server config
    |
    v
PlatformAdapter.deploy_config(): Update server config (atomic write)
    |
    v
integrity.py: Update config hash in vault
    |
    v
PlatformAdapter.reload_tunnel(): wg syncconf
    |
    v
vault.open().__exit__(): Re-encrypt vault (alice's keys now gone), wipe
    |
    v
audit.py: Log "remove-client" (name=alice, NO keys)
```

**Critical removal invariant:** The client's key material is removed from the vault *and* the [Peer] block is removed from the server config *in the same vault context*. If either fails, neither commits (the vault re-encrypts the original state on exception).

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Passing Raw bytes for Secrets

**What:** Using plain `bytes` or `str` for key material anywhere in the call stack.
**Why bad:** `bytes` is immutable -- cannot be zeroed. Shows up in `repr()`. Can be pickled. Can be used as dict key (keeps reference alive). Logged by default exception handlers.
**Instead:** Always use `SecretBytes`. Grep for `.reveal()` to audit all raw access.

### Anti-Pattern 2: Secrets in Exception Messages

**What:** Including key values in exception text or error context.
```python
# BAD
raise ValueError(f"Invalid key format: {private_key}")
```
**Why bad:** Exception messages end up in tracebacks, crash reports, logs, and error monitoring.
**Instead:** Reference keys by identifier, never by value.
```python
# GOOD
raise ValueError(f"Invalid key format for client '{client_name}'")
```

### Anti-Pattern 3: Subprocess with Secrets in Arguments

**What:** Passing key material via `subprocess.run(['wg', 'set', 'private-key', key_value])`.
**Why bad:** Arguments visible in `ps aux`, `/proc/PID/cmdline`, and process accounting logs.
**Instead:** Use the `cryptography` library directly for key operations. For `wg syncconf`, write to a temporary file with 600 permissions, pass the file path, then securely delete the temp file. Better yet: use `wg syncconf` with stdin pipe where supported.

### Anti-Pattern 4: Global State or Module-Level Secrets

**What:** Storing decrypted keys in module-level variables or singleton instances.
**Why bad:** Module-level objects persist for the entire process lifetime. No controlled cleanup.
**Instead:** Secrets exist only inside vault context manager scope. Context manager guarantees wipe.

### Anti-Pattern 5: Using os.system() or shell=True

**What:** `os.system('wg-quick up wg0')` or `subprocess.run(cmd, shell=True)`.
**Why bad:** Shell injection via crafted interface names or config values. Unpredictable shell expansion.
**Instead:** Always use `subprocess.run([...], shell=False, check=True)` with explicit argument lists. Validate all inputs before they reach subprocess calls.

### Anti-Pattern 6: Catching and Suppressing Errors Silently

**What:** `except Exception: pass` around security operations.
**Why bad:** Security tool must fail closed. Suppressed errors in permission setting, firewall application, or config deployment = silent security holes.
**Instead:** Let exceptions propagate. Catch specifically where you have a meaningful recovery. Log all caught exceptions. Every catch block should either re-raise or take an explicit corrective action.

---

## Build Order with Dependency Justification

The build order is driven by a strict principle: **no component should be built until the components it depends on for security guarantees exist.**

### Phase 1: Security Foundation (Build First)

| Order | Component | Depends On | Justification |
|-------|-----------|------------|---------------|
| 1 | `security/secret_types.py` | Nothing | Everything else uses this type. Must exist first so no code ever uses raw bytes for secrets. |
| 2 | `security/secrets_wipe.py` | `secret_types` | Provides the `mlock`/zeroing primitives that `SecretBytes.__del__` calls. |
| 3 | `security/vault.py` | `secret_types`, `secrets_wipe` | The vault is the security perimeter. All persistent state goes through it. Nothing else should persist data until this works. |
| 4 | `security/permissions.py` | Nothing | Vault needs to set 600/700 on its own file/directory. |
| 5 | `security/audit.py` | Nothing (but type-checks against `secret_types`) | Every subsequent operation should be audited from the start. |

**Phase 1 milestone:** Can create an encrypted vault, store/retrieve secret values, and log actions. Nothing else exists yet. This is correct -- the foundation must be trustworthy before building on it.

### Phase 2: Core Domain Logic

| Order | Component | Depends On | Justification |
|-------|-----------|------------|---------------|
| 6 | `core/keygen.py` | `secret_types` | Generates keys wrapped in `SecretBytes`. Needs vault to store them, but can be unit-tested independently. |
| 7 | `core/psk.py` | `secret_types` | Same pattern as keygen. |
| 8 | `core/ip_pool.py` | `vault` (for persistence) | IP allocation state stored in vault. No secrets involved, but needs persistent storage. |
| 9 | `templates/*.j2` | Nothing | Static templates, but needed by config_builder. |
| 10 | `core/config_builder.py` | `secret_types`, `vault`, `ip_pool`, templates | Renders configs from vault state. Needs all the above. |
| 11 | `security/validator.py` | `config_builder` (validates its output) | Must exist before any config is deployed. |
| 12 | `security/integrity.py` | `vault` (stores hashes) | Must exist before any config is deployed. |

**Phase 2 milestone:** Can generate keys, allocate IPs, render valid configs, validate them, and track their integrity. Still no platform-specific code.

### Phase 3: Platform Layer

| Order | Component | Depends On | Justification |
|-------|-----------|------------|---------------|
| 13 | `platform/base.py` | Nothing | ABC definition. |
| 14 | `platform/detect.py` | `base.py` | Factory function. |
| 15 | `platform/linux.py` | `base.py`, `permissions`, `firewall` | Primary platform. Build first because easiest to test (Docker). |
| 16 | `security/firewall.py` | `platform/base.py` | Abstraction that platform adapters implement. |
| 17 | `platform/macos.py` | `base.py`, `permissions`, `firewall` | Second platform. |
| 18 | `platform/windows.py` | `base.py`, `permissions`, `firewall` | Third platform. Most different (DPAPI, netsh, services). |

**Phase 3 milestone:** Can deploy configs and manage WireGuard tunnels on all three platforms.

### Phase 4: User-Facing Features

| Order | Component | Depends On | Justification |
|-------|-----------|------------|---------------|
| 19 | `core/qr_generator.py` | `config_builder` | QR display is a presentation concern. |
| 20 | `dns/ip_resolver.py` | `requests` | Independent utility. |
| 21 | `dns/duckdns.py` | `ip_resolver`, `vault` (for token) | DuckDNS integration. |
| 22 | `main.py` | Everything | CLI wiring. All components must exist. |

### Phase 5: Hardening and Distribution

| Order | Component | Depends On | Justification |
|-------|-----------|------------|---------------|
| 23 | Integration tests | All components | Docker-based end-to-end tests. |
| 24 | PyInstaller packaging | `main.py` + all deps | Standalone binaries. |
| 25 | GPG signing | PyInstaller output | Supply chain protection. |

---

## Secrets Flow Through the Call Stack

This is the most security-critical architectural concern. The rule is: **secrets flow DOWN into the vault context and NEVER flow UP past it.**

```
CLI Layer (main.py)
  |
  | passphrase (SecretBytes) -- only thing CLI touches
  v
Vault Layer (vault.py context manager)
  |
  | VaultState (contains SecretBytes values)
  | -- only exists inside `with vault.open() as state:`
  v
Domain Layer (keygen, config_builder, ip_pool)
  |
  | operates on VaultState, generates new SecretBytes
  | returns non-secret results (rendered config strings, IP strings)
  v
Platform Layer (adapters)
  |
  | receives config FILE PATHS, not secret values
  | executes system commands with non-secret arguments
  v
System (WireGuard, firewall, systemd)
```

**Key invariant:** The platform layer NEVER receives `SecretBytes` objects. It receives file paths to already-written config files. The config files themselves contain keys (WireGuard requires this), but file permissions (600) and integrity tracking protect them.

**Exception: Windows DPAPI.** On Windows, the DuckDNS token may be encrypted via DPAPI instead of the main vault. This is an acceptable deviation because DPAPI encryption is tied to the Windows user account and provides OS-level protection. The DPAPI integration should still use `SecretBytes` for the plaintext token in memory.

### Preventing Accidental Secret Exposure

| Risk | Mitigation |
|------|------------|
| `print()` debugging | `SecretBytes.__repr__` returns `"SecretBytes(***)"` |
| `logging.debug()` | `SecretBytes.__str__` returns `"***"` |
| Exception tracebacks | Never include secret values in exception messages |
| JSON serialization | `SecretBytes.__getstate__` raises `TypeError` |
| f-string interpolation | `__format__` should also return `"***"` (add this) |
| Dict key storage | `__hash__` raises `TypeError` |
| Comparison timing | `__eq__` uses `hmac.compare_digest` |
| Memory swap to disk | `mlock` via ctypes (best-effort) |
| Process crash dumps | `mlock` prevents core dump of locked pages on Linux (`MADV_DONTDUMP` also recommended) |
| GC delay in cleanup | Use context manager, don't rely solely on `__del__` |

### Additional Recommendation: MADV_DONTDUMP

On Linux, after `mlock`, also call `madvise(addr, len, MADV_DONTDUMP)` (value 16) to prevent the locked memory from appearing in core dumps. This is a one-line addition to `_try_mlock`:

```python
# After successful mlock on Linux:
libc.madvise(ctypes.c_void_p(addr), len(self._data), 16)  # MADV_DONTDUMP
```

**Confidence:** MEDIUM (MADV_DONTDUMP is a well-known Linux constant, value 16; verify against current kernel headers during implementation)

---

## Scalability Considerations

This is a CLI tool, not a server. "Scalability" here means number of managed peers and config complexity.

| Concern | 10 clients | 100 clients | 1000 clients |
|---------|-----------|-------------|--------------|
| Vault size | ~5KB encrypted | ~50KB encrypted | ~500KB encrypted |
| Config render time | Instant | Instant | ~1-2s (Jinja2 loop) |
| IP pool management | Linear scan OK | Linear scan OK | Consider bitmap allocation |
| Vault open/close | ~500ms (Argon2id) | ~500ms (Argon2id) | ~500ms + larger decrypt |
| WireGuard performance | Full speed | Full speed | WireGuard handles 1000s of peers natively |

**Recommendation:** Design for 100 clients in v1. The vault format should support efficient client lookup (dict keyed by client name, not a list). IP pool should use a set-based free list, not "scan all allocated IPs."

---

## Vault Data Format

The vault's decrypted JSON structure should be designed now because it affects every component.

```json
{
  "version": 1,
  "created": "2026-03-17T00:00:00Z",
  "server": {
    "private_key": "<base64>",
    "public_key": "<base64>",
    "port": 51820,
    "subnet": "10.0.0.0/24",
    "interface": "wg0",
    "dns_token": "<base64, DuckDNS token>",
    "hostname": "myvpn.duckdns.org"
  },
  "clients": {
    "alice": {
      "private_key": "<base64>",
      "public_key": "<base64>",
      "psk": "<base64>",
      "ip": "10.0.0.2",
      "created": "2026-03-17T00:00:00Z",
      "enabled": true
    }
  },
  "ip_pool": {
    "subnet": "10.0.0.0/24",
    "server_ip": "10.0.0.1",
    "allocated": {"10.0.0.2": "alice"}
  },
  "integrity": {
    "server_config_hash": "<sha256 hex>",
    "last_verified": "2026-03-17T00:00:00Z"
  }
}
```

**Note:** When this JSON is decrypted in memory, all `*_key` and `*_token` fields must be immediately wrapped in `SecretBytes` during deserialization. The `VaultState` class handles this -- it never exposes raw dict values.

**Version field:** Critical for forward compatibility. When vault format changes, the version field enables migration without re-creation.

---

## Testing Architecture

### Unit Tests (No Privileges Required)
- `secret_types.py` -- verify wipe, verify no repr leak, verify constant-time eq
- `vault.py` -- encrypt/decrypt round-trip, wrong passphrase rejection, atomic write
- `keygen.py` -- valid key generation, output is SecretBytes
- `ip_pool.py` -- allocation, release, exhaustion
- `config_builder.py` -- template rendering, StrictUndefined enforcement
- `validator.py` -- valid config passes, invalid config fails, injection attempts fail
- `audit.py` -- type checking rejects SecretBytes, append works

### Integration Tests (Docker, Requires Root)
- Linux end-to-end: init -> add-client -> verify tunnel -> remove-client
- Config integrity: deploy, tamper, verify detects
- Firewall: rules applied correctly, deny-by-default works
- Vault migration: v1 vault upgraded to v2 correctly

### Security-Specific Tests
- Verify `SecretBytes` does not appear in any log output
- Verify subprocess calls never contain key material in arguments
- Verify vault file is always encrypted (never plaintext on disk)
- Verify temp files are cleaned up on all error paths
- Verify file permissions are set correctly on all platforms

---

## Sources and Confidence

| Finding | Source | Confidence |
|---------|--------|------------|
| `bytearray` is mutable, `bytes` is not (for zeroing) | Python language specification | HIGH |
| `mmap` does NOT provide memory locking | Python mmap docs (verified via WebFetch) | HIGH |
| `ctypes` can call `mlock`/`munlock`/`VirtualLock` | Python ctypes docs + POSIX/Win32 API | MEDIUM (pattern well-known, but exact ctypes incantation should be tested per-platform) |
| `os.replace()` is atomic on NTFS | Python os module docs | HIGH |
| `MADV_DONTDUMP` value is 16 | Linux kernel headers | MEDIUM (verify during implementation) |
| ABC vs Protocol for platform abstraction | Python typing/abc design patterns | HIGH (language semantics are clear) |
| Argon2id with 256MB/4 iterations is OWASP-recommended | OWASP password storage cheat sheet | MEDIUM (verify current OWASP recommendations) |
| `hmac.compare_digest` provides constant-time comparison | Python hmac module docs | HIGH |
| WireGuard handles thousands of peers | WireGuard design documentation | MEDIUM (performance claims from training data) |
| Click group/command pattern for CLI | Click documentation | HIGH |

**Gaps requiring phase-specific research:**
- Windows DPAPI integration specifics via `ctypes.windll` -- needs testing on Windows
- PyInstaller behavior with `ctypes` mlock calls -- may need special handling
- Exact Argon2id parameters to achieve >500ms on target hardware -- benchmark during implementation
- `wg syncconf` stdin support across platforms -- verify during platform phase
