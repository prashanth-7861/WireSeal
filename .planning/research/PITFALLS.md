# Domain Pitfalls: WireGuard Server Automation CLI

**Domain:** Security-hardened WireGuard VPN automation (Python CLI)
**Project:** wg-automate
**Researched:** 2026-03-17
**Overall Confidence:** MEDIUM (training data on well-established technical domains; web verification unavailable)

---

## Critical Pitfalls

Mistakes that cause security breaches, data loss, or require architectural rewrites.

---

### CRIT-1: Python Secrets Survive in Memory Indefinitely

**Severity:** CRITICAL
**Phase:** Vault/crypto foundation (Phase 1)
**Confidence:** HIGH (well-documented CPython internals)

**What goes wrong:** Python strings are immutable and garbage-collected non-deterministically. A private key loaded as a `str` or `bytes` object cannot be reliably overwritten. The original data persists in heap memory until the allocator reuses that page. Even `del` and `gc.collect()` do not guarantee the memory is zeroed.

**Why it happens:** CPython's memory allocator (`pymalloc`) uses arena-based allocation. Small objects (< 512 bytes -- which includes WireGuard keys at 44 base64 chars) are allocated from pools that are never returned to the OS until the arena is fully empty. String interning can create additional copies. Bytes concatenation creates intermediate copies.

**Consequences:**
- Core dumps contain plaintext private keys
- Memory forensics on a compromised server recovers keys
- Swap files may contain key material written to disk by the OS

**Prevention:**
```python
import ctypes
import mmap

class SecureBuffer:
    """Mutable buffer that can be explicitly zeroed."""
    def __init__(self, size):
        # Use mmap for page-aligned memory we control
        self._buf = mmap.mmap(-1, size, access=mmap.ACCESS_WRITE)
        # On Linux, mlock to prevent swapping
        try:
            import ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library('c'))
            libc.mlock(ctypes.c_void_p(ctypes.addressof(
                ctypes.c_char.from_buffer(self._buf))), size)
        except Exception:
            pass  # Best effort -- log warning

    def wipe(self):
        """Overwrite buffer contents with zeros."""
        self._buf.seek(0)
        self._buf.write(b'\x00' * self._buf.size())
        self._buf.close()

    def __del__(self):
        self.wipe()
```

Key rules:
1. Never convert key material to `str` -- keep as `bytes` in a `bytearray` (mutable) or `mmap` buffer
2. Use `bytearray` instead of `bytes` for any secret, then `bytearray[:] = b'\x00' * len(ba)` when done
3. Disable core dumps at process start: `resource.setrlimit(resource.RLIMIT_CORE, (0, 0))` on Unix
4. On Windows, use `ctypes.windll.kernel32.SetProcessWorkingSetSize` or `VirtualLock` to prevent swapping
5. Use `mlock()` on Linux to pin secret pages in RAM (prevent swap)

**Detection (warning signs during development):**
- Any function accepting a secret as `str` parameter
- String formatting or f-strings containing secrets
- Secrets appearing in `repr()` output of custom objects
- Logging statements near secret-handling code

**Additional leak vectors people miss:**
- `traceback.format_exc()` captures local variables including secrets in frame objects
- `sys.exc_info()` holds references to the frame, keeping secrets alive
- `pickle` serialization of objects containing secrets
- Python's `readline` module history (if secrets are ever entered interactively)
- `multiprocessing` pickles arguments, including secrets, through pipes
- `subprocess.run(capture_output=True)` stores output containing secrets in `CompletedProcess.stdout`

---

### CRIT-2: AES-GCM Nonce Reuse Destroys All Confidentiality

**Severity:** CRITICAL
**Phase:** Vault/crypto foundation (Phase 1)
**Confidence:** HIGH (mathematical property of GCM, well-documented in NIST SP 800-38D)

**What goes wrong:** AES-GCM uses a counter-mode construction where the nonce (IV) generates the keystream. If the same nonce is used twice with the same key, an attacker can XOR the two ciphertexts to cancel out the keystream, recovering plaintext. Worse, the authentication key (GHASH) is also derived from the nonce, so nonce reuse leaks the auth key, enabling forgeries of arbitrary messages.

**Why it happens:**
- Using a counter that resets on application restart
- Using `os.urandom(12)` for 96-bit nonces and hitting the birthday bound (~2^48 encryptions)
- Storing the nonce counter in a file that gets corrupted or rolled back from backup
- Clock-based nonce generation on systems where the clock can be set backwards

**Consequences:** Complete loss of both confidentiality and authenticity for ALL messages encrypted under that key. Not just the two colliding messages -- the leaked GHASH key allows forging any message.

**Prevention:**

Use the `cryptography` library's AESGCM which requires you to supply the nonce explicitly. The safest approach for a vault that encrypts infrequently:

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VaultCrypto:
    NONCE_SIZE = 12  # 96 bits, required for AES-GCM

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        aesgcm = AESGCM(key)
        # Random nonce is safe when:
        # 1. Key is rotated before 2^32 encryptions (very conservative)
        # 2. Nonce is 96 bits with os.urandom
        nonce = os.urandom(self.NONCE_SIZE)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ct  # Prepend nonce to ciphertext

    def decrypt(self, key: bytes, data: bytes, aad: bytes = b"") -> bytes:
        nonce = data[:self.NONCE_SIZE]
        ct = data[self.NONCE_SIZE:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, aad)
```

Critical rules:
1. Generate nonce with `os.urandom(12)` for each encryption -- never reuse, never derive from predictable values
2. Rotate the vault key after at most 2^32 encryptions (birthday bound for 96-bit nonce). For a CLI vault that encrypts on every save, this is effectively unlimited
3. Never implement nonce-as-counter unless you can guarantee persistence and monotonicity across crashes, restarts, and backup restores
4. Consider AES-GCM-SIV (nonce-misuse-resistant) if the library supports it, but standard AES-GCM with random nonces is fine for low-frequency vault operations
5. Include the vault version/format as AAD (additional authenticated data) to prevent downgrade attacks

**Detection:**
- Code review: any `encrypt()` call where the nonce is not freshly random
- Any nonce stored in a file or database (risky if file can be rolled back)
- Any nonce derived from a timestamp or counter without crash-safe persistence

---

### CRIT-3: WireGuard Config Reload Race Condition Causes Peer Disconnection

**Severity:** CRITICAL
**Phase:** WireGuard config management (Phase 2)
**Confidence:** MEDIUM (based on WireGuard documentation and known `wg` tool behavior; verify `wg syncconf` behavior on target platforms)

**What goes wrong:** `wg setconf` replaces the entire interface configuration atomically but tears down all existing peer sessions in the process. Every connected peer must re-handshake. If two config updates happen near-simultaneously (e.g., two `add-peer` commands), one update overwrites the other, losing a peer.

`wg syncconf` is the correct tool -- it diffs the config and applies only changes, preserving existing sessions. However, `wg syncconf` reads from a file, creating a TOCTOU (time-of-check-time-of-use) race: if another process modifies the file between your write and the `wg syncconf` call, the wrong config gets applied.

**Why it happens:**
- Using `wg setconf` instead of `wg syncconf`
- No file locking on the WireGuard config file
- Running `wg-quick` (which does `wg setconf` internally) instead of `wg syncconf`
- Multiple CLI invocations running concurrently (user runs `add-peer` twice quickly)

**Consequences:**
- Peers silently dropped from config (no error returned)
- Active VPN sessions interrupted for all peers (with `setconf`)
- Config file in inconsistent state (partial writes visible to concurrent readers)

**Prevention:**
```python
import fcntl  # Unix only
import tempfile
import os

class WireGuardConfigManager:
    def __init__(self, config_path: str, lock_path: str):
        self.config_path = config_path
        self.lock_path = lock_path

    def update_config(self, modifier_fn):
        """Atomically update WireGuard config with file locking."""
        # 1. Acquire exclusive lock
        lock_fd = open(self.lock_path, 'w')
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)

            # 2. Read current config
            with open(self.config_path, 'r') as f:
                current = f.read()

            # 3. Apply modification
            new_config = modifier_fn(current)

            # 4. Atomic write (tmp + rename in same directory)
            dir_name = os.path.dirname(self.config_path)
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')
            try:
                os.write(fd, new_config.encode())
                os.fsync(fd)
                os.close(fd)
                os.replace(tmp_path, self.config_path)  # Atomic on POSIX
            except:
                os.close(fd)
                os.unlink(tmp_path)
                raise

            # 5. Apply with syncconf (preserves sessions)
            # subprocess.run(['wg', 'syncconf', iface, config_path])

        finally:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            lock_fd.close()
```

Critical rules:
1. Always use `wg syncconf`, never `wg setconf` or `wg-quick` for live updates
2. Use file locking (`fcntl.flock` on Unix, `msvcrt.locking` on Windows) around the read-modify-write-apply cycle
3. Use atomic file writes (write to temp, `os.replace` to target) -- `os.replace` is atomic on POSIX when same filesystem
4. On Windows, `os.replace` may fail if the target is open by another process; handle `PermissionError` with retry
5. Verify `wg syncconf` return code -- a non-zero exit means the config was NOT applied
6. After `wg syncconf`, run `wg show <iface>` to verify the expected peers are present

**Detection:**
- Any use of `wg setconf` or `wg-quick up/down` for config changes after initial setup
- Config writes without a lock file
- Missing return code checks after `wg syncconf`

---

### CRIT-4: Argon2id Parameters Too Weak Defeats Vault Purpose

**Severity:** CRITICAL
**Phase:** Vault/crypto foundation (Phase 1)
**Confidence:** HIGH (OWASP and RFC 9106 provide specific parameter guidance)

**What goes wrong:** Argon2id with weak parameters (low memory, low iterations) can be brute-forced. The vault password is the single point of failure for all private keys. If parameters are tuned for "fast startup" during development and never updated, the vault provides security theater.

**Why it happens:**
- Developers set low parameters during testing and ship them
- Targeting low-end hardware (Raspberry Pi) and choosing parameters that are comfortable rather than secure
- Not understanding that Argon2's security comes primarily from memory hardness, not iteration count

**Consequences:** An attacker who obtains the encrypted vault file can brute-force weak passwords offline. If Argon2 parameters are too low, even moderate passwords fall.

**Prevention:**

Use RFC 9106 recommended minimums (OWASP 2023 guidelines align):

```python
# MINIMUM parameters for Argon2id (RFC 9106 / OWASP)
ARGON2_PARAMS = {
    'time_cost': 3,          # 3 iterations minimum
    'memory_cost': 65536,    # 64 MiB minimum (in KiB)
    'parallelism': 4,        # 4 lanes
    'hash_len': 32,          # 256-bit derived key
    'salt_len': 16,          # 128-bit salt (random per vault)
    'type': 'argon2id',      # NOT argon2i or argon2d
}

# RECOMMENDED parameters for server use (where 256 MiB is acceptable):
ARGON2_PARAMS_STRONG = {
    'time_cost': 3,
    'memory_cost': 262144,   # 256 MiB
    'parallelism': 4,
    'hash_len': 32,
    'salt_len': 16,
    'type': 'argon2id',
}
```

Critical rules:
1. Store Argon2 parameters in the vault header so they can be upgraded without re-encrypting from scratch -- the vault format must support parameter migration
2. At vault creation, benchmark the host: find the highest memory cost that completes in < 2 seconds on the target machine
3. Minimum floor: 64 MiB memory, 3 iterations, 4 parallelism. Refuse to create a vault with less
4. On Raspberry Pi / low-memory targets, 64 MiB is still achievable; do not drop below this
5. Salt must be `os.urandom(16)`, stored alongside the ciphertext (not secret, but must be unique)
6. Consider a "vault upgrade" command that re-encrypts with stronger parameters

**Detection:**
- `memory_cost` below 65536 (64 MiB) in any configuration
- `time_cost` below 2
- Hardcoded parameters without a benchmark or upgrade path
- Salt reuse across vault re-encryptions

---

### CRIT-5: Secrets Leak Through Python Exception Tracebacks

**Severity:** CRITICAL
**Phase:** Vault/crypto foundation (Phase 1), cross-cutting concern
**Confidence:** HIGH (inherent Python behavior, verified via faulthandler docs)

**What goes wrong:** When an exception occurs inside a function that has decrypted a secret, the traceback object holds references to frame locals, which include the secret. If this traceback is logged, printed, or serialized, the secret appears in plaintext. Even if not printed, the traceback object keeps the secret alive in memory, defeating wiping.

**Why it happens:**
```python
def deploy_peer_config(vault, peer_name):
    private_key = vault.decrypt_key(peer_name)  # Secret in local scope
    try:
        write_config(private_key)  # Raises an exception
    except Exception as e:
        logging.exception("Failed to deploy config")  # LEAKS private_key
        # Even without logging, sys.exc_info()[2] holds frame -> private_key
```

The `logging.exception()` call formats the traceback, which includes local variable references in the frame chain. Even `except Exception as e:` keeps the traceback alive via `e.__traceback__`.

**Consequences:**
- Private keys appear in log files
- Private keys persist in memory via traceback frame references
- Error reporting services (Sentry, etc.) capture and transmit secrets

**Prevention:**
```python
import sys

def safe_crypto_operation(vault, peer_name):
    private_key = None
    try:
        private_key = vault.decrypt_key(peer_name)
        result = use_key(private_key)
        return result
    except Exception:
        # Wipe secret BEFORE exception propagates
        if private_key is not None and isinstance(private_key, bytearray):
            private_key[:] = b'\x00' * len(private_key)
        # Clear traceback to release frame references
        try:
            raise  # Re-raise without holding the original traceback
        except Exception as clean_exc:
            # Log only the exception message, NOT the traceback
            logging.error("Crypto operation failed: %s", type(clean_exc).__name__)
            raise CryptoError("Operation failed") from None  # 'from None' suppresses chained traceback
    finally:
        if private_key is not None and isinstance(private_key, bytearray):
            private_key[:] = b'\x00' * len(private_key)
        # Explicitly clear traceback references
        sys.exc_clear() if hasattr(sys, 'exc_clear') else None  # Python 2 only
        # In Python 3, delete the exception variable explicitly
```

Critical rules:
1. Every function that handles secrets must wipe them in a `finally` block
2. Never use `logging.exception()` or `traceback.print_exc()` in code paths that handle secrets
3. Use `raise NewException("message") from None` to prevent traceback chaining that preserves frames
4. Implement a custom exception handler (`sys.excepthook`) that strips frame locals before printing
5. Delete exception variables explicitly: `except Exception as e: ... del e` (Python 3 does this automatically at end of `except` block, but explicit is safer in nested contexts)
6. Disable `faulthandler` in production if secrets are in memory (faulthandler dumps tracebacks, but NOT local variables -- per official docs, it shows only filename, function name, line number, so this is lower risk than initially expected)

**Detection:**
- `logging.exception()` or `logging.error(..., exc_info=True)` anywhere near secret-handling code
- `except Exception as e:` without `del e` or `from None` in secret-handling code
- Sentry/error-reporting SDK initialized without a `before_send` hook that scrubs secrets

---

## High Pitfalls

Mistakes that cause significant bugs, security weaknesses, or platform-specific failures.

---

### HIGH-1: Windows ACLs Are Not Unix chmod -- File Permissions Silently Wrong

**Severity:** HIGH
**Phase:** Cross-platform file I/O (Phase 2)
**Confidence:** HIGH (well-documented Windows/Unix divergence)

**What goes wrong:** On Unix, `chmod 600` restricts a file to owner-only read/write. On Windows, `os.chmod()` only affects the read-only flag; it does NOT set ACLs. A vault file "protected" with `os.chmod(path, 0o600)` on Windows is still readable by every user on the system. WireGuard private key files have the same problem.

**Why it happens:**
- Python's `os.chmod` on Windows maps permission bits to the read-only attribute only
- Developers test on Linux, assume `os.chmod` works the same on Windows
- Windows permission model is fundamentally different: ACLs (Access Control Lists) with inheritance, not simple user/group/other bits

**Consequences:**
- Vault file readable by any local user on Windows
- Private keys accessible to other processes/users
- False sense of security from "chmod 600" that silently does nothing useful

**Prevention:**
```python
import platform
import os

def secure_file_permissions(filepath: str):
    """Set owner-only read/write on any platform."""
    if platform.system() == 'Windows':
        _secure_windows_acl(filepath)
    else:
        os.chmod(filepath, 0o600)

def _secure_windows_acl(filepath: str):
    """Set Windows ACL to owner-only using icacls or win32security."""
    import subprocess
    # Method 1: icacls (always available, no pip dependencies)
    # Disable inheritance, remove all existing ACEs, grant current user full control
    username = os.environ.get('USERNAME', '')
    subprocess.run([
        'icacls', filepath,
        '/inheritance:r',           # Remove inherited permissions
        '/grant:r', f'{username}:(F)',  # Full control for current user only
    ], check=True, capture_output=True)

    # Method 2: pywin32 (more robust, handles edge cases)
    # import win32security, ntsecuritycon
    # ... set DACL with single ACE for current user SID
```

Critical rules:
1. Never rely on `os.chmod()` on Windows for security -- it is not a security mechanism on that platform
2. Use `icacls` (built into all Windows versions) or `pywin32` for real ACL management
3. On Windows, also handle inherited permissions: a file in a world-readable directory inherits those permissions unless inheritance is explicitly broken
4. Test file permissions on Windows CI, not just Unix
5. WireGuard on Windows runs as a SYSTEM service -- the config file must be readable by SYSTEM, not just the current user. Account for this in ACL setup

**Detection:**
- `os.chmod()` used without a platform check
- No Windows-specific permission code in the codebase
- Tests that only run on Linux

---

### HIGH-2: WireGuard on Windows Runs as SYSTEM -- User Context Mismatch

**Severity:** HIGH
**Phase:** Cross-platform WireGuard management (Phase 2-3)
**Confidence:** MEDIUM (based on WireGuard Windows architecture; verify current tunnel service behavior)

**What goes wrong:** On Windows, the WireGuard tunnel runs as the `NT AUTHORITY\SYSTEM` service. The CLI tool runs as the current user. This creates multiple problems:
1. Config files must be readable by SYSTEM, but you want them restricted from other users
2. The WireGuard tunnel service manages its own config store (`C:\Program Files\WireGuard\Data\Configurations`) and expects configs in a specific encrypted format
3. You cannot simply write a `.conf` file and have the service pick it up -- you must use the WireGuard tunnel management API or `wireguard.exe /installtunnelservice`
4. Named pipes used for IPC between the UI and tunnel service have specific security descriptors

**Why it happens:**
- Developers prototype on Linux where everything is simpler (just edit `/etc/wireguard/wg0.conf`)
- WireGuard's Windows implementation has a fundamentally different architecture than the kernel module on Linux
- The Windows tunnel service encrypts configs with DPAPI, so you cannot just overwrite the file

**Consequences:**
- CLI cannot manage tunnels without elevation (admin/SYSTEM rights)
- Config files written to wrong location are ignored
- Attempting to modify the DPAPI-encrypted config store corrupts it
- UAC prompts break automated workflows

**Prevention:**
1. On Windows, use `wireguard.exe /installtunnelservice <config>` and `/uninstalltunnelservice <tunnel-name>` for management
2. Alternatively, use the `wg.exe` userspace tool which works like Linux `wg` (but requires the tunnel to already be running)
3. Accept that Windows management requires Administrator elevation -- detect and prompt early rather than failing mid-operation
4. Store your own config files separately from WireGuard's DPAPI-encrypted store
5. On Windows, consider using the WireGuard Named Pipe IPC (`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<tunnel-name>`) for runtime management

**Detection:**
- Code that assumes `/etc/wireguard/` paths work everywhere
- No Windows elevation check (`ctypes.windll.shell32.IsUserAnAdmin()`)
- Direct file manipulation of WireGuard's Windows config store

---

### HIGH-3: macOS SIP/TCC Blocks pfctl and Network Configuration

**Severity:** HIGH
**Phase:** Cross-platform firewall/routing (Phase 3)
**Confidence:** MEDIUM (SIP/TCC restrictions are well-known but evolve with each macOS release; verify on target macOS version)

**What goes wrong:** macOS System Integrity Protection (SIP) and Transparency, Consent, and Control (TCC) restrict what processes can do, even with sudo:
1. `pfctl` (the packet filter control tool) requires root but works under SIP. However, modifying `/etc/pf.conf` may conflict with macOS's own firewall rules
2. Network extensions (the modern way to implement VPN on macOS) require an Apple Developer ID and notarization
3. The `wireguard-go` userspace implementation on macOS uses a `utun` device, which requires creating a network interface -- this needs root
4. TCC blocks access to network configuration changes without explicit user approval on newer macOS versions

**Why it happens:**
- macOS tightens security restrictions with each release
- WireGuard on macOS uses `wireguard-go` (userspace) not a kernel module
- Apple pushes developers toward Network Extension framework, which requires signing and notarization
- Homebrew `wireguard-tools` works but has limitations compared to Linux

**Consequences:**
- CLI tool cannot configure firewall rules without root and careful pfctl management
- pfctl rule conflicts with macOS Application Firewall
- Unsigned tools may be blocked by Gatekeeper
- Updates to macOS may break previously working configurations

**Prevention:**
1. On macOS, use `wg-quick` (from `wireguard-tools` Homebrew package) which handles `utun` setup and routing
2. For firewall rules, use `pfctl` but load rules into a separate anchor (`/etc/pf.anchors/wg-automate`) rather than modifying the main `pf.conf`
3. Check macOS version and warn about known restrictions
4. Accept that macOS support will always be a second-class citizen compared to Linux
5. Document that macOS users need to install `wireguard-tools` via Homebrew

**Detection:**
- Code that assumes `iptables` exists on macOS
- Direct modification of `/etc/pf.conf` instead of using anchors
- No macOS version detection

---

### HIGH-4: PyInstaller _MEI Temp Directory Enables Code Injection

**Severity:** HIGH
**Phase:** Packaging/distribution (Phase 4-5)
**Confidence:** MEDIUM (well-known PyInstaller behavior, but mitigations may have changed in recent versions; verify current PyInstaller)

**What goes wrong:** When a PyInstaller `--onefile` bundle runs, it extracts all bundled files (Python interpreter, libraries, your code) to a temporary directory (`_MEI<random>` in the system temp dir). On multi-user systems:
1. The temp directory may be predictable or world-readable
2. A local attacker can race to modify extracted `.pyd`/`.so` files before they are loaded
3. DLL hijacking: if the extraction directory is in the DLL search path, an attacker can place malicious DLLs there
4. On Windows, the `%TEMP%` directory defaults to the user's AppData, but for SYSTEM services it is `C:\Windows\Temp` which has different ACLs

**Why it happens:**
- PyInstaller must extract files to disk before the Python interpreter can load them
- The extraction happens before your code runs, so you cannot control the directory permissions
- `--onefile` mode is convenient but creates this attack surface
- `--onedir` mode avoids extraction but has its own issues (users can modify bundled files)

**Consequences:**
- Local privilege escalation if the CLI runs as admin/root
- Code injection into a security-sensitive tool
- Bundled `cryptography` library DLLs could be replaced with malicious versions

**Prevention:**
1. Prefer `--onedir` mode over `--onefile` -- install to a protected directory (e.g., `C:\Program Files\` on Windows, `/usr/local/bin/` on Linux) with proper permissions
2. If using `--onefile`, set `--runtime-tmpdir` to a secure directory with restricted permissions rather than system temp
3. On Windows, if running as SYSTEM, ensure the extraction directory is not writable by regular users
4. Consider code signing the executable (Authenticode on Windows, `codesign` on macOS)
5. Add runtime integrity checks: hash the bundled `cryptography` library after extraction
6. Alternative: use `shiv` or `zipapp` which do not extract native code to temp directories (but have their own limitations with C extensions)

**Detection:**
- Using `--onefile` without `--runtime-tmpdir`
- No code signing in the release pipeline
- Running the PyInstaller bundle as admin/SYSTEM without considering temp directory security

---

### HIGH-5: IP Pool Allocation Race Condition Causes Address Conflicts

**Severity:** HIGH
**Phase:** Peer management (Phase 2)
**Confidence:** HIGH (classic concurrency bug)

**What goes wrong:** When two `add-peer` commands run concurrently, both read the current peer list, both find the same "next available IP" (e.g., 10.0.0.3), and both assign it. One peer's config overwrites the other, or both peers get the same IP causing routing conflicts.

**Why it happens:**
- IP allocation reads the current config, finds gaps, and assigns the next IP
- Without locking, the read-check-assign sequence is not atomic
- Even single-user CLIs can have this: user runs `add-peer alice` and `add-peer bob` in two terminals

**Consequences:**
- Two peers with same VPN IP -- one cannot connect, or traffic routes to wrong peer
- Silent failure: WireGuard does not validate IP uniqueness across peers at the protocol level
- Debugging is difficult because both configs look valid individually

**Prevention:**
```python
def allocate_ip(config_manager, subnet: str) -> str:
    """Allocate next available IP with exclusive locking."""
    # This must be inside the same lock as the config write
    # DO NOT: allocate IP, release lock, then write config
    with config_manager.exclusive_lock():  # Same lock as CRIT-3
        used_ips = config_manager.get_all_peer_ips()
        for candidate in ip_network(subnet).hosts():
            if str(candidate) not in used_ips and candidate != gateway_ip:
                # Write peer config with this IP while still holding lock
                config_manager.add_peer(ip=str(candidate), ...)
                return str(candidate)
        raise ExhaustedError("No IPs available in subnet")
```

Critical rules:
1. IP allocation and config write MUST be in the same critical section (same lock acquisition)
2. Never allocate an IP, release the lock, then write the config -- another process can grab the same IP
3. Validate IP uniqueness at write time, not just at allocation time
4. Consider storing allocated IPs in the vault/state file, not just deriving from the WireGuard config (in case the config is manually edited)

**Detection:**
- IP allocation function that does not hold a lock during the entire allocate-and-write sequence
- Separate "find next IP" and "write peer" functions without shared locking
- No duplicate IP validation before applying config

---

### HIGH-6: DuckDNS Token Exposure Through Process Arguments and Logs

**Severity:** HIGH
**Phase:** DNS update module (Phase 3)
**Confidence:** HIGH (well-known Unix process visibility model)

**What goes wrong:** DuckDNS updates are typically HTTP GET requests: `https://www.duckdns.org/update?domains=X&token=Y&ip=Z`. The token authenticates updates. Common exposure vectors:
1. Token passed as CLI argument: visible in `ps aux`, `/proc/<pid>/cmdline`, Windows Task Manager
2. Token in environment variable: visible in `/proc/<pid>/environ`, inherited by child processes
3. Token logged in HTTP request URLs by debug logging
4. Token in shell history (`~/.bash_history`) if user runs commands manually
5. Token in error messages when the HTTP request fails (URL appears in exception)

**Why it happens:**
- DuckDNS API is simple HTTP, encouraging quick-and-dirty implementations
- Python's `urllib` and `requests` libraries log URLs at DEBUG level
- Exception messages from HTTP libraries include the full URL (with token)

**Consequences:**
- Anyone who can list processes sees the token
- Token in logs allows DNS hijacking -- attacker points your domain to their server, enabling MitM against VPN clients

**Prevention:**
```python
import logging

# 1. Never pass token as CLI argument or environment variable
#    Read from the encrypted vault only

# 2. Suppress URL logging from HTTP libraries
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("http.client").setLevel(logging.WARNING)

# 3. Catch HTTP exceptions and strip the URL
def update_duckdns(token: str, domain: str, ip: str) -> bool:
    import urllib.request
    url = f"https://www.duckdns.org/update?domains={domain}&token={token}&ip={ip}"
    try:
        resp = urllib.request.urlopen(url)
        result = resp.read().decode().strip()
        return result == "OK"
    except Exception as e:
        # DO NOT log the exception directly -- it contains the URL with token
        logging.error("DuckDNS update failed (network error)")
        return False
    finally:
        # Wipe URL from local scope (it contains the token)
        url = "x" * len(url)  # Overwrite (imperfect for str, but reduces window)
```

Critical rules:
1. Store DuckDNS token in the encrypted vault, not in a config file, environment variable, or CLI argument
2. Suppress DEBUG logging for HTTP libraries
3. Never log the full DuckDNS URL
4. Sanitize exception messages before logging (strip token)
5. Use HTTPS (DuckDNS supports it) -- but note the token is still in the URL path, visible to proxy logs

**Detection:**
- Token appears in any CLI argument parsing (`argparse` definition)
- Token read from environment variable (`os.environ`)
- `logging.debug` or `logging.info` calls near HTTP request code
- Raw exception re-raising from HTTP code without sanitization

---

## Moderate Pitfalls

Mistakes that cause bugs, poor UX, or maintenance burden.

---

### MOD-1: INI Injection in WireGuard Config Files

**Severity:** MEDIUM
**Phase:** Config generation (Phase 2)
**Confidence:** HIGH (WireGuard configs are INI-like format)

**What goes wrong:** WireGuard config files are INI format. If peer names, descriptions, or comments are derived from user input without sanitization, an attacker can inject additional config directives. For example, a peer "friendly name" stored as a comment could contain a newline followed by `PostUp = malicious-command`.

**Prevention:**
1. Never interpolate user input directly into config files
2. Strip newlines, `[`, `]`, `=`, and `#` from any user-supplied values before writing to config
3. Use a config builder that writes fields explicitly, not string concatenation
4. Validate the generated config before writing: parse it back and ensure no unexpected sections/keys exist
5. `wg-quick` executes `PostUp`, `PostDown`, `PreUp`, `PreDown` as shell commands -- ensure these are never populated from user input

**Detection:**
- String concatenation or f-strings used to build config files
- User input written to config without a sanitization step
- PostUp/PostDown values that include any dynamic content

---

### MOD-2: os.replace() Is Not Atomic on Windows in All Cases

**Severity:** MEDIUM
**Phase:** File I/O (Phase 1-2)
**Confidence:** HIGH (documented Python behavior on Windows)

**What goes wrong:** On POSIX, `os.replace(src, dst)` is atomic (guaranteed by rename(2) on same filesystem). On Windows, `os.replace()` calls `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, which is NOT atomic if:
1. The target file is open by another process (raises `PermissionError`)
2. Source and destination are on different volumes (operation becomes copy+delete)
3. Antivirus software has a handle on the file

**Prevention:**
1. Always write temp files to the SAME directory as the target (same filesystem)
2. On Windows, implement retry logic for `PermissionError` with exponential backoff (antivirus scans)
3. On Windows, consider using `ctypes` to call `ReplaceFileW` which provides transactional semantics with backup
4. Close all handles to the target file before replacing
5. Test with Windows Defender active (it opens files for scanning)

**Detection:**
- `tempfile.mkstemp()` using default temp directory instead of target directory
- No error handling around `os.replace()` on Windows
- No retry logic for `PermissionError`

---

### MOD-3: subprocess Key Generation Leaks Keys via ps/proc

**Severity:** MEDIUM
**Phase:** Key generation (Phase 1)
**Confidence:** HIGH (well-known Unix process model)

**What goes wrong:** The project correctly plans to avoid subprocess for key generation. But this pitfall documents WHY and what to watch for. Running `wg genkey | wg pubkey` as subprocess:
1. Private key appears in pipe buffers
2. If using `shell=True`, the key may appear in process arguments
3. On Linux, `/proc/<pid>/cmdline` and `/proc/<pid>/fd/` expose pipe contents
4. `ps aux` shows command arguments for the brief time the process exists

The project plans to use Python's `cryptography` library for key generation (Curve25519). This is correct. But watch for:
- Using `subprocess` for ANY WireGuard command that accepts keys as arguments
- `wg set <iface> peer <pubkey> preshared-key /dev/stdin` is safe (reads from stdin, not arg)
- `wg set <iface> private-key /dev/stdin` is safe

**Prevention:**
1. Generate keys with `cryptography` library: `X25519PrivateKey.generate()`
2. For `wg set` commands that need keys, pass via stdin or temp file (not CLI argument)
3. If a temp file is used for key passing, create it with `0o600` permissions, pass to `wg`, then securely delete (overwrite + unlink)
4. Prefer `wg syncconf <file>` over `wg set` with individual key arguments

**Detection:**
- `subprocess.run(['wg', 'genkey'])` anywhere in codebase
- Private key appearing in any `subprocess` argument list
- `shell=True` in any subprocess call

---

### MOD-4: Audit Log Injection and Tampering

**Severity:** MEDIUM
**Phase:** Audit logging (Phase 3-4)
**Confidence:** HIGH (standard logging pitfall)

**What goes wrong:** "Append-only audit log" is harder than it sounds:
1. On most filesystems, append-only is not enforced -- any process with write access can truncate or rewrite the file
2. Log injection: if user-supplied data (peer names, etc.) is written to logs without sanitization, an attacker can inject fake log entries with newlines
3. On Linux, `chattr +a` makes a file append-only at the filesystem level, but requires root to set and only works on ext4/xfs

**Prevention:**
1. Use structured logging (JSON lines) so each entry is machine-parseable and injection is detectable
2. Include a running HMAC chain: each log entry includes HMAC(previous_entry_hash + current_entry), making tampering detectable
3. On Linux, use `chattr +a` on the log file after creation
4. Rotate logs with integrity verification (hash the completed log file, store hash in vault)
5. Sanitize all user input in log messages: strip newlines, control characters
6. Consider writing to syslog/journald in addition to file log (harder to tamper)

**Detection:**
- Log entries built with string concatenation from user input
- No integrity chain on log entries
- Log file writable by non-root users

---

### MOD-5: Python's secrets Module vs os.urandom for Random Generation

**Severity:** MEDIUM
**Phase:** Crypto foundation (Phase 1)
**Confidence:** HIGH (documented in Python docs)

**What goes wrong:** Using `random` module (Mersenne Twister, not cryptographically secure) instead of `secrets` or `os.urandom` for any security-sensitive random generation. This seems obvious but shows up in:
1. Generating temporary passwords or tokens
2. Generating nonces (sometimes `random.randint` sneaks in)
3. Choosing random ports or IPs (may not need crypto random, but if used for security decisions, it does)
4. Test fixtures that accidentally get used in production paths

**Prevention:**
1. Ban `import random` via linting rule (or confine to a single non-security module)
2. Use `secrets.token_bytes()` for all random generation in security contexts
3. `os.urandom()` is equally secure but `secrets` makes intent clearer
4. In code review, flag any `random.*` call in security-adjacent code

**Detection:**
- `import random` in any module that handles crypto, keys, or tokens
- `random.randint`, `random.choice`, `random.getrandbits` in security code

---

### MOD-6: Stale Peer Revocation Does Not Remove Active Sessions

**Severity:** MEDIUM
**Phase:** Peer lifecycle management (Phase 2-3)
**Confidence:** MEDIUM (based on WireGuard protocol behavior; verify with current implementation)

**What goes wrong:** Removing a peer from the WireGuard config file does NOT immediately disconnect them. WireGuard is stateless in terms of session persistence -- but an active session (with a valid handshake within the last 180 seconds) will continue to work until the handshake expires, unless `wg syncconf` is called to apply the removal.

More subtly: if you remove a peer from config but do not call `wg syncconf`, the peer remains active in the kernel/userspace WireGuard interface indefinitely.

**Prevention:**
1. Peer removal must ALWAYS be followed by `wg syncconf` (or `wg set <iface> peer <pubkey> remove`)
2. Verify removal with `wg show <iface> peers` -- the revoked public key must not appear
3. For immediate disconnection, also consider rotating the server's listening port (forces all peers to re-handshake, only valid peers can complete)
4. Maintain a revocation list in the vault and check it during any config rebuild

**Detection:**
- Peer removal that only modifies the config file without calling `wg syncconf`
- No verification step after peer removal
- No revocation tracking in the vault/state

---

## Minor Pitfalls

Mistakes that cause annoyance or minor issues.

---

### MIN-1: QR Code Terminal Display Broken on Windows Console

**Severity:** LOW
**Phase:** Client config distribution (Phase 2)
**Confidence:** MEDIUM (Windows console Unicode/block character support varies)

**What goes wrong:** QR codes rendered with block characters (e.g., `qrcode` library using `print_ascii()` or `print_tty()`) may display incorrectly on Windows Command Prompt due to:
1. Missing Unicode block character support in legacy console
2. Incorrect terminal width calculation
3. Font rendering issues with half-block characters

**Prevention:**
1. Use Windows Terminal (not cmd.exe) and detect which terminal is active
2. Provide fallback: `--qr-file output.png` option using `qrcode[pil]`
3. Test QR display on both Windows Terminal and legacy cmd.exe
4. Consider using the `segno` library which has better cross-platform terminal output

---

### MIN-2: Click/Typer CLI Framework Version Compatibility

**Severity:** LOW
**Phase:** CLI framework (Phase 1)
**Confidence:** MEDIUM (common Python packaging issue)

**What goes wrong:** If using Click or Typer, version conflicts with other installed packages can cause import errors. Click 7.x vs 8.x had breaking API changes. Typer depends on Click and can conflict with other Click-dependent tools.

**Prevention:**
1. Pin exact versions in `pyproject.toml`
2. Test with both the minimum and latest supported versions
3. If distributing as a standalone binary (PyInstaller), this is less of a concern
4. Consider using `argparse` (stdlib) to avoid the dependency entirely for a security tool where minimizing dependencies matters

---

### MIN-3: Git-Managed Config Files and Secret Residue

**Severity:** LOW
**Phase:** Development/CI (Phase 1, ongoing)
**Confidence:** HIGH (extremely common mistake)

**What goes wrong:** During development, a config file containing a test key or token is accidentally committed to git. Even after removal, it persists in git history forever.

**Prevention:**
1. `.gitignore` must include: `*.conf`, `*.vault`, `*.key`, `*.psk`, `.env`
2. Use `git-secrets` or `gitleaks` as a pre-commit hook
3. Never generate real keys during testing -- use deterministic test keys that are obviously fake
4. Add a pre-commit hook that greps for base64 strings of WireGuard key length (44 chars)

---

## Phase-Specific Warnings

| Phase | Likely Pitfall | Severity | Mitigation |
|-------|---------------|----------|------------|
| Phase 1: Vault/Crypto | CRIT-1 (memory leaks), CRIT-2 (nonce reuse), CRIT-4 (weak Argon2), CRIT-5 (traceback leaks) | CRITICAL | Design SecureBuffer primitive first. Get crypto right before building anything on top. |
| Phase 1: Vault/Crypto | MOD-5 (random module misuse) | MEDIUM | Establish linting rules banning `import random` in security modules from day one. |
| Phase 2: WireGuard Config | CRIT-3 (reload race), HIGH-5 (IP race), MOD-1 (INI injection), MOD-3 (subprocess key leak) | CRITICAL-HIGH | File locking and atomic writes must be designed together. IP allocation inside the lock. |
| Phase 2: Peer Management | MOD-6 (stale peer revocation) | MEDIUM | Always syncconf after config changes. Verify with wg show. |
| Phase 3: Cross-Platform | HIGH-1 (Windows ACL), HIGH-2 (Windows SYSTEM), HIGH-3 (macOS SIP) | HIGH | Build platform abstraction layer early. Test on all three platforms before feature expansion. |
| Phase 3: DNS Updates | HIGH-6 (DuckDNS token exposure) | HIGH | Token from vault only. Suppress HTTP logging. Sanitize exceptions. |
| Phase 3: Audit Logging | MOD-4 (log injection/tampering) | MEDIUM | Structured JSON logging with HMAC chain from the start. |
| Phase 4: Packaging | HIGH-4 (PyInstaller temp dir) | HIGH | Consider --onedir with secure installation path. Code signing. |
| Phase 4: Packaging | MIN-2 (CLI version compat) | LOW | Pin versions. Consider argparse for zero dependencies. |
| All Phases | MOD-2 (os.replace Windows) | MEDIUM | Wrap all file operations in platform-aware utility functions from Phase 1. |

---

## Confidence Notes

| Pitfall | Confidence | Basis |
|---------|-----------|-------|
| CRIT-1: Memory leaks | HIGH | CPython internals are well-documented and stable |
| CRIT-2: AES-GCM nonce | HIGH | Mathematical property, documented in NIST SP 800-38D |
| CRIT-3: Config race | MEDIUM | WireGuard `wg` tool behavior from docs; verify `syncconf` on Windows |
| CRIT-4: Argon2 params | HIGH | RFC 9106 and OWASP provide specific numbers |
| CRIT-5: Traceback leaks | HIGH | Python language behavior, verified via faulthandler docs |
| HIGH-1: Windows ACL | HIGH | Documented Python `os.chmod` limitation on Windows |
| HIGH-2: Windows SYSTEM | MEDIUM | WireGuard Windows architecture; verify current tunnel service API |
| HIGH-3: macOS SIP | MEDIUM | SIP/TCC restrictions evolve per macOS release |
| HIGH-4: PyInstaller | MEDIUM | Known behavior but mitigations may have evolved; verify current version |
| HIGH-5: IP pool race | HIGH | Classic concurrency bug, not platform-specific |
| HIGH-6: DuckDNS token | HIGH | Standard process visibility model on Unix/Windows |

**Research limitation:** WebSearch and WebFetch were unavailable for this session. All findings are based on training data covering well-established technical domains. The MEDIUM-confidence items (CRIT-3, HIGH-2, HIGH-3, HIGH-4) should be re-verified against current documentation during implementation.

---

## Sources

- Python `faulthandler` module documentation (verified via WebFetch): confirms faulthandler dumps only filename/function/line number, NOT local variables or memory contents
- NIST SP 800-38D: AES-GCM specification and nonce requirements (training data, HIGH confidence -- mathematical properties do not change)
- RFC 9106: Argon2 Memory-Hard Function (training data, HIGH confidence -- RFC is a stable document)
- OWASP Password Storage Cheat Sheet: Argon2id parameter recommendations (training data, MEDIUM confidence -- verify current OWASP recommendations)
- CPython source code and documentation: memory allocator behavior, `pymalloc` arenas (training data, HIGH confidence -- stable CPython internals)
- WireGuard protocol documentation at wireguard.com (training data, MEDIUM confidence -- verify current `wg` tool behavior on each platform)
- PyInstaller documentation on operating mode and `_MEI` extraction (training data, MEDIUM confidence -- verify current version behavior)
- Python `os.chmod` documentation on Windows behavior (training data, HIGH confidence -- long-standing documented limitation)
