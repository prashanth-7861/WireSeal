"""WireSeal REST API server — stdlib only, no extra dependencies.

Run via ``wireseal serve`` (requires root/admin like all wireseal commands).
Listens on 127.0.0.1:8080 by default.

All routes except GET /api/vault-info require an unlocked vault.
Unlock by calling POST /api/unlock with the vault passphrase.

Endpoints
---------
GET  /api/vault-info              vault exists? locked?
POST /api/init                    first-time setup
POST /api/unlock                  load vault into memory
POST /api/lock                    wipe in-memory vault state
GET  /api/status                  wg show + vault clients
GET  /api/clients                 list clients
POST /api/clients                 add-client
DELETE /api/clients/<name>        remove-client
GET  /api/clients/<name>/qr       client QR as base64 PNG + raw config
GET  /api/audit-log               last 100 audit log entries
POST /api/change-passphrase       re-encrypt vault
POST /api/terminate               wg-quick down
POST /api/fresh-start             destroy vault + configs
POST /api/update-endpoint         update stored public IP
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Static frontend helpers
# ---------------------------------------------------------------------------

_MIME: dict[str, str] = {
    ".html":  "text/html; charset=utf-8",
    ".js":    "application/javascript",
    ".mjs":   "application/javascript",
    ".css":   "text/css",
    ".svg":   "image/svg+xml",
    ".png":   "image/png",
    ".jpg":   "image/jpeg",
    ".ico":   "image/x-icon",
    ".json":  "application/json",
    ".woff":  "font/woff",
    ".woff2": "font/woff2",
    ".ttf":   "font/ttf",
    ".txt":   "text/plain",
}


def _get_dist_dir() -> Path | None:
    """Locate the bundled React dashboard dist directory.

    Checks two locations in order:
    1. PyInstaller one-file bundle  → sys._MEIPASS / dashboard
    2. Development checkout         → <repo root> / Dashboard / dist
    """
    # PyInstaller sets _MEIPASS to the temp extraction directory
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        d = Path(meipass) / "dashboard"
        if d.is_dir():
            return d

    # Development: api.py lives at src/wireseal/api.py → go up 3 levels
    dev = Path(__file__).parent.parent.parent / "Dashboard" / "dist"
    if dev.is_dir():
        return dev

    return None

# Lazy TOTP import — kept here so handlers can reference after module load.
# The actual import happens inside handlers; this symbol is set at first use.
from wireseal.security.totp import (  # noqa: E402 — placed after stdlib imports
    generate_totp_secret,
    totp_uri,
    verify_totp,
    generate_backup_codes,
    hash_backup_code,
    verify_backup_code,
    secret_to_b32,
    b32_to_secret,
)

# ---------------------------------------------------------------------------
# Module-level session state
# ---------------------------------------------------------------------------

_lock = threading.RLock()

_session: dict = {
    "vault":      None,   # Vault instance (path + methods)
    "passphrase": None,   # SecretBytes kept in memory
    "cache":      None,   # Non-secret snapshot for fast reads
    "admin_id":   None,   # Admin ID of the currently authenticated user
    "admin_role": None,   # Role of the currently authenticated user
}

# Pending TOTP enrollment state keyed by admin_id.
# Populated by _h_totp_enroll_begin, consumed by _h_totp_enroll_confirm.
# Entries are {secret: bytes, used_codes: set[str]}.
_pending_totp: dict[str, dict] = {}


def _utcnow_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

_VAULT_DIR  = Path.home() / ".wireseal"
_VAULT_PATH = _VAULT_DIR / "vault.enc"
_AUDIT_PATH = _VAULT_DIR / "audit.log"
_PIN_PATH   = _VAULT_DIR / "pin.enc"
_WG_IFACE   = "wg0"

# PIN-based quick unlock — encrypts the passphrase with a PIN-derived key.
# After 5 wrong attempts the PIN file is wiped (must use full passphrase).
_PIN_MAX_ATTEMPTS = 5
_pin_fail_count   = 0

# ---------------------------------------------------------------------------
# Rate limiting for /api/unlock — prevents brute-force passphrase guessing.
# Tracks failed attempts per IP in a sliding window. After _UNLOCK_MAX
# failures within _UNLOCK_WINDOW seconds, returns 429 Too Many Requests.
# ---------------------------------------------------------------------------
_unlock_attempts: dict[str, list[float]] = {}  # ip -> list of failure timestamps
_UNLOCK_WINDOW = 300   # 5-minute sliding window
_UNLOCK_MAX    = 5     # max failures per window

# Rate-limit heartbeat resets: maps client_name → last_reset_timestamp
_heartbeat_cooldown: dict[str, float] = {}
_HEARTBEAT_MIN_INTERVAL = 30.0  # seconds between heartbeat resets per client

# Maps peer public_key → last_handshake_seconds from previous _h_status call.
# Used to detect new handshake events for the audit log (DASH-06).
_peer_handshake_cache: dict[str, int] = {}


def _check_rate_limit(ip: str) -> None:
    """Raise 429 if this IP has exceeded the unlock attempt limit."""
    import time as _time
    now = _time.time()
    with _lock:
        attempts = _unlock_attempts.get(ip, [])
        # Prune entries outside the window
        attempts = [t for t in attempts if now - t < _UNLOCK_WINDOW]
        _unlock_attempts[ip] = attempts
        if len(attempts) >= _UNLOCK_MAX:
            from wireseal.security.audit import AuditLog
            AuditLog(_AUDIT_PATH).log("unlock-ratelimited", {"ip": ip})
            raise _ApiError("Too many unlock attempts. Try again later.", 429)


def _record_unlock_failure(ip: str) -> None:
    """Record a failed unlock attempt for rate limiting."""
    import time as _time
    with _lock:
        _unlock_attempts.setdefault(ip, []).append(_time.time())
    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("unlock-failed", {"ip": ip})


def _clear_unlock_failures(ip: str) -> None:
    """Clear failed attempts after a successful unlock."""
    with _lock:
        _unlock_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# Admin mode — full system access via verified root/sudo credentials.
# Activated by POST /api/admin/authenticate with the root password.
# Expires after _ADMIN_TIMEOUT seconds or on vault lock / shutdown.
# ---------------------------------------------------------------------------

_admin_session: dict = {
    "active":     False,
    "password":   None,   # SecretBytes — cached sudo password
    "expires_at": None,   # monotonic clock timestamp
}
_ADMIN_TIMEOUT   = 1800  # 30 minutes
_ADMIN_MAX_FAILS = 3     # stricter limit than vault unlock
_admin_lock      = threading.Lock()
_admin_attempts: dict[str, list[float]] = {}


def _check_admin_rate_limit(ip: str) -> None:
    """Raise 429 if this IP has exceeded admin authentication attempts."""
    import time as _time
    now = _time.time()
    with _admin_lock:
        attempts = [t for t in _admin_attempts.get(ip, []) if now - t < _UNLOCK_WINDOW]
        _admin_attempts[ip] = attempts
        if len(attempts) >= _ADMIN_MAX_FAILS:
            from wireseal.security.audit import AuditLog
            AuditLog(_AUDIT_PATH).log("admin-auth-ratelimited", {"ip": ip})
            raise _ApiError("Too many admin authentication attempts. Try again later.", 429)


def _record_admin_failure(ip: str) -> None:
    import time as _time
    with _admin_lock:
        _admin_attempts.setdefault(ip, []).append(_time.time())


def _clear_admin_failures(ip: str) -> None:
    with _admin_lock:
        _admin_attempts.pop(ip, None)


def _verify_root_password(password: str) -> bool:
    """Return True if the given password is the valid sudo/root password."""
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    if os.geteuid() == 0:
        return True  # Already root — no password needed
    try:
        result = subprocess.run(
            ["sudo", "-k", "-S", "true"],   # -k forces re-auth, -S reads password from stdin
            input=(password + "\n").encode("utf-8"),
            capture_output=True,
            timeout=10,
            creationflags=_SP_FLAGS,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _require_admin_active() -> None:
    """Raise 403 if admin mode is not active or has expired."""
    import time as _time
    with _admin_lock:
        active  = _admin_session["active"]
        expires = _admin_session["expires_at"]
    if not active:
        raise _ApiError("Admin mode not active. POST /api/admin/authenticate first.", 403)
    if expires is not None and _time.monotonic() > expires:
        _admin_deactivate()
        raise _ApiError("Admin session expired. Re-authenticate.", 403)


def _admin_deactivate() -> None:
    """Wipe admin session credentials from memory."""
    with _admin_lock:
        if _admin_session["password"] is not None:
            try:
                _admin_session["password"].wipe()
            except Exception:
                pass
        _admin_session.update(active=False, password=None, expires_at=None)


def _admin_run(
    cmd: list[str],
    stdin_extra: bytes = b"",
    timeout: int = 30,
) -> "subprocess.CompletedProcess[bytes]":
    """Execute a command with root credentials (admin mode required).

    When not already root, prepends ``sudo -S`` and pipes the cached password
    as the first stdin line, followed by any stdin bytes for the child process.
    """
    import time as _time
    with _admin_lock:
        active   = _admin_session["active"]
        expires  = _admin_session["expires_at"]
        password = _admin_session["password"]

    if not active:
        raise _ApiError("Admin mode not active.", 403)
    if expires is not None and _time.monotonic() > expires:
        _admin_deactivate()
        raise _ApiError("Admin session expired.", 403)

    already_root = sys.platform == "win32" or os.geteuid() == 0
    if already_root:
        full_cmd: list[str] = cmd
        stdin_bytes: bytes | None = stdin_extra or None
    else:
        full_cmd = ["sudo", "-S"] + cmd
        pw_bytes = password.expose_secret() + b"\n"
        stdin_bytes = pw_bytes + stdin_extra if stdin_extra else pw_bytes

    return subprocess.run(
        full_cmd,
        input=stdin_bytes,
        capture_output=True,
        timeout=timeout,
        creationflags=_SP_FLAGS,
    )


# On Windows, prevent subprocess calls from flashing a visible console window.
# CREATE_NO_WINDOW (0x08000000) suppresses the console for child processes.
_SP_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _ApiError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def _sudo(cmd: list[str]) -> list[str]:
    """Prepend 'sudo' to a command when not running as root on Linux/macOS.

    This allows the GUI to run as the regular user (so it can access the
    display) while elevating only for WireGuard / network commands.
    """
    if sys.platform == "win32":
        return cmd
    if os.geteuid() == 0:
        return cmd
    return ["sudo", "-n"] + cmd  # -n = non-interactive (no password prompt)


def _require_unlocked() -> None:
    global _last_activity
    if _session["vault"] is None:
        raise _ApiError("Vault is locked. POST /api/unlock first.", 401)
    import time as _time
    _last_activity = _time.monotonic()


# ---------------------------------------------------------------------------
# PIN helpers — encrypt/decrypt passphrase with a short PIN
# ---------------------------------------------------------------------------

def _pin_derive_key(pin: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a PIN using PBKDF2-HMAC-SHA256.

    PBKDF2 is intentional here (not Argon2): the PIN file is wiped after 5
    wrong attempts, so sustained brute-force is not possible. PBKDF2 keeps
    the PIN unlock fast (~50ms vs ~3s for Argon2).
    """
    import hashlib
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, iterations=600_000, dklen=32)


def _pin_save(passphrase_bytes: bytes, pin: str) -> None:
    """Encrypt the passphrase with the PIN and save to pin.enc."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _pin_derive_key(pin, salt)
    ct = AESGCM(key).encrypt(nonce, passphrase_bytes, salt)
    # Format: salt(16) + nonce(12) + ciphertext(variable)
    _VAULT_DIR.mkdir(parents=True, exist_ok=True)
    _PIN_PATH.write_bytes(salt + nonce + ct)
    try:
        if sys.platform != "win32":
            os.chmod(_PIN_PATH, 0o600)
    except OSError:
        pass


def _pin_load(pin: str) -> bytes | None:
    """Decrypt the passphrase from pin.enc. Returns None on failure."""
    if not _PIN_PATH.exists():
        return None
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    data = _PIN_PATH.read_bytes()
    if len(data) < 29:  # 16 salt + 12 nonce + 1 min ciphertext
        return None
    salt, nonce, ct = data[:16], data[16:28], data[28:]
    key = _pin_derive_key(pin, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, salt)
    except InvalidTag:
        return None


def _pin_wipe() -> None:
    """Delete the PIN file."""
    try:
        _PIN_PATH.unlink(missing_ok=True)
    except OSError:
        pass



def _refresh_cache(state: Any) -> dict:
    """Build a non-secret snapshot from an open VaultState."""
    return {
        "server": {
            "ip":       state.server.get("ip", ""),
            "subnet":   state.server.get("subnet",
                            state.ip_pool.get("subnet", "")),
            "port":     state.server.get("port", 51820),
            "endpoint": state.server.get("endpoint", ""),
            "duckdns":  state.server.get("duckdns_domain", ""),
        },
        "clients": {
            name: {
                "ip":             data["ip"],
                "permanent":      data.get("permanent", True),
                "ttl_seconds":    data.get("ttl_seconds"),
                "ttl_expires_at": data.get("ttl_expires_at"),
            }
            for name, data in state.clients.items()
        },
        "ip_pool": dict(state.ip_pool),
        "admins": dict(state.data.get("admins", {})),
        "dns_mappings": dict(state.data.get("dns_mappings", {})),
    }


def _refresh_cache_unlocked(vault: Any, passphrase: Any, admin_id: str = "owner") -> None:
    """Open vault and refresh in-memory cache. Called after writes that happen
    outside the context manager pattern (heartbeat, set-ttl, expiry watcher).
    """
    try:
        with vault.open(passphrase, admin_id=admin_id) as state:
            with _lock:
                _session["cache"] = _refresh_cache(state)
    except Exception:
        pass


def _extract(value: Any) -> str:
    """Return plain str from either str or SecretBytes."""
    from wireseal.security.secret_types import SecretBytes
    if isinstance(value, SecretBytes):
        return value.expose_secret().decode("utf-8")
    return str(value)


def _detect_mtu() -> int:
    """Detect optimal WireGuard client MTU based on outbound interface MTU.

    WireGuard adds 80 bytes overhead (60 IPv4/IPv6 + 20 WireGuard header).
    We subtract that from the outbound interface MTU to get the optimal client MTU.
    Falls back to 1420 if detection fails.
    """
    try:
        if sys.platform == "win32":
            import subprocess as _sp
            result = _sp.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                capture_output=True, text=True, timeout=10,
            )
            # Find the highest MTU from connected interfaces (skip loopback)
            import re as _re
            mtus = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0].isdigit() and parts[1].isdigit():
                    mtu_val = int(parts[1])
                    if 500 < mtu_val <= 9000:  # reasonable range
                        mtus.append(mtu_val)
            if mtus:
                return max(mtus) - 80
        else:
            import subprocess as _sp
            # Use ip route to find the outbound interface, then get its MTU
            result = _sp.run(
                ["ip", "route", "get", "8.8.8.8"],
                capture_output=True, text=True, timeout=10,
            )
            import re as _re
            iface_match = _re.search(r"\bdev\s+(\S+)", result.stdout)
            if iface_match:
                iface = iface_match.group(1)
                mtu_result = _sp.run(
                    ["cat", f"/sys/class/net/{iface}/mtu"],
                    capture_output=True, text=True, timeout=5,
                )
                if mtu_result.returncode == 0:
                    return int(mtu_result.stdout.strip()) - 80
    except Exception:
        pass
    return 1420  # safe default


def _resolve_client_endpoint(server_state: dict) -> str:
    """Return the endpoint string clients use to reach the server."""
    port = server_state["port"]
    duckdns_domain = server_state.get("duckdns_domain")
    if duckdns_domain:
        return f"{duckdns_domain}.duckdns.org:{port}"
    stored_endpoint = server_state.get("endpoint")
    if stored_endpoint:
        return f"{stored_endpoint}:{port}"
    return f"{server_state['ip']}:{port}"


def _reload_wireguard(interface: str = "wg0") -> str:
    """Reload WireGuard interface. Returns empty string on success, error message on failure.

    Strategy:
      1. Try wg syncconf (hot-reload, no disconnect)
      2. If syncconf fails, fall back to wg-quick down/up (brief disconnect)
      3. If both fail, return the error message
    """
    if sys.platform == "win32":
        _no_win = subprocess.CREATE_NO_WINDOW
        svc = f"WireGuardTunnel${interface}"
        subprocess.run(
            ["sc.exe", "stop", svc],
            check=False, capture_output=True, timeout=10, creationflags=_no_win,
        )
        from wireseal.platform.detect import get_adapter as _get_adapter
        _adapter = _get_adapter()
        config_path = _adapter.get_config_path(interface)
        wg_exe = Path(r"C:\Program Files\WireGuard\wireguard.exe")
        if config_path.exists() and wg_exe.exists():
            subprocess.run(
                [str(wg_exe), "/uninstalltunnelservice", interface],
                check=False, capture_output=True, timeout=10, creationflags=_no_win,
            )
            subprocess.run(
                [str(wg_exe), "/installtunnelservice", str(config_path)],
                check=False, capture_output=True, timeout=10, creationflags=_no_win,
            )
        else:
            subprocess.run(
                ["sc.exe", "start", svc],
                check=False, capture_output=True, timeout=10, creationflags=_no_win,
            )
        return ""

    import tempfile
    from wireseal.platform.detect import get_adapter
    adapter = get_adapter()
    config_path = adapter.get_config_path(interface)

    # Check if interface is up
    check = subprocess.run(
        _sudo(["ip", "link", "show", interface]),
        capture_output=True, timeout=5,
    )
    if check.returncode != 0:
        # Interface not up — bring it up
        result = subprocess.run(
            _sudo(["wg-quick", "up", interface]),
            shell=False, check=False, capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            err = result.stderr.decode("utf-8", errors="replace")
            print(f"[wireseal] wg-quick up failed: {err}", file=sys.stderr)
            return f"wg-quick up failed: {err}"
        return ""

    # Interface is up — try syncconf (hot reload, no disconnect)
    sync_err = ""
    try:
        strip_result = subprocess.run(
            _sudo(["wg-quick", "strip", str(config_path)]),
            shell=False, check=True, capture_output=True, timeout=10,
        )
        with tempfile.NamedTemporaryFile(
            suffix=".conf", mode="wb", delete=False
        ) as tmp:
            tmp.write(strip_result.stdout)
            tmp_path = tmp.name
        try:
            os.chmod(tmp_path, 0o600)
            result = subprocess.run(
                _sudo(["wg", "syncconf", interface, tmp_path]),
                shell=False, check=False, capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                return ""  # Success
            sync_err = result.stderr.decode("utf-8", errors="replace")
            print(f"[wireseal] wg syncconf failed: {sync_err}", file=sys.stderr)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    except Exception as exc:
        sync_err = str(exc)
        print(f"[wireseal] wg syncconf exception: {exc}", file=sys.stderr)

    # Fallback: full restart (brief disconnect but guarantees config is loaded)
    print("[wireseal] Falling back to wg-quick down/up...", file=sys.stderr)
    subprocess.run(
        _sudo(["wg-quick", "down", interface]),
        shell=False, check=False, capture_output=True, timeout=15,
    )
    result = subprocess.run(
        _sudo(["wg-quick", "up", interface]),
        shell=False, check=False, capture_output=True, timeout=30,
    )
    if result.returncode == 0:
        return ""  # Fallback succeeded
    err = result.stderr.decode("utf-8", errors="replace")
    print(f"[wireseal] wg-quick up fallback failed: {err}", file=sys.stderr)
    return f"WireGuard reload failed: {sync_err}; fallback: {err}"


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


_server_start_time: float = 0.0
_last_activity: float = 0.0
_SESSION_TIMEOUT = 900  # 15 minutes of inactivity triggers auto-lock


def _h_health(req: "_Handler", _groups: tuple) -> dict:
    """Lightweight health endpoint for monitoring — no auth, no subprocess."""
    import time
    uptime = int(time.monotonic() - _server_start_time) if _server_start_time else 0
    return {
        "status": "ok",
        "vault_initialized": _VAULT_PATH.exists(),
        "vault_locked": _session["vault"] is None,
        "uptime_seconds": uptime,
    }


def _h_vault_info(req: "_Handler", _groups: tuple) -> dict:
    locked = _session["vault"] is None
    multi_admin: bool = False
    totp_required_for: list = []
    if not locked and _session["cache"]:
        admins_data = _session["cache"].get("admins", {})
        multi_admin = len(admins_data) > 1
        totp_required_for = [
            aid for aid, info in admins_data.items()
            if info.get("totp_secret_b32") is not None
        ]
    return {
        "initialized":      _VAULT_PATH.exists(),
        "locked":           locked,
        "interface":        _WG_IFACE,
        "pin_set":          _PIN_PATH.exists(),
        "multi_admin":      multi_admin,
        "totp_required_for": totp_required_for,
    }


def _h_init(req: "_Handler", _groups: tuple) -> dict:
    if _VAULT_PATH.exists():
        raise _ApiError("Vault already exists. Use /api/unlock.", 409)

    body           = req._json()
    passphrase_str = body.get("passphrase", "")
    if len(passphrase_str) < 12:
        raise _ApiError("Passphrase must be at least 12 characters.", 400)

    subnet   = body.get("subnet", "10.0.0.0/24")
    port     = int(body.get("port", 51820))
    endpoint = body.get("endpoint") or None

    from wireseal.security.secret_types  import SecretBytes
    from wireseal.security.secrets_wipe  import wipe_string
    from wireseal.security.vault         import Vault
    from wireseal.security.audit         import AuditLog
    from wireseal.core.keygen            import generate_keypair
    from wireseal.core.ip_pool           import IPPool
    from wireseal.core.config_builder    import ConfigBuilder

    passphrase = SecretBytes(bytearray(passphrase_str.encode()))
    try:
        if endpoint is None:
            try:
                from wireseal.dns.ip_resolver import resolve_public_ip
                endpoint = str(resolve_public_ip())
            except Exception:
                endpoint = None

        priv_key, pub_key_bytes = generate_keypair()
        pub_key_str  = pub_key_bytes.decode("ascii")
        priv_key_str = priv_key.expose_secret().decode("ascii")

        pool      = IPPool(subnet)
        server_ip = pool.server_ip

        initial_state = {
            "schema_version": 1,
            "server": {
                "private_key": priv_key_str,
                "public_key":  pub_key_str,
                "ip":          server_ip,
                "subnet":      pool.subnet_str,
                "port":        port,
                "endpoint":    endpoint,
            },
            "clients":  {},
            "ip_pool":  {"subnet": pool.subnet_str,
                         "allocated": pool.get_allocated()},
            "integrity": {},
        }

        # ── Step 1: Create the encrypted vault (always succeeds or fails fast) ──
        vault = Vault.create(_VAULT_PATH, passphrase, initial_state)

        # Build cache directly from initial_state instead of re-opening the
        # vault (which would run Argon2id KDF again, adding ~5s of latency).
        cache = {
            "server": {
                "ip":       server_ip,
                "subnet":   pool.subnet_str,
                "port":     port,
                "endpoint": endpoint or "",
                "duckdns":  "",
            },
            "clients": {},
            "ip_pool": dict(initial_state["ip_pool"]),
        }
        with _lock:
            _session.update(vault=vault, passphrase=passphrase, cache=cache)
        passphrase = None  # ownership transferred to session

        AuditLog(_AUDIT_PATH).log("init", {"subnet": subnet, "port": port})

        # ── Step 2: Platform setup (best-effort — failures are warnings) ────────
        # These operations require admin privileges and WireGuard to be installed.
        # If they fail, the vault is still created and the dashboard works.
        warnings_list: list[str] = []

        try:
            from wireseal.platform.detect import get_adapter
            adapter = get_adapter()
            adapter.check_privileges()
        except Exception as exc:
            warnings_list.append("Not running as admin — platform setup skipped.")
            # Cannot proceed with platform setup without admin
            return {
                "ok":         True,
                "server_ip":  server_ip,
                "subnet":     pool.subnet_str,
                "public_key": pub_key_str,
                "endpoint":   endpoint,
                "warnings":   warnings_list,
            }

        try:
            config = ConfigBuilder().render_server_config(
                server_private_key=priv_key_str,
                server_ip=server_ip,
                prefix_length=int(pool.subnet_str.split("/")[1]),
                server_port=port,
                clients=[],
            )
            adapter.deploy_config(config)
        except Exception as exc:
            warnings_list.append("Config deploy failed.")

        try:
            adapter.install_wireguard()
        except Exception as exc:
            warnings_list.append("WireGuard install skipped.")

        try:
            adapter.apply_firewall_rules(port, _WG_IFACE, pool.subnet_str)
        except Exception as exc:
            warnings_list.append("Firewall rules skipped.")

        # Open port in firewalld and ensure SSH is running (Linux only)
        if hasattr(adapter, "open_firewalld_port"):
            try:
                adapter.open_firewalld_port(port)
            except Exception:
                warnings_list.append("firewalld port open skipped.")
        if hasattr(adapter, "ensure_sshd"):
            try:
                adapter.ensure_sshd()
            except Exception:
                warnings_list.append("SSH server setup skipped.")
        # Server hardening (SSH, kernel, fail2ban, auto-updates)
        if hasattr(adapter, "harden_server"):
            try:
                adapter.harden_server()
            except Exception:
                warnings_list.append("Server hardening skipped.")

        try:
            adapter.enable_tunnel_service(_WG_IFACE)
        except Exception as exc:
            warnings_list.append("Tunnel service failed.")

        return {
            "ok":         True,
            "server_ip":  server_ip,
            "subnet":     pool.subnet_str,
            "public_key": pub_key_str,
            "endpoint":   endpoint,
            "warnings":   warnings_list if warnings_list else None,
        }
    except _ApiError:
        raise
    except Exception as exc:
        if passphrase is not None:
            passphrase.wipe()
        raise _ApiError("Server initialization failed.", 500)
    finally:
        wipe_string(passphrase_str)


def _h_unlock(req: "_Handler", _groups: tuple) -> dict:
    client_ip = req.client_address[0]
    _check_rate_limit(client_ip)

    body           = req._json()
    passphrase_str = body.get("passphrase", "")
    admin_id       = body.get("admin_id", "owner")
    if not passphrase_str:
        raise _ApiError("passphrase is required", 400)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string
    from wireseal.security.vault        import Vault
    from wireseal.security.audit        import AuditLog

    totp_code = body.get("totp_code")  # optional — required only when enrolled

    passphrase = SecretBytes(bytearray(passphrase_str.encode()))
    try:
        vault = Vault(_VAULT_PATH)
        try:
            with vault.open(passphrase, admin_id=admin_id) as st:
                # Update last_unlock for this admin
                admins_dict = st.data.setdefault("admins", {})
                if admin_id in admins_dict:
                    admins_dict[admin_id]["last_unlock"] = _utcnow_iso()
                admin_role = admins_dict.get(admin_id, {}).get("role", "owner")

                # TOTP enforcement: if admin has enrolled TOTP, require a valid code.
                totp_b32 = admins_dict.get(admin_id, {}).get("totp_secret_b32")
                if totp_b32 is not None:
                    if not totp_code:
                        raise _ApiError("totp_code required", 401)
                    totp_secret = b32_to_secret(totp_b32)
                    if not verify_totp(totp_secret, str(totp_code)):
                        raise _ApiError("invalid_totp", 401)

                cache = _refresh_cache(st)
        except _ApiError:
            passphrase.wipe()
            _record_unlock_failure(client_ip)
            raise
        except Exception as exc:
            passphrase.wipe()
            _record_unlock_failure(client_ip)
            raise _ApiError("Incorrect passphrase.", 401)

        with _lock:
            if _session["passphrase"]:
                _session["passphrase"].wipe()
            _session.update(
                vault=vault, passphrase=passphrase, cache=cache,
                admin_id=admin_id, admin_role=admin_role,
            )

        _clear_unlock_failures(client_ip)
        AuditLog(_AUDIT_PATH).log("unlock-web", {"admin_id": admin_id})

        # Auto-start WireGuard tunnel if config exists but tunnel is down
        try:
            wg_check = subprocess.run(
                _sudo(["wg", "show", _WG_IFACE]),
                capture_output=True, timeout=5,
                creationflags=_SP_FLAGS,
            )
            if wg_check.returncode != 0:
                # Tunnel not running — try to bring it up
                conf_path = Path("/etc/wireguard") / f"{_WG_IFACE}.conf"
                if sys.platform == "win32":
                    conf_path = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "WireGuard" / f"{_WG_IFACE}.conf"
                if conf_path.exists():
                    subprocess.run(
                        _sudo(["wg-quick", "up", _WG_IFACE]),
                        capture_output=True, timeout=15,
                        creationflags=_SP_FLAGS,
                    )
        except Exception:
            pass  # Best-effort — don't block unlock

        return {"ok": True, "role": admin_role}
    finally:
        wipe_string(passphrase_str)


def _h_lock(req: "_Handler", _groups: tuple) -> dict:
    from wireseal.security.audit import AuditLog
    _admin_deactivate()  # admin mode is tied to the authenticated session
    with _lock:
        if _session["passphrase"]:
            _session["passphrase"].wipe()
        _session.update(vault=None, passphrase=None, cache=None,
                        admin_id=None, admin_role=None)
    AuditLog(_AUDIT_PATH).log("lock", {})
    return {"ok": True}


def _detect_new_handshakes(peers: list[dict]) -> None:
    """Compare current handshake times against the module-level cache.

    For each peer that has crossed from disconnected (last_handshake_seconds
    >= 180 or absent from cache) to connected (last_handshake_seconds < 180),
    write a 'peer-connected' entry to the audit log and update the cache.

    Intentionally swallows all exceptions: a failing audit write must never
    crash the status endpoint.
    """
    global _peer_handshake_cache
    try:
        from wireseal.security.audit import AuditLog
        audit = AuditLog(_AUDIT_PATH)
        new_cache: dict[str, int] = {}
        for p in peers:
            key = p.get("public_key", p.get("public_key_short", ""))
            secs = p.get("last_handshake_seconds", -1)
            new_cache[key] = secs
            prev = _peer_handshake_cache.get(key)
            # Fire event: was disconnected (or unseen), now connected
            was_disconnected = (prev is None) or (prev < 0) or (prev >= 180)
            now_connected = 0 <= secs < 180
            if was_disconnected and now_connected:
                try:
                    audit.log(
                        "peer-connected",
                        {
                            "name": p.get("name", "unknown"),
                            "peer": p.get("public_key_short", ""),
                            "last_handshake_seconds": secs,
                        },
                    )
                except Exception:
                    pass  # Audit failures never crash the status endpoint
        _peer_handshake_cache = new_cache
    except Exception:
        pass  # Never crash _h_status due to audit/cache logic


def _h_status(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    with _lock:
        cache = _session["cache"] or {}

    running = False
    peers: list[dict] = []
    try:
        result = subprocess.run(
            _sudo(["wg", "show", _WG_IFACE]), capture_output=True, text=True, timeout=5,
            creationflags=_SP_FLAGS,
        )
        # wg show <iface> returns 0 only if the interface exists and is active.
        # wg show (no args) returns 0 even with no interfaces.
        if result.returncode == 0 and result.stdout.strip():
            running = True
            peers = _parse_wg_show(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Windows fallback: wg CLI may not be in PATH; check service status instead
    if not running and sys.platform == "win32":
        try:
            sc_result = subprocess.run(
                ["sc.exe", "query", f"WireGuardTunnel${_WG_IFACE}"],
                capture_output=True, text=True, timeout=5,
                creationflags=_SP_FLAGS,
            )
            if sc_result.returncode == 0 and "RUNNING" in sc_result.stdout:
                running = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    ip_to_name = {
        data["ip"].split("/")[0]: name
        for name, data in cache.get("clients", {}).items()
    }
    for p in peers:
        ip = p.get("allowed_ips", "").split("/")[0]
        p["name"] = ip_to_name.get(ip, "unknown")

    # DASH-06: Detect new handshake events by comparing against previous poll.
    _detect_new_handshakes(peers)

    return {
        "running":       running,
        "interface":     _WG_IFACE,
        "server_ip":     cache.get("server", {}).get("ip", ""),
        "endpoint":      cache.get("server", {}).get("endpoint", ""),
        "port":          cache.get("server", {}).get("port", 51820),
        "peers":         peers,
        "total_clients": len(cache.get("clients", {})),
    }


def _parse_handshake_to_seconds(hs: str) -> int:
    """Convert a WireGuard handshake age string to total seconds.

    Handles the full range of wg show output:
      "Never"                        → -1
      "30 seconds ago"               → 30
      "2 minutes, 30 seconds ago"    → 150
      "1 hour, 5 minutes ago"        → 3900
      "1 day, 3 hours ago"           → 97200

    Returns -1 for "Never" or any unparseable value.
    """
    if not hs or hs.strip().lower() in ("never", ""):
        return -1
    total = 0
    # Strip trailing "ago" and commas, then tokenise "N unit" pairs
    cleaned = re.sub(r"\bago\b", "", hs, flags=re.IGNORECASE).replace(",", " ")
    tokens = cleaned.split()
    i = 0
    matched_any = False
    while i < len(tokens) - 1:
        try:
            val = int(tokens[i])
        except ValueError:
            i += 1
            continue
        unit = tokens[i + 1].lower().rstrip("s")  # "minutes" → "minute"
        if unit == "second":
            total += val
            matched_any = True
        elif unit == "minute":
            total += val * 60
            matched_any = True
        elif unit == "hour":
            total += val * 3600
            matched_any = True
        elif unit == "day":
            total += val * 86400
            matched_any = True
        elif unit == "week":
            total += val * 604800
            matched_any = True
        i += 2
    return total if matched_any else -1


def _format_transfer_bytes(raw: str) -> str:
    """Parse a WireGuard transfer string like '1.23 MiB' and re-format
    to decimal units (B, KB, MB, GB) for consistent display.

    WireGuard uses IEC (KiB=1024, MiB=1024²) in wg show output.
    We convert to SI (KB=1000, MB=1000², GB=1000³) for display.
    Returns '0 B' on parse failure.
    """
    raw = raw.strip()
    m = re.match(r"^([\d.]+)\s*([KMGT]?i?B)$", raw, re.IGNORECASE)
    if not m:
        return raw if raw else "0 B"
    try:
        value = float(m.group(1))
    except ValueError:
        return "0 B"
    unit = m.group(2).upper()
    multipliers = {
        "B": 1,
        "KIB": 1024, "KB": 1000,
        "MIB": 1024 ** 2, "MB": 1000 ** 2,
        "GIB": 1024 ** 3, "GB": 1000 ** 3,
        "TIB": 1024 ** 4, "TB": 1000 ** 4,
    }
    byte_val = value * multipliers.get(unit, 1)
    if byte_val < 1000:
        return f"{byte_val:.0f} B"
    elif byte_val < 1_000_000:
        return f"{byte_val / 1000:.2f} KB"
    elif byte_val < 1_000_000_000:
        return f"{byte_val / 1_000_000:.2f} MB"
    else:
        return f"{byte_val / 1_000_000_000:.2f} GB"


def _parse_wg_show(output: str) -> list[dict]:
    peers: list[dict] = []
    cur: dict | None = None
    for line in output.strip().splitlines():
        s = line.strip()
        if s.startswith("peer:"):
            if cur:
                peers.append(cur)
            cur = {
                "public_key":             s.split(":", 1)[1].strip(),
                "public_key_short":       s.split(":", 1)[1].strip()[:12] + "...",
                "allowed_ips":            "",
                "last_handshake":         "never",
                "last_handshake_seconds": -1,
                "transfer_rx":            "0 B",
                "transfer_tx":            "0 B",
                "connected":              False,
            }
        elif cur:
            if s.startswith("allowed ips:"):
                cur["allowed_ips"] = s.split(":", 1)[1].strip()
            elif s.startswith("latest handshake:"):
                hs = s.split(":", 1)[1].strip()
                cur["last_handshake"] = hs
                secs = _parse_handshake_to_seconds(hs)
                cur["last_handshake_seconds"] = secs
                cur["connected"] = 0 <= secs < 180
            elif s.startswith("transfer:"):
                parts = s.split(":", 1)[1].strip().split(",")
                if len(parts) == 2:
                    cur["transfer_rx"] = _format_transfer_bytes(
                        parts[0].replace("received", "").strip()
                    )
                    cur["transfer_tx"] = _format_transfer_bytes(
                        parts[1].replace("sent", "").strip()
                    )
    if cur:
        peers.append(cur)
    return peers


def _h_heartbeat(req: "_Handler", groups: tuple) -> dict:
    """Reset TTL for a client. Rate-limited to 1 reset per 30s per client.

    No vault unlock required — clients call this directly.
    """
    import time as _time
    name = groups[0]

    # Rate limiting
    now = _time.time()
    last = _heartbeat_cooldown.get(name, 0)
    if now - last < _HEARTBEAT_MIN_INTERVAL:
        raise _ApiError("Heartbeat rate limit exceeded.", 429)

    with _lock:
        cache      = _session.get("cache") or {}
        vault      = _session.get("vault")
        passphrase = _session.get("passphrase")
        admin_id   = _session.get("admin_id", "owner")

    if vault is None:
        raise _ApiError("Server vault is locked.", 503)

    client = cache.get("clients", {}).get(name)
    if not client:
        raise _ApiError("Client not found.", 404)

    if client.get("permanent", True):
        return {"ok": True, "permanent": True}

    ttl_seconds = client.get("ttl_seconds") or 86400
    new_expires = now + ttl_seconds
    _heartbeat_cooldown[name] = now

    # Update vault
    with vault.open(passphrase, admin_id=admin_id) as state:
        if name in state.clients:
            state.clients[name]["ttl_expires_at"] = new_expires
        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, admin_id)

    from wireseal.security.audit import AuditLog
    try:
        AuditLog(_AUDIT_PATH).log("heartbeat", {"name": name, "expires_at": new_expires})
    except Exception:
        pass

    return {"ok": True, "expires_at": new_expires}


def _h_set_client_ttl(req: "_Handler", groups: tuple) -> dict:
    """Set or clear TTL for an existing client. Requires unlocked vault."""
    _require_unlocked()
    name = groups[0]
    body = req._json()
    permanent   = body.get("permanent", False)
    ttl_seconds = body.get("ttl_seconds")

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        admin_id   = _session.get("admin_id", "owner")
        cache      = _session.get("cache") or {}

    if name not in cache.get("clients", {}):
        raise _ApiError("Client not found.", 404)

    import time as _time
    with vault.open(passphrase, admin_id=admin_id) as state:
        if name not in state.clients:
            raise _ApiError("Client not found.", 404)
        client = state.clients[name]
        if permanent or ttl_seconds == 0:
            client["permanent"]      = True
            client["ttl_seconds"]    = None
            client["ttl_expires_at"] = None
            result = {"ok": True, "permanent": True}
        else:
            client["permanent"]      = False
            client["ttl_seconds"]    = int(ttl_seconds)
            client["ttl_expires_at"] = _time.time() + int(ttl_seconds)
            result = {"ok": True, "expires_at": client["ttl_expires_at"]}
        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, admin_id)
    return result


def _h_list_clients(req: "_Handler", _groups: tuple) -> list:
    _require_unlocked()
    import time as _time
    with _lock:
        cache = _session["cache"] or {}
    now = _time.time()
    return [
        {
            "name":             n,
            "ip":               d["ip"],
            "permanent":        d.get("permanent", True),
            "ttl_seconds":      d.get("ttl_seconds"),
            "ttl_expires_at":   d.get("ttl_expires_at"),
            "expires_in_seconds": (
                max(0, int(d["ttl_expires_at"] - now))
                if not d.get("permanent", True) and d.get("ttl_expires_at")
                else None
            ),
        }
        for n, d in cache.get("clients", {}).items()
    ]


def _h_add_client(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    name = body.get("name", "").strip()
    if not name:
        raise _ApiError("name is required", 400)
    if not re.fullmatch(r"^[a-zA-Z0-9-]{1,32}$", name):
        raise _ApiError(
            "Name must be alphanumeric + hyphens only, max 32 chars", 400
        )

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.core.keygen         import generate_keypair
    from wireseal.core.psk            import generate_psk
    from wireseal.core.ip_pool        import IPPool
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.atomic     import atomic_write
    from wireseal.security.audit      import AuditLog
    from wireseal.platform.detect     import get_adapter

    allocated_ip = ""
    with vault.open(passphrase) as state:
        if name in state.clients:
            raise _ApiError(f"Client '{name}' already exists.", 409)

        priv_key, pub_key_bytes = generate_keypair()
        pub_key_str  = pub_key_bytes.decode("ascii")
        priv_key_str = priv_key.expose_secret().decode("ascii")

        psk     = generate_psk()
        psk_str = psk.expose_secret().decode("ascii")

        pool = IPPool(state.ip_pool["subnet"])
        pool.load_state(state.ip_pool.get("allocated", {}))
        allocated_ip = pool.allocate(name)

        server_endpoint = _resolve_client_endpoint(state.server)
        server_ip       = state.server["ip"]
        server_pub_key  = _extract(state.server["public_key"])

        builder       = ConfigBuilder()
        client_config = builder.render_client_config(
            client_private_key=priv_key_str,
            client_ip=allocated_ip,
            dns_server="1.1.1.1, 8.8.8.8",
            server_public_key=server_pub_key,
            psk=psk_str,
            server_endpoint=server_endpoint,
            mtu=_detect_mtu(),
        )

        clients_dir     = _VAULT_DIR / "clients"
        clients_dir.mkdir(parents=True, exist_ok=True)
        client_conf_path = clients_dir / f"{name}.conf"
        atomic_write(client_conf_path, client_config.encode(), mode=0o600)

        config_hash = hashlib.sha256(client_config.encode()).hexdigest()

        peers = [
            {
                "name":       n,
                "public_key": _extract(d["public_key"]),
                "psk":        _extract(d["psk"]),
                "ip":         d["ip"],
            }
            for n, d in state.clients.items()
        ]
        peers.append({
            "name":       name,
            "public_key": pub_key_str,
            "psk":        psk_str,
            "ip":         allocated_ip,
        })

        server_config = builder.render_server_config(
            server_private_key=_extract(state.server["private_key"]),
            server_ip=server_ip,
            prefix_length=int(state.ip_pool["subnet"].split("/")[1]),
            server_port=state.server["port"],
            clients=peers,
        )
        wg_warning = ""
        try:
            adapter = get_adapter()
            adapter.check_privileges()
            adapter.deploy_config(server_config)
            wg_warning = _reload_wireguard()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            wg_warning = f"WireGuard setup failed: {exc}"

        import time as _time
        ttl_seconds = body.get("ttl_seconds")
        if ttl_seconds is not None and int(ttl_seconds) > 0:
            _ttl_secs = int(ttl_seconds)
            _ttl_expires = _time.time() + _ttl_secs
            _permanent = False
        else:
            _ttl_secs = None
            _ttl_expires = None
            _permanent = True

        state.clients[name] = {
            "private_key":    priv_key_str,
            "public_key":     pub_key_str,
            "psk":            psk_str,
            "ip":             allocated_ip,
            "config_hash":    config_hash,
            "permanent":      _permanent,
            "ttl_seconds":    _ttl_secs,
            "ttl_expires_at": _ttl_expires,
        }
        state.ip_pool["allocated"]        = pool.get_allocated()
        state.integrity[f"client-{name}"] = config_hash
        vault.save(state, passphrase)

        AuditLog(_AUDIT_PATH).log("add-client", {"name": name, "ip": allocated_ip})

        with _lock:
            _session["cache"] = _refresh_cache(state)

    result: dict = {"name": name, "ip": allocated_ip}
    if wg_warning:
        result["warning"] = wg_warning
    return result


def _h_remove_client(req: "_Handler", groups: tuple) -> dict:
    _require_unlocked()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.core.ip_pool        import IPPool
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.audit      import AuditLog
    from wireseal.platform.detect     import get_adapter

    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)

        revoked_ip = state.clients[name]["ip"]

        peers = [
            {
                "name":       n,
                "public_key": _extract(d["public_key"]),
                "psk":        _extract(d["psk"]),
                "ip":         d["ip"],
            }
            for n, d in state.clients.items()
            if n != name
        ]

        server_config = ConfigBuilder().render_server_config(
            server_private_key=_extract(state.server["private_key"]),
            server_ip=state.server["ip"],
            prefix_length=int(state.ip_pool["subnet"].split("/")[1]),
            server_port=state.server["port"],
            clients=peers,
        )
        try:
            adapter = get_adapter()
            adapter.check_privileges()
            adapter.deploy_config(server_config)
            reload_err = _reload_wireguard()
            if reload_err:
                print(f"[wireseal] remove-client reload warning: {reload_err}",
                      file=sys.stderr)
        except Exception as exc:
            print(f"[wireseal] remove-client reload failed: {exc}",
                  file=sys.stderr)

        pool = IPPool(state.ip_pool["subnet"])
        pool.load_state(state.ip_pool.get("allocated", {}))
        pool.release(revoked_ip)
        state.ip_pool["allocated"] = pool.get_allocated()

        del state.clients[name]
        state.integrity.pop(f"client-{name}", None)
        state.integrity.pop(f"client-{name}_verified", None)

        conf_path = _VAULT_DIR / "clients" / f"{name}.conf"
        try:
            conf_path.unlink(missing_ok=True)
        except OSError:
            pass

        vault.save(state, passphrase)
        AuditLog(_AUDIT_PATH).log("remove-client", {"name": name})

        with _lock:
            _session["cache"] = _refresh_cache(state)

    return {"ok": True}


def _h_client_qr(req: "_Handler", groups: tuple) -> dict:
    _require_unlocked()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.audit      import AuditLog

    config_str = ""
    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)
        cdata = state.clients[name]
        config_str = ConfigBuilder().render_client_config(
            client_private_key=_extract(cdata["private_key"]),
            client_ip=cdata["ip"],
            dns_server="1.1.1.1, 8.8.8.8",
            server_public_key=_extract(state.server["public_key"]),
            psk=_extract(cdata["psk"]),
            server_endpoint=_resolve_client_endpoint(state.server),
            mtu=_detect_mtu(),
        )

    try:
        import qrcode
        import qrcode.image.svg

        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(config_str)
        qr.make(fit=True)

        # Try PNG first (needs Pillow), fall back to SVG (no deps)
        try:
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            png_b64 = base64.b64encode(buf.getvalue()).decode()
            img_format = "png"
        except Exception:
            # Pillow not available — use SVG
            img = qr.make_image(image_factory=qrcode.image.svg.SvgPathFillImage)
            buf = io.BytesIO()
            img.save(buf)
            png_b64 = base64.b64encode(buf.getvalue()).decode()
            img_format = "svg+xml"
    except ImportError:
        raise _ApiError("QR code generation unavailable — 'qrcode' package not installed", 500)
    except Exception:
        raise _ApiError("QR code generation failed.", 500)

    AuditLog(_AUDIT_PATH).log("export-qr", {"client": name})
    return {"name": name, "qr_png_b64": png_b64, "format": img_format}


def _h_client_config(req: "_Handler", groups: tuple) -> dict:
    """Return the client WireGuard config as text for download."""
    _require_unlocked()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.audit      import AuditLog

    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)
        cdata = state.clients[name]
        config_str = ConfigBuilder().render_client_config(
            client_private_key=_extract(cdata["private_key"]),
            client_ip=cdata["ip"],
            dns_server="1.1.1.1, 8.8.8.8",
            server_public_key=_extract(state.server["public_key"]),
            psk=_extract(cdata["psk"]),
            server_endpoint=_resolve_client_endpoint(state.server),
            mtu=_detect_mtu(),
        )

    AuditLog(_AUDIT_PATH).log("export-config", {"client": name})
    return {"name": name, "config": config_str}


def _h_audit_log(req: "_Handler", _groups: tuple) -> dict:
    if not _AUDIT_PATH.exists():
        return {"entries": []}
    try:
        text    = _AUDIT_PATH.read_text()
        entries = []
        for line in text.strip().splitlines()[-100:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return {"entries": list(reversed(entries))}
    except OSError:
        return {"entries": []}


def _h_session_summary(req: "_Handler", _groups: tuple) -> dict:
    """Build a session summary from audit log entries."""
    _require_unlocked()
    if not _AUDIT_PATH.exists():
        return {"sessions": [], "summary": {}}

    try:
        lines = _AUDIT_PATH.read_text().strip().splitlines()
    except OSError:
        return {"sessions": [], "summary": {}}

    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    # Build session list (unlock → lock pairs)
    sessions = []
    current_session: dict | None = None
    action_counts: dict[str, int] = {}
    total_actions = 0

    for entry in entries:
        action = entry.get("action", "")
        total_actions += 1
        action_counts[action] = action_counts.get(action, 0) + 1

        if action in ("unlock-web", "init"):
            current_session = {
                "start": entry.get("timestamp", ""),
                "end": None,
                "events": [entry],
            }
        elif action == "lock" and current_session:
            current_session["end"] = entry.get("timestamp", "")
            current_session["events"].append(entry)
            sessions.append(current_session)
            current_session = None
        elif current_session:
            current_session["events"].append(entry)

    # If there's an active session (no lock yet), include it
    if current_session:
        current_session["end"] = None
        sessions.append(current_session)

    # Build session summaries (last 10)
    session_summaries = []
    for sess in sessions[-10:]:
        event_types: dict[str, int] = {}
        for ev in sess["events"]:
            a = ev.get("action", "unknown")
            event_types[a] = event_types.get(a, 0) + 1
        session_summaries.append({
            "start": sess["start"],
            "end": sess["end"],
            "event_count": len(sess["events"]),
            "event_types": event_types,
        })

    return {
        "sessions": list(reversed(session_summaries)),
        "summary": {
            "total_sessions": len(sessions),
            "total_events": total_actions,
            "action_counts": action_counts,
            "clients_added": action_counts.get("add-client", 0),
            "clients_removed": action_counts.get("remove-client", 0),
            "configs_exported": action_counts.get("export-config", 0),
            "qr_codes_generated": action_counts.get("export-qr", 0),
        },
    }


def _h_security_status(req: "_Handler", _groups: tuple) -> dict:
    """Return server security posture (cross-platform)."""
    _require_unlocked()
    _empty: dict = {
        "ssh_hardened": False, "kernel_hardened": False,
        "fail2ban_active": False, "fail2ban_bans": 0,
        "firewall_active": False, "ip_forwarding": False,
        "auto_updates": False, "open_ports": [], "checks": [],
    }
    try:
        from wireseal.platform.detect import get_adapter
        adapter = get_adapter()
        if hasattr(adapter, "get_security_status"):
            return adapter.get_security_status()
        return _empty
    except Exception:
        return _empty


def _h_harden_server(req: "_Handler", _groups: tuple) -> dict:
    """Apply server hardening (cross-platform)."""
    _require_unlocked()
    try:
        from wireseal.platform.detect import get_adapter
        adapter = get_adapter()
        if hasattr(adapter, "harden_server"):
            actions = adapter.harden_server()
            from wireseal.security.audit import AuditLog
            AuditLog(_AUDIT_PATH).log("harden-server", {"actions_count": len(actions)})
            return {"ok": True, "actions": actions}
        return {"ok": True, "actions": ["Hardening not available on this platform"]}
    except Exception as exc:
        return {"ok": False, "actions": [], "error": str(exc)}


def _h_file_activity(req: "_Handler", _groups: tuple) -> dict:
    """Return recent SFTP/SSH file activity from system logs."""
    _require_unlocked()

    events: list[dict] = []

    if sys.platform != "win32":
        # Parse SFTP activity from journalctl (sshd internal-sftp logs)
        try:
            result = subprocess.run(
                ["journalctl", "-u", "sshd", "--no-pager", "-n", "500",
                 "--output=short-iso", "--grep=sftp-server"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                # Try ssh.service (Debian/Ubuntu)
                result = subprocess.run(
                    ["journalctl", "-u", "ssh", "--no-pager", "-n", "500",
                     "--output=short-iso", "--grep=sftp-server"],
                    capture_output=True, text=True, timeout=10,
                )

            for line in result.stdout.strip().splitlines():
                if not line:
                    continue
                event = _parse_sftp_log_line(line)
                if event:
                    events.append(event)
        except Exception:
            pass

        # Also check auth.log if journalctl didn't find anything
        if not events:
            for log_path in ["/var/log/auth.log", "/var/log/secure"]:
                try:
                    with open(log_path, "r") as f:
                        lines = f.readlines()[-500:]
                    for line in lines:
                        if "sftp-server" in line:
                            event = _parse_sftp_log_line(line)
                            if event:
                                events.append(event)
                    if events:
                        break
                except (OSError, PermissionError):
                    continue

    # Return most recent 100
    return {"events": events[-100:]}


def _parse_sftp_log_line(line: str) -> dict | None:
    """Parse an SFTP log line into a structured event."""
    import re as _re

    # Common SFTP operations in log lines
    sftp_ops = {
        "open": "file_open",
        "close": "file_close",
        "read": "file_read",
        "write": "file_write",
        "opendir": "dir_open",
        "closedir": "dir_close",
        "mkdir": "dir_create",
        "rmdir": "dir_remove",
        "remove": "file_remove",
        "rename": "file_rename",
        "stat": "file_stat",
        "lstat": "file_stat",
        "fstat": "file_stat",
        "setstat": "file_permissions",
        "fsetstat": "file_permissions",
        "symlink": "file_symlink",
        "readlink": "file_readlink",
        "realpath": "file_realpath",
    }

    for op, event_type in sftp_ops.items():
        pattern = _re.compile(
            rf'{op}\s+"([^"]+)"', _re.IGNORECASE
        )
        match = pattern.search(line)
        if match:
            filepath = match.group(1)
            # Extract timestamp from beginning of line
            ts_match = _re.match(r'(\d{4}-\d{2}-\d{2}T[\d:]+[+-]\d{4}|\w+\s+\d+\s+[\d:]+)', line)
            timestamp = ts_match.group(1) if ts_match else ""

            # For rename, try to find the second path
            details: dict[str, Any] = {"path": filepath}
            if op == "rename":
                rename_match = _re.search(rf'rename\s+"([^"]+)"\s+"([^"]+)"', line)
                if rename_match:
                    details["from"] = rename_match.group(1)
                    details["to"] = rename_match.group(2)

            # Extract user if possible
            user_match = _re.search(r'session opened for.*user\s+(\w+)|user\s+(\w+)', line)
            if user_match:
                details["user"] = user_match.group(1) or user_match.group(2)

            return {
                "timestamp": timestamp,
                "type": event_type,
                "operation": op,
                "details": details,
            }

    return None


def _h_change_passphrase(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body        = req._json()
    current_str = body.get("current", "")
    new_str     = body.get("new", "")

    if len(new_str) < 12:
        raise _ApiError("New passphrase must be at least 12 characters.", 400)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe  import wipe_string
    from wireseal.security.audit         import AuditLog

    with _lock:
        vault = _session["vault"]

    old_passphrase = SecretBytes(bytearray(current_str.encode()))
    new_passphrase = SecretBytes(bytearray(new_str.encode()))
    try:
        try:
            vault.change_passphrase(old_passphrase, new_passphrase)
        except Exception:
            old_passphrase.wipe()
            new_passphrase.wipe()
            raise _ApiError("Passphrase change failed — check current passphrase.", 401)

        with _lock:
            _session["passphrase"].wipe()
            _session["passphrase"] = new_passphrase
        old_passphrase.wipe()

        # Wipe PIN — it's encrypted with the old passphrase, now stale
        _pin_wipe()

        AuditLog(_AUDIT_PATH).log("change-passphrase", {})
        return {"ok": True, "pin_removed": _PIN_PATH.exists() is False}
    finally:
        wipe_string(current_str)
        wipe_string(new_str)


def _h_start_server(req: "_Handler", _groups: tuple) -> dict:
    """Start the WireGuard tunnel (wg-quick up)."""
    _require_unlocked()
    from wireseal.security.audit import AuditLog

    # Check if already running
    check = subprocess.run(
        _sudo(["ip", "link", "show", _WG_IFACE]) if sys.platform != "win32"
        else ["sc.exe", "query", f"WireGuardTunnel${_WG_IFACE}"],
        capture_output=True, timeout=5,
    )

    if sys.platform == "win32":
        if b"RUNNING" in (check.stdout or b""):
            return {"ok": True, "note": "already running"}
        wg_exe = Path(r"C:\Program Files\WireGuard\wireguard.exe")
        from wireseal.platform.detect import get_adapter
        config_path = get_adapter().get_config_path(_WG_IFACE)
        if wg_exe.exists() and config_path.exists():
            subprocess.run(
                [str(wg_exe), "/installtunnelservice", str(config_path)],
                check=False, capture_output=True, timeout=15,
                creationflags=_SP_FLAGS,
            )
            AuditLog(_AUDIT_PATH).log("start", {"interface": _WG_IFACE})
            return {"ok": True}
        raise _ApiError("WireGuard not found or no config.", 500)

    # Linux/macOS
    if check.returncode == 0:
        return {"ok": True, "note": "already running"}

    try:
        result = subprocess.run(
            _sudo(["wg-quick", "up", _WG_IFACE]),
            check=False, capture_output=True, timeout=30,
        )
        if result.returncode == 0:
            AuditLog(_AUDIT_PATH).log("start", {"interface": _WG_IFACE})
            return {"ok": True}
        err = result.stderr.decode("utf-8", errors="replace")
        raise _ApiError(f"Failed to start: {err}", 500)
    except FileNotFoundError:
        raise _ApiError("wg-quick not found — is WireGuard installed?", 500)


def _h_terminate(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    from wireseal.security.audit import AuditLog

    if sys.platform == "win32":
        # Windows: stop via sc.exe and uninstall the tunnel service
        svc = f"WireGuardTunnel${_WG_IFACE}"
        subprocess.run(
            ["sc.exe", "stop", svc],
            check=False, capture_output=True, timeout=15,
            creationflags=_SP_FLAGS,
        )
        wg_exe = Path(r"C:\Program Files\WireGuard\wireguard.exe")
        if wg_exe.exists():
            subprocess.run(
                [str(wg_exe), "/uninstalltunnelservice", _WG_IFACE],
                check=False, capture_output=True, timeout=15,
                creationflags=_SP_FLAGS,
            )
        AuditLog(_AUDIT_PATH).log("terminate", {"interface": _WG_IFACE})
        return {"ok": True}

    # Linux/macOS: use wg-quick down
    try:
        subprocess.run(
            _sudo(["wg-quick", "down", _WG_IFACE]),
            check=True, capture_output=True, timeout=15,
        )
        AuditLog(_AUDIT_PATH).log("terminate", {"interface": _WG_IFACE})
        return {"ok": True}
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode() if exc.stderr else ""
        if "not a WireGuard interface" in stderr or "does not exist" in stderr:
            return {"ok": True, "note": "interface was already down"}
        raise _ApiError("Failed to stop WireGuard interface.", 500)
    except FileNotFoundError:
        raise _ApiError("wg-quick not found — is WireGuard installed?", 500)


def _h_fresh_start(req: "_Handler", _groups: tuple) -> dict:
    # NOTE: deliberately NOT requiring unlock — fresh start must work when
    # the user has forgotten their passphrase or the vault is corrupt.
    body = req._json()
    if body.get("confirm") != "CONFIRM":
        raise _ApiError('Send {"confirm":"CONFIRM"} to proceed.', 400)

    # Stop the WireGuard tunnel
    if sys.platform == "win32":
        svc = f"WireGuardTunnel${_WG_IFACE}"
        try:
            subprocess.run(["sc.exe", "stop", svc], check=False, capture_output=True, timeout=10, creationflags=_SP_FLAGS)
        except Exception:
            pass
        wg_exe = Path(r"C:\Program Files\WireGuard\wireguard.exe")
        if wg_exe.exists():
            try:
                subprocess.run([str(wg_exe), "/uninstalltunnelservice", _WG_IFACE], check=False, capture_output=True, timeout=10, creationflags=_SP_FLAGS)
            except Exception:
                pass
    else:
        try:
            subprocess.run(_sudo(["wg-quick", "down", _WG_IFACE]), check=False, capture_output=True, timeout=10)
        except Exception:
            pass

    import shutil
    shutil.rmtree(_VAULT_DIR, ignore_errors=True)

    from wireseal.platform.detect import get_adapter
    try:
        cfg = get_adapter().get_config_path(_WG_IFACE)
        cfg.unlink(missing_ok=True)
    except Exception:
        pass

    with _lock:
        if _session["passphrase"]:
            _session["passphrase"].wipe()
        _session.update(vault=None, passphrase=None, cache=None)

    return {"ok": True}


def _h_update_endpoint(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body     = req._json()
    endpoint = body.get("endpoint")
    if not endpoint:
        try:
            from wireseal.dns.ip_resolver import resolve_public_ip
            endpoint = str(resolve_public_ip())
        except Exception as exc:
            raise _ApiError("Could not auto-detect public IP.", 500)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.security.audit import AuditLog
    with vault.open(passphrase) as state:
        state.server["endpoint"] = endpoint
        vault.save(state, passphrase)
        with _lock:
            _session["cache"] = _refresh_cache(state)

    AuditLog(_AUDIT_PATH).log("update-endpoint", {"endpoint": endpoint})
    return {"ok": True, "endpoint": endpoint}


# ---------------------------------------------------------------------------
# PIN handlers
# ---------------------------------------------------------------------------


def _h_set_pin(req: "_Handler", _groups: tuple) -> dict:
    """Set a quick-unlock PIN. Requires vault to be unlocked."""
    _require_unlocked()
    body = req._json()
    pin = body.get("pin", "")
    if not pin or not pin.isdigit() or len(pin) < 4 or len(pin) > 8:
        raise _ApiError("PIN must be 4–8 digits.", 400)

    with _lock:
        passphrase = _session["passphrase"]

    if passphrase is None:
        raise _ApiError("No passphrase in session.", 500)

    # Encrypt the passphrase with the PIN and save to disk
    passphrase_bytes = passphrase.expose_secret()
    _pin_save(passphrase_bytes, pin)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("set-pin", {})
    return {"ok": True}


def _h_remove_pin(req: "_Handler", _groups: tuple) -> dict:
    """Remove the quick-unlock PIN."""
    _pin_wipe()
    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("remove-pin", {})
    return {"ok": True}


def _h_unlock_pin(req: "_Handler", _groups: tuple) -> dict:
    """Unlock the vault using a PIN instead of the full passphrase."""
    global _pin_fail_count
    client_ip = req.client_address[0]
    _check_rate_limit(client_ip)

    if not _PIN_PATH.exists():
        raise _ApiError("No PIN set. Use passphrase to unlock.", 400)

    if _pin_fail_count >= _PIN_MAX_ATTEMPTS:
        _pin_wipe()
        _pin_fail_count = 0
        raise _ApiError("Too many wrong PIN attempts. PIN removed — use your passphrase.", 403)

    body = req._json()
    pin = body.get("pin", "")
    if not pin:
        raise _ApiError("pin is required", 400)

    passphrase_bytes = _pin_load(pin)
    if passphrase_bytes is None:
        _pin_fail_count += 1
        _record_unlock_failure(client_ip)
        remaining = _PIN_MAX_ATTEMPTS - _pin_fail_count
        if _pin_fail_count >= _PIN_MAX_ATTEMPTS:
            _pin_wipe()
            _pin_fail_count = 0
            raise _ApiError("Wrong PIN. PIN removed after too many attempts — use your passphrase.", 403)
        raise _ApiError(f"Wrong PIN. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", 401)

    # PIN correct — decrypt passphrase and unlock the vault
    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.vault import Vault
    from wireseal.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_bytes))
    try:
        vault = Vault(_VAULT_PATH)
        try:
            with vault.open(passphrase) as st:
                cache = _refresh_cache(st)
        except Exception:
            passphrase.wipe()
            # PIN decrypted something but it doesn't unlock the vault —
            # passphrase may have changed since PIN was set.
            _pin_wipe()
            raise _ApiError("PIN is stale — passphrase was changed. Use your passphrase to unlock.", 401)

        with _lock:
            if _session["passphrase"]:
                _session["passphrase"].wipe()
            _session.update(vault=vault, passphrase=passphrase, cache=cache)

        _pin_fail_count = 0  # Reset on success
        _clear_unlock_failures(client_ip)
        AuditLog(_AUDIT_PATH).log("unlock-pin", {})

        # Auto-start WireGuard tunnel (same as passphrase unlock)
        try:
            wg_check = subprocess.run(
                _sudo(["wg", "show", _WG_IFACE]),
                capture_output=True, timeout=5,
                creationflags=_SP_FLAGS,
            )
            if wg_check.returncode != 0:
                conf_path = Path("/etc/wireguard") / f"{_WG_IFACE}.conf"
                if sys.platform == "win32":
                    conf_path = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "WireGuard" / f"{_WG_IFACE}.conf"
                if conf_path.exists():
                    subprocess.run(
                        _sudo(["wg-quick", "up", _WG_IFACE]),
                        capture_output=True, timeout=15,
                        creationflags=_SP_FLAGS,
                    )
        except Exception:
            pass

        return {"ok": True}
    except _ApiError:
        raise
    except Exception:
        passphrase.wipe()
        raise _ApiError("Unlock failed.", 500)


def _h_pin_info(req: "_Handler", _groups: tuple) -> dict:
    """Check if a PIN is configured."""
    return {"pin_set": _PIN_PATH.exists()}


# ---------------------------------------------------------------------------
# Admin mode endpoints
# ---------------------------------------------------------------------------

def _h_admin_authenticate(req: "_Handler", _groups: tuple) -> dict:
    """Verify root/sudo password and activate admin mode.

    POST /api/admin/authenticate
    Body: {"password": "..."}

    Vault must be unlocked first. Admin mode grants unrestricted system access
    for _ADMIN_TIMEOUT seconds. Rate-limited to 3 attempts per 5 minutes.
    """
    _require_unlocked()
    body      = req._json()
    password  = body.get("password", "")
    client_ip = req.client_address[0]

    if not password and sys.platform != "win32":
        raise _ApiError("password is required", 400)

    _check_admin_rate_limit(client_ip)

    if not _verify_root_password(password):
        _record_admin_failure(client_ip)
        from wireseal.security.audit import AuditLog
        AuditLog(_AUDIT_PATH).log("admin-auth-failed", {"ip": client_ip})
        raise _ApiError("Invalid credentials.", 401)

    _clear_admin_failures(client_ip)

    import time as _time
    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.audit import AuditLog

    pw_secret = SecretBytes(bytearray(password.encode("utf-8")))

    with _admin_lock:
        if _admin_session["password"] is not None:
            try:
                _admin_session["password"].wipe()
            except Exception:
                pass
        _admin_session["active"]     = True
        _admin_session["password"]   = pw_secret
        _admin_session["expires_at"] = _time.monotonic() + _ADMIN_TIMEOUT

    AuditLog(_AUDIT_PATH).log("admin-activate", {"ip": client_ip})
    return {"ok": True, "expires_in": _ADMIN_TIMEOUT}


def _h_admin_deactivate_endpoint(req: "_Handler", _groups: tuple) -> dict:
    """Deactivate admin mode and wipe cached credentials.

    POST /api/admin/deactivate
    """
    _require_unlocked()
    _admin_deactivate()
    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("admin-deactivate", {})
    return {"ok": True}


def _h_admin_status(req: "_Handler", _groups: tuple) -> dict:
    """Return admin mode state and seconds remaining.

    GET /api/admin/status
    """
    import time as _time
    with _admin_lock:
        active  = _admin_session["active"]
        expires = _admin_session["expires_at"]

    if not active:
        return {"active": False, "expires_in": 0}

    remaining = max(0.0, (expires or 0.0) - _time.monotonic())
    if remaining == 0.0:
        _admin_deactivate()
        return {"active": False, "expires_in": 0}

    return {"active": True, "expires_in": int(remaining)}


def _h_admin_exec(req: "_Handler", _groups: tuple) -> dict:
    """Execute any command as root.

    POST /api/admin/exec
    Body: {"cmd": ["ls", "-la", "/etc"], "stdin": "", "timeout": 30}

    Requires vault unlocked + admin mode active.
    ``timeout`` is capped at 120 seconds.
    """
    _require_unlocked()
    _require_admin_active()

    body      = req._json()
    cmd       = body.get("cmd", [])
    if not cmd or not isinstance(cmd, list):
        raise _ApiError("cmd (array of strings) is required", 400)
    if not all(isinstance(s, str) for s in cmd):
        raise _ApiError("cmd must be an array of strings", 400)

    stdin_str = body.get("stdin", "")
    timeout   = min(int(body.get("timeout", 30)), 120)

    try:
        result = _admin_run(
            cmd,
            stdin_extra=stdin_str.encode("utf-8") if stdin_str else b"",
            timeout=timeout,
        )
    except _ApiError:
        raise
    except subprocess.TimeoutExpired:
        raise _ApiError(f"Command timed out after {timeout}s", 504)
    except Exception as exc:
        raise _ApiError(f"Execution failed: {exc}", 500)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("admin-exec", {"cmd": cmd[:3], "rc": result.returncode})

    return {
        "returncode": result.returncode,
        "stdout":     result.stdout.decode("utf-8", errors="replace"),
        "stderr":     result.stderr.decode("utf-8", errors="replace"),
    }


def _h_admin_services(req: "_Handler", _groups: tuple) -> dict:
    """List all systemd services with their state.

    GET /api/admin/services   — Linux only.
    """
    _require_unlocked()
    _require_admin_active()

    if sys.platform != "linux":
        return {"services": [], "note": "Service management is Linux-only."}

    try:
        result = _admin_run(
            [
                "systemctl", "list-units", "--type=service",
                "--all", "--no-pager", "--plain", "--no-legend",
            ],
            timeout=15,
        )
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(f"Failed to list services: {exc}", 500)

    services: list[dict] = []
    for line in result.stdout.decode("utf-8", errors="replace").splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            services.append({
                "unit":        parts[0],
                "load":        parts[1],
                "active":      parts[2],
                "sub":         parts[3],
                "description": parts[4].strip() if len(parts) > 4 else "",
            })

    return {"services": services}


_SERVICE_ACTIONS = frozenset({
    "start", "stop", "restart", "reload", "status", "enable", "disable",
})


def _h_admin_service_action(req: "_Handler", groups: tuple) -> dict:
    """Perform an action on a systemd service.

    POST /api/admin/services/<name>/<action>

    Linux only. Valid actions: start, stop, restart, reload, status, enable, disable.
    """
    _require_unlocked()
    _require_admin_active()

    service = groups[0] if groups else ""
    action  = groups[1] if len(groups) > 1 else ""

    if not re.fullmatch(r"[a-zA-Z0-9@._:-]{1,128}", service):
        raise _ApiError("Invalid service name.", 400)
    if action not in _SERVICE_ACTIONS:
        raise _ApiError(
            f"action must be one of: {', '.join(sorted(_SERVICE_ACTIONS))}", 400
        )
    if sys.platform != "linux":
        raise _ApiError("Service management is Linux-only.", 400)

    try:
        result = _admin_run(["systemctl", action, service, "--no-pager"], timeout=30)
    except _ApiError:
        raise
    except subprocess.TimeoutExpired:
        raise _ApiError("Service action timed out.", 504)
    except Exception as exc:
        raise _ApiError(f"Service action failed: {exc}", 500)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log(
        "admin-service", {"service": service, "action": action, "rc": result.returncode}
    )

    return {
        "ok":         result.returncode == 0,
        "returncode": result.returncode,
        "stdout":     result.stdout.decode("utf-8", errors="replace"),
        "stderr":     result.stderr.decode("utf-8", errors="replace"),
    }


def _h_admin_read_file(req: "_Handler", _groups: tuple) -> dict:
    """Read any file as root.

    POST /api/admin/file/read
    Body: {"path": "/etc/wireguard/wg0.conf"}
    """
    _require_unlocked()
    _require_admin_active()

    body = req._json()
    path = body.get("path", "").strip()
    if not path:
        raise _ApiError("path is required", 400)

    try:
        result = _admin_run(["cat", "--", path], timeout=10)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(f"Read failed: {exc}", 500)

    if result.returncode != 0:
        err = result.stderr.decode("utf-8", errors="replace").strip()
        raise _ApiError(err or "File not found or permission denied.", 404)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("admin-read-file", {"path": path})

    return {"path": path, "content": result.stdout.decode("utf-8", errors="replace")}


def _h_admin_write_file(req: "_Handler", _groups: tuple) -> dict:
    """Write content to any file as root.

    POST /api/admin/file/write
    Body: {"path": "/etc/wireguard/wg0.conf", "content": "..."}
    """
    _require_unlocked()
    _require_admin_active()

    body    = req._json()
    path    = body.get("path", "").strip()
    content = body.get("content", "")
    if not path:
        raise _ApiError("path is required", 400)

    try:
        result = _admin_run(
            ["tee", "--", path],
            stdin_extra=content.encode("utf-8"),
            timeout=10,
        )
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(f"Write failed: {exc}", 500)

    if result.returncode != 0:
        err = result.stderr.decode("utf-8", errors="replace").strip()
        raise _ApiError(err or "Write failed.", 500)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("admin-write-file", {"path": path})

    return {"ok": True, "path": path}


# ---------------------------------------------------------------------------
# Key rotation API endpoints (Phase 7)
# ---------------------------------------------------------------------------


def _h_rotate_client_keys(req: "_Handler", groups: tuple) -> dict:
    """Rotate the keypair and PSK for a specific client.

    POST /api/clients/<name>/rotate

    Generates new client keypair + PSK, rebuilds both client and server
    configs, validates them, writes atomically, reloads WireGuard, and
    updates the vault.  Returns the new client config + QR PNG.
    """
    _require_unlocked()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.core.keygen         import generate_keypair
    from wireseal.core.psk            import generate_psk
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.validator  import validate_client_config, validate_server_config
    from wireseal.security.atomic     import atomic_write
    from wireseal.security.audit      import AuditLog
    from wireseal.platform.detect     import get_adapter

    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)

        client_data = state.clients[name]

        # Generate new material
        new_priv, new_pub_bytes = generate_keypair()
        new_psk = generate_psk()
        new_pub_str  = new_pub_bytes.decode("ascii")
        new_priv_str = new_priv.expose_secret().decode("ascii")
        new_psk_str  = new_psk.expose_secret().decode("ascii")

        # Collect server info
        server_data     = state.server
        server_pub_key  = _extract(server_data["public_key"])
        client_ip       = client_data["ip"]
        server_port     = server_data["port"]
        server_endpoint = _resolve_client_endpoint(server_data)
        subnet          = state.ip_pool.get("subnet", "10.0.0.0/24")
        prefix_length   = int(subnet.split("/")[1])
        dns_server      = client_data.get("dns_server", "1.1.1.1, 8.8.8.8")

        # Build new client config
        builder = ConfigBuilder()
        new_client_config = builder.render_client_config(
            client_private_key=new_priv_str,
            client_ip=client_ip,
            dns_server=dns_server,
            server_public_key=server_pub_key,
            psk=new_psk_str,
            server_endpoint=server_endpoint,
            mtu=_detect_mtu(),
        )

        # Build updated server config
        peers = []
        for cname, cdata in state.clients.items():
            if cname == name:
                peers.append({
                    "name": cname, "public_key": new_pub_str,
                    "psk": new_psk_str, "ip": cdata["ip"],
                })
            else:
                peers.append({
                    "name": cname, "public_key": _extract(cdata["public_key"]),
                    "psk": _extract(cdata["psk"]), "ip": cdata["ip"],
                })

        new_server_config = builder.render_server_config(
            server_private_key=_extract(server_data["private_key"]),
            server_ip=server_data["ip"],
            prefix_length=prefix_length,
            server_port=server_port,
            clients=peers,
        )

        # Validate
        try:
            validate_client_config({
                "private_key": new_priv_str, "psk": new_psk_str,
                "ip": client_ip, "dns_server": dns_server,
                "server_public_key": server_pub_key,
                "endpoint": server_endpoint,
            })
        except ValueError as exc:
            new_priv.wipe()
            new_psk.wipe()
            raise _ApiError(f"Client config validation failed: {exc}", 500) from exc

        try:
            validate_server_config({
                "private_key": _extract(server_data["private_key"]),
                "public_key": "", "port": server_port,
                "subnet": subnet, "clients": peers,
            })
        except ValueError as exc:
            new_priv.wipe()
            new_psk.wipe()
            raise _ApiError(f"Server config validation failed: {exc}", 500) from exc

        # Write configs atomically
        clients_dir = _VAULT_DIR / "clients"
        clients_dir.mkdir(parents=True, exist_ok=True)
        client_conf_path = clients_dir / f"{name}.conf"
        client_encoded = new_client_config.encode("utf-8")
        atomic_write(client_conf_path, client_encoded, mode=0o600)
        client_hash = hashlib.sha256(client_encoded).hexdigest()

        adapter = get_adapter()
        server_conf_path = adapter.get_config_path(_WG_IFACE)
        server_encoded = new_server_config.encode("utf-8")
        atomic_write(server_conf_path, server_encoded, mode=0o600)
        server_hash = hashlib.sha256(server_encoded).hexdigest()

        # Reload WireGuard
        wg_warning = _reload_wireguard(_WG_IFACE)

        # Update vault state
        state.clients[name]["private_key"] = new_priv_str
        state.clients[name]["public_key"]  = new_pub_str
        state.clients[name]["psk"]         = new_psk_str
        state.integrity[f"client-{name}"]  = client_hash
        state.integrity["server"]          = server_hash
        vault.save(state, passphrase)

        AuditLog(_AUDIT_PATH).log("rotate-client-keys", {"name": name})

        with _lock:
            _session["cache"] = _refresh_cache(state)

    # Generate QR
    qr_b64 = ""
    try:
        qr_img = io.BytesIO()
        import qrcode  # type: ignore
        qrcode.make(new_client_config).save(qr_img, format="PNG")
        qr_b64 = base64.b64encode(qr_img.getvalue()).decode()
    except Exception:
        pass

    result: dict = {"ok": True, "name": name, "config": new_client_config}
    if qr_b64:
        result["qr_png_b64"] = qr_b64
    if wg_warning:
        result["warning"] = wg_warning
    return result


def _h_rotate_server_keys(req: "_Handler", _groups: tuple) -> dict:
    """Rotate the server keypair and update all client configs.

    POST /api/rotate-server-keys

    Generates a new server keypair, rebuilds ALL client configs with the
    new server public key, validates everything, writes atomically,
    reloads WireGuard, and updates the vault.
    """
    _require_unlocked()

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.core.keygen         import generate_keypair
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.validator  import validate_client_config, validate_server_config
    from wireseal.security.atomic     import atomic_write
    from wireseal.security.audit      import AuditLog
    from wireseal.platform.detect     import get_adapter

    with vault.open(passphrase) as state:
        clients = list(state.clients.keys())
        client_count = len(clients)

        # Generate new server keypair
        new_server_priv, new_server_pub = generate_keypair()
        new_server_pub_str  = new_server_pub.decode("ascii")
        new_server_priv_str = new_server_priv.expose_secret().decode("ascii")

        server_data   = state.server
        server_port   = server_data["port"]
        server_ip     = server_data["ip"]
        subnet        = state.ip_pool.get("subnet", "10.0.0.0/24")
        prefix_length = int(subnet.split("/")[1])

        builder     = ConfigBuilder()
        clients_dir = _VAULT_DIR / "clients"
        clients_dir.mkdir(parents=True, exist_ok=True)
        adapter = get_adapter()

        # Rebuild all client configs with new server public key
        new_client_hashes: dict[str, str] = {}
        updated_configs: dict[str, str] = {}
        for cname in clients:
            cdata = state.clients[cname]
            client_ip       = cdata["ip"]
            dns_server      = cdata.get("dns_server", "1.1.1.1, 8.8.8.8")
            server_endpoint = _resolve_client_endpoint(server_data)
            cpriv_str       = _extract(cdata.get("private_key", ""))
            cpsk_str        = _extract(cdata.get("psk", ""))

            updated_cfg = builder.render_client_config(
                client_private_key=cpriv_str,
                client_ip=client_ip,
                dns_server=dns_server,
                server_public_key=new_server_pub_str,
                psk=cpsk_str,
                server_endpoint=server_endpoint,
                mtu=_detect_mtu(),
            )

            try:
                validate_client_config({
                    "private_key": cpriv_str, "psk": cpsk_str,
                    "ip": client_ip, "dns_server": dns_server,
                    "server_public_key": new_server_pub_str,
                    "endpoint": server_endpoint,
                })
            except ValueError as exc:
                new_server_priv.wipe()
                raise _ApiError(
                    f"Client config validation failed for '{cname}': {exc}", 500
                ) from exc

            client_encoded = updated_cfg.encode("utf-8")
            atomic_write(clients_dir / f"{cname}.conf", client_encoded, mode=0o600)
            new_client_hashes[cname] = hashlib.sha256(client_encoded).hexdigest()
            updated_configs[cname] = updated_cfg

        # Build new server config
        peers_for_server = []
        for cname in clients:
            cdata = state.clients[cname]
            peers_for_server.append({
                "name": cname,
                "public_key": _extract(cdata.get("public_key", "")),
                "psk": _extract(cdata.get("psk", "")),
                "ip": cdata["ip"],
            })

        try:
            validate_server_config({
                "private_key": new_server_priv_str, "public_key": "",
                "port": server_port, "subnet": subnet,
                "clients": peers_for_server,
            })
        except ValueError as exc:
            new_server_priv.wipe()
            raise _ApiError(f"Server config validation failed: {exc}", 500) from exc

        new_server_config = builder.render_server_config(
            server_private_key=new_server_priv_str,
            server_ip=server_ip,
            prefix_length=prefix_length,
            server_port=server_port,
            clients=peers_for_server,
        )
        server_encoded = new_server_config.encode("utf-8")
        server_conf_path = adapter.get_config_path(_WG_IFACE)
        atomic_write(server_conf_path, server_encoded, mode=0o600)
        server_hash = hashlib.sha256(server_encoded).hexdigest()

        # Reload WireGuard
        wg_warning = _reload_wireguard(_WG_IFACE)

        # Update vault state
        state.server["private_key"] = new_server_priv_str
        state.server["public_key"]  = new_server_pub_str
        state.integrity["server"]   = server_hash
        for cname, chash in new_client_hashes.items():
            state.integrity[f"client-{cname}"] = chash
        vault.save(state, passphrase)

        AuditLog(_AUDIT_PATH).log(
            "rotate-server-keys", {"client_count": client_count}
        )

        with _lock:
            _session["cache"] = _refresh_cache(state)

    result: dict = {"ok": True, "client_count": client_count}
    if wg_warning:
        result["warning"] = wg_warning
    return result


# ---------------------------------------------------------------------------
# Multi-admin management helpers and handlers
# ---------------------------------------------------------------------------


def _require_owner() -> None:
    """Raise 403 if current session does not have owner role."""
    if _session.get("admin_role") != "owner":
        raise _ApiError("owner role required", 403)


def _h_list_admins(req: "_Handler", _groups: tuple) -> dict:
    """GET /api/admins — list all admins."""
    _require_unlocked()
    with _lock:
        admins_data = (_session["cache"] or {}).get("admins", {})
    result = []
    for aid, info in admins_data.items():
        result.append({
            "id": aid,
            "role": info.get("role", "admin"),
            "totp_enrolled": info.get("totp_secret_b32") is not None,
            "last_unlock": info.get("last_unlock"),
        })
    return {"admins": result}


def _h_add_admin(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/admins — add a new admin keyslot."""
    _require_unlocked()
    _require_owner()
    body       = req._json()
    admin_id   = body.get("admin_id", "").strip()
    passphrase = body.get("passphrase", "")
    role       = body.get("role", "admin")
    if not admin_id or not passphrase:
        raise _ApiError("admin_id and passphrase required", 400)
    if role not in ("owner", "admin", "readonly"):
        raise _ApiError("role must be owner, admin, or readonly", 400)

    with _lock:
        vault     = _session["vault"]
        sess_pass = _session["passphrase"]
        acting_id = _session.get("admin_id", "owner")

    new_bytes = bytearray(passphrase.encode())
    try:
        with vault.open(sess_pass, admin_id=acting_id) as state:
            vault.add_keyslot(admin_id, new_bytes, role=role)
            # add_keyslot already syncs state.data["admins"] but ensure entry is complete
            state.data.setdefault("admins", {})[admin_id] = {
                "role": role,
                "created_at": _utcnow_iso(),
                "totp_secret_b32": None,
                "totp_enrolled_at": None,
                "backup_codes": [],
                "last_unlock": None,
            }
            with _lock:
                _session["cache"] = _refresh_cache(state)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(str(exc), 409)
    finally:
        new_bytes[:] = b"\x00" * len(new_bytes)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("add-admin", {
        "target": admin_id, "role": role, "actor": acting_id,
    })
    return {"ok": True, "admin_id": admin_id}


def _h_remove_admin(req: "_Handler", groups: tuple) -> dict:
    """DELETE /api/admins/<id> — remove an admin keyslot."""
    _require_unlocked()
    _require_owner()
    target_id = (groups[0] if groups else "").strip()
    if not target_id:
        raise _ApiError("admin_id is required", 400)

    with _lock:
        vault     = _session["vault"]
        sess_pass = _session["passphrase"]
        acting_id = _session.get("admin_id", "owner")

    if target_id == acting_id:
        raise _ApiError("cannot remove yourself", 409)

    # Check if target is last owner
    with _lock:
        admins = (_session["cache"] or {}).get("admins", {})
    owners = [aid for aid, info in admins.items() if info.get("role") == "owner"]
    if target_id in owners and len(owners) == 1:
        raise _ApiError("cannot remove the last owner", 409)

    try:
        with vault.open(sess_pass, admin_id=acting_id) as state:
            vault.remove_keyslot(target_id)
            state.data.get("admins", {}).pop(target_id, None)
            with _lock:
                _session["cache"] = _refresh_cache(state)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(str(exc), 404)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("remove-admin", {
        "target": target_id, "actor": acting_id,
    })
    return {"ok": True}


def _h_change_admin_passphrase(req: "_Handler", groups: tuple) -> dict:
    """POST /api/admins/<id>/change-passphrase — change an admin's passphrase.

    Owner can change any admin's passphrase without knowing the old one.
    Non-owner must provide old_passphrase and can only change their own.
    """
    _require_unlocked()
    target_id = (groups[0] if groups else "").strip()
    if not target_id:
        raise _ApiError("admin_id is required", 400)

    with _lock:
        vault       = _session["vault"]
        sess_pass   = _session["passphrase"]
        acting_id   = _session.get("admin_id", "owner")
        acting_role = _session.get("admin_role", "owner")

    # Non-owner may only change their own passphrase
    if acting_role != "owner" and acting_id != target_id:
        raise _ApiError("may only change your own passphrase", 403)

    body           = req._json()
    new_passphrase = body.get("new_passphrase", "")
    old_passphrase = body.get("old_passphrase", "")
    if not new_passphrase:
        raise _ApiError("new_passphrase required", 400)

    # Non-owner changing their own passphrase must provide old_passphrase
    if acting_role != "owner" and not old_passphrase:
        raise _ApiError("old_passphrase required for non-owner passphrase change", 400)

    new_bytes = bytearray(new_passphrase.encode())
    old_bytes = bytearray(old_passphrase.encode()) if old_passphrase else bytearray()
    try:
        with vault.open(sess_pass, admin_id=acting_id) as _state:
            if acting_role == "owner" and acting_id != target_id:
                # Owner changing another admin's passphrase: remove + re-add using master key
                from wireseal.security.keyslot import create_keyslot
                store = vault._session_store
                if store is None:
                    raise _ApiError("Vault is not FORMAT_VERSION 3; multi-admin not active", 409)
                slot = store.find(target_id)
                if slot is None:
                    raise _ApiError(f"No keyslot for admin '{target_id}'", 404)
                new_slot = create_keyslot(
                    target_id, new_bytes, vault._session_master_key, role=slot.role
                )
                store.keyslots = [new_slot if s.admin_id == target_id else s
                                  for s in store.keyslots]
            else:
                vault.change_keyslot_passphrase(target_id, old_bytes, new_bytes)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(str(exc), 400)
    finally:
        new_bytes[:] = b"\x00" * len(new_bytes)
        old_bytes[:] = b"\x00" * len(old_bytes)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("change-passphrase", {
        "target": target_id, "actor": acting_id,
    })
    return {"ok": True}


# ---------------------------------------------------------------------------
# TOTP handlers
# ---------------------------------------------------------------------------


def _h_totp_enroll_begin(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/enroll/begin — generate a new TOTP secret for enrollment.

    Requires unlocked vault.  Stores a pending enrollment entry in
    ``_pending_totp`` keyed by admin_id.  The Dashboard renders the QR code
    from the returned otpauth:// URI using a JS library.

    Returns: {otpauth_uri, secret_b32}
    """
    _require_unlocked()
    with _lock:
        admin_id = _session.get("admin_id", "owner")

    secret = generate_totp_secret()
    uri = totp_uri(secret, admin_id)
    _pending_totp[admin_id] = {"secret": secret, "used_codes": set()}

    return {
        "otpauth_uri": uri,
        "secret_b32": secret_to_b32(secret),
    }


def _h_totp_enroll_confirm(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/enroll/confirm — verify code and commit TOTP enrollment.

    Body: {totp_code: "123456"}
    Returns: {ok: true, backup_codes: [...8 plaintext codes...]}

    The 8 backup codes are shown once and never stored in plaintext.
    The vault stores only their SHA-256 hashes.
    """
    _require_unlocked()
    with _lock:
        admin_id  = _session.get("admin_id", "owner")
        vault     = _session["vault"]
        sess_pass = _session["passphrase"]

    body      = req._json()
    totp_code = str(body.get("totp_code", "")).strip()

    pending = _pending_totp.get(admin_id)
    if pending is None:
        raise _ApiError("No pending enrollment. Call /api/totp/enroll/begin first.", 400)

    if not verify_totp(pending["secret"], totp_code, used_codes=pending["used_codes"]):
        raise _ApiError("invalid_code", 400)

    # Enrollment verified — generate backup codes and persist to vault
    backup_codes  = generate_backup_codes(8)
    hashed_codes  = [hash_backup_code(c) for c in backup_codes]
    b32           = secret_to_b32(pending["secret"])

    try:
        with vault.open(sess_pass, admin_id=admin_id) as state:
            admins_dict = state.data.setdefault("admins", {})
            if admin_id not in admins_dict:
                admins_dict[admin_id] = {
                    "role": "owner",
                    "created_at": _utcnow_iso(),
                    "totp_secret_b32": None,
                    "totp_enrolled_at": None,
                    "backup_codes": [],
                    "last_unlock": None,
                }
            admins_dict[admin_id]["totp_secret_b32"]  = b32
            admins_dict[admin_id]["totp_enrolled_at"] = _utcnow_iso()
            admins_dict[admin_id]["backup_codes"]     = hashed_codes
            with _lock:
                _session["cache"] = _refresh_cache(state)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(str(exc), 500)

    _pending_totp.pop(admin_id, None)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("totp-enrolled", {"admin_id": admin_id})

    return {"ok": True, "backup_codes": backup_codes}


def _h_totp_disable(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/disable — disable TOTP for an admin.

    Body (optional): {admin_id: "alice"}
    Owner can disable any admin's TOTP; non-owner can only disable their own.
    """
    _require_unlocked()
    with _lock:
        acting_id   = _session.get("admin_id", "owner")
        acting_role = _session.get("admin_role", "owner")
        vault       = _session["vault"]
        sess_pass   = _session["passphrase"]

    body      = req._json()
    target_id = body.get("admin_id", acting_id).strip() or acting_id

    if acting_role != "owner" and target_id != acting_id:
        raise _ApiError("may only disable your own TOTP", 403)

    try:
        with vault.open(sess_pass, admin_id=acting_id) as state:
            admins_dict = state.data.setdefault("admins", {})
            if target_id not in admins_dict:
                raise _ApiError(f"Admin '{target_id}' not found", 404)
            admins_dict[target_id]["totp_secret_b32"]  = None
            admins_dict[target_id]["totp_enrolled_at"] = None
            admins_dict[target_id]["backup_codes"]     = []
            with _lock:
                _session["cache"] = _refresh_cache(state)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(str(exc), 500)

    _pending_totp.pop(target_id, None)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("totp-disabled", {
        "target": target_id, "actor": acting_id,
    })
    return {"ok": True}


def _h_totp_reset(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/reset — owner-only: force-clear TOTP for any admin.

    Body: {admin_id: "alice"}
    """
    _require_unlocked()
    _require_owner()
    with _lock:
        acting_id = _session.get("admin_id", "owner")
        vault     = _session["vault"]
        sess_pass = _session["passphrase"]

    body      = req._json()
    target_id = body.get("admin_id", "").strip()
    if not target_id:
        raise _ApiError("admin_id is required", 400)

    try:
        with vault.open(sess_pass, admin_id=acting_id) as state:
            admins_dict = state.data.setdefault("admins", {})
            if target_id not in admins_dict:
                raise _ApiError(f"Admin '{target_id}' not found", 404)
            admins_dict[target_id]["totp_secret_b32"]  = None
            admins_dict[target_id]["totp_enrolled_at"] = None
            admins_dict[target_id]["backup_codes"]     = []
            with _lock:
                _session["cache"] = _refresh_cache(state)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(str(exc), 500)

    _pending_totp.pop(target_id, None)

    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("totp-reset", {
        "target": target_id, "actor": acting_id,
    })
    return {"ok": True}


def _h_totp_verify_backup(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/verify-backup — unlock using a passphrase + backup code.

    This replaces the normal unlock flow when the user has lost their TOTP
    device.  Does not require an unlocked session.

    Body: {admin_id: "owner", passphrase: "...", backup_code: "ABCDEFGHIJ"}
    Returns: {ok: true, role: "owner"} on success.
    """
    body          = req._json()
    admin_id      = body.get("admin_id", "owner")
    passphrase_str = body.get("passphrase", "")
    backup_code   = body.get("backup_code", "").upper().strip()
    client_ip     = req.client_address[0]

    if not passphrase_str:
        raise _ApiError("passphrase is required", 400)
    if not backup_code:
        raise _ApiError("backup_code is required", 400)

    _check_rate_limit(client_ip)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string
    from wireseal.security.vault        import Vault
    from wireseal.security.audit        import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode()))
    try:
        vault = Vault(_VAULT_PATH)
        try:
            with vault.open(passphrase, admin_id=admin_id) as st:
                admins_dict = st.data.setdefault("admins", {})
                if admin_id in admins_dict:
                    admins_dict[admin_id]["last_unlock"] = _utcnow_iso()
                admin_role   = admins_dict.get(admin_id, {}).get("role", "owner")
                hashed_codes = admins_dict.get(admin_id, {}).get("backup_codes", [])

                # Verify backup code (constant-time)
                matched = verify_backup_code(backup_code, hashed_codes)
                if matched is None:
                    _record_unlock_failure(client_ip)
                    raise _ApiError("invalid_backup_code", 401)

                # Consume the matched code (single-use)
                admins_dict[admin_id]["backup_codes"] = [
                    h for h in hashed_codes if h != matched
                ]
                cache = _refresh_cache(st)
        except _ApiError:
            passphrase.wipe()
            raise
        except Exception as exc:
            passphrase.wipe()
            _record_unlock_failure(client_ip)
            raise _ApiError("Incorrect passphrase.", 401)

        with _lock:
            if _session["passphrase"]:
                _session["passphrase"].wipe()
            _session.update(
                vault=vault, passphrase=passphrase, cache=cache,
                admin_id=admin_id, admin_role=admin_role,
            )

        _clear_unlock_failures(client_ip)
        AuditLog(_AUDIT_PATH).log("unlock-backup-code", {"admin_id": admin_id})
        return {"ok": True, "role": admin_role}
    finally:
        wipe_string(passphrase_str)


# ---------------------------------------------------------------------------
# DNS handlers (7.4 split-DNS)
# ---------------------------------------------------------------------------

def _h_get_dns(req, _groups):
    _require_unlocked()
    with _lock:
        cache = _session["cache"] or {}
    from wireseal.dns.dnsmasq import DnsmasqManager
    mgr = DnsmasqManager(_WG_IFACE)
    return {
        "mappings": cache.get("dns_mappings", {}),
        "dnsmasq_available": mgr.is_available(),
        "dnsmasq_running": mgr.is_running(),
    }


def _h_set_dns(req, _groups):
    _require_unlocked()
    body = req._json()
    mappings = body.get("mappings", {})
    if not isinstance(mappings, dict):
        raise _ApiError("mappings must be an object.", 400)
    from wireseal.dns.dnsmasq import DnsmasqManager, validate_hostname, validate_ip
    for hostname, ip in mappings.items():
        validate_hostname(hostname)
        validate_ip(ip)
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        admin_id = _session.get("admin_id", "owner")
    with vault.open(passphrase, admin_id=admin_id) as state:
        state.data["dns_mappings"] = mappings
        vault.save(state, passphrase)
    _refresh_cache_unlocked(vault, passphrase, admin_id)
    mgr = DnsmasqManager(_WG_IFACE)
    reloaded = False
    if mgr.is_available():
        mgr.write_config(mappings)
        reloaded = mgr.reload()
    return {"ok": True, "reloaded": reloaded}


def _h_add_dns_mapping(req, groups):
    _require_unlocked()
    hostname = groups[0]
    body = req._json()
    ip = body.get("ip", "")
    from wireseal.dns.dnsmasq import DnsmasqManager, validate_hostname, validate_ip
    validate_hostname(hostname)
    validate_ip(ip)
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        admin_id = _session.get("admin_id", "owner")
    with vault.open(passphrase, admin_id=admin_id) as state:
        state.data.setdefault("dns_mappings", {})[hostname] = ip
        mappings = dict(state.data["dns_mappings"])
        vault.save(state, passphrase)
    _refresh_cache_unlocked(vault, passphrase, admin_id)
    mgr = DnsmasqManager(_WG_IFACE)
    if mgr.is_available():
        mgr.write_config(mappings)
        mgr.reload()
    return {"ok": True}


def _h_remove_dns_mapping(req, groups):
    _require_unlocked()
    hostname = groups[0]
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        admin_id = _session.get("admin_id", "owner")
    with vault.open(passphrase, admin_id=admin_id) as state:
        if hostname not in state.data.get("dns_mappings", {}):
            raise _ApiError(f"Hostname '{hostname}' not found.", 404)
        del state.data["dns_mappings"][hostname]
        mappings = dict(state.data.get("dns_mappings", {}))
        vault.save(state, passphrase)
    _refresh_cache_unlocked(vault, passphrase, admin_id)
    from wireseal.dns.dnsmasq import DnsmasqManager
    mgr = DnsmasqManager(_WG_IFACE)
    if mgr.is_available():
        mgr.write_config(mappings)
        mgr.reload()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Routing table  — order matters for overlapping patterns
# ---------------------------------------------------------------------------

_ROUTES: list[tuple[str, re.Pattern, Any]] = [
    ("GET",    re.compile(r"^/api/health$"),                 _h_health),
    ("GET",    re.compile(r"^/api/vault-info$"),             _h_vault_info),
    ("POST",   re.compile(r"^/api/init$"),                   _h_init),
    ("POST",   re.compile(r"^/api/unlock$"),                 _h_unlock),
    ("POST",   re.compile(r"^/api/lock$"),                   _h_lock),
    ("GET",    re.compile(r"^/api/status$"),                 _h_status),
    ("GET",    re.compile(r"^/api/admins$"),                                     _h_list_admins),
    ("POST",   re.compile(r"^/api/admins$"),                                     _h_add_admin),
    ("POST",   re.compile(r"^/api/admins/([^/]+)/change-passphrase$"),           _h_change_admin_passphrase),
    ("DELETE", re.compile(r"^/api/admins/([^/]+)$"),                             _h_remove_admin),
    ("GET",    re.compile(r"^/api/clients$"),                _h_list_clients),
    ("POST",   re.compile(r"^/api/clients$"),                _h_add_client),
    # QR must come before the generic DELETE so GET .../qr is matched first
    ("GET",    re.compile(r"^/api/clients/([^/]+)/qr$"),     _h_client_qr),
    ("GET",    re.compile(r"^/api/clients/([^/]+)/config$"), _h_client_config),
    ("POST",   re.compile(r"^/api/clients/([^/]+)/rotate$"), _h_rotate_client_keys),
    ("POST",   re.compile(r"^/api/clients/([^/]+)/ttl$"),   _h_set_client_ttl),
    ("DELETE", re.compile(r"^/api/clients/([^/]+)$"),        _h_remove_client),
    ("POST",   re.compile(r"^/api/heartbeat/([^/]+)$"),      _h_heartbeat),
    ("GET",    re.compile(r"^/api/audit-log$"),              _h_audit_log),
    ("GET",    re.compile(r"^/api/session-summary$"),         _h_session_summary),
    ("GET",    re.compile(r"^/api/file-activity$"),           _h_file_activity),
    ("GET",    re.compile(r"^/api/security-status$"),        _h_security_status),
    ("POST",   re.compile(r"^/api/harden-server$"),          _h_harden_server),
    ("POST",   re.compile(r"^/api/change-passphrase$"),      _h_change_passphrase),
    ("POST",   re.compile(r"^/api/start$"),                  _h_start_server),
    ("POST",   re.compile(r"^/api/terminate$"),              _h_terminate),
    ("POST",   re.compile(r"^/api/fresh-start$"),            _h_fresh_start),
    ("POST",   re.compile(r"^/api/update-endpoint$"),        _h_update_endpoint),
    ("POST",   re.compile(r"^/api/rotate-server-keys$"),                    _h_rotate_server_keys),
    # Admin mode
    ("POST",   re.compile(r"^/api/admin/authenticate$"),                 _h_admin_authenticate),
    ("POST",   re.compile(r"^/api/admin/deactivate$"),                   _h_admin_deactivate_endpoint),
    ("GET",    re.compile(r"^/api/admin/status$"),                       _h_admin_status),
    ("POST",   re.compile(r"^/api/admin/exec$"),                         _h_admin_exec),
    ("GET",    re.compile(r"^/api/admin/services$"),                     _h_admin_services),
    ("POST",   re.compile(r"^/api/admin/services/([^/]+)/([^/]+)$"),    _h_admin_service_action),
    ("POST",   re.compile(r"^/api/admin/file/read$"),                    _h_admin_read_file),
    ("POST",   re.compile(r"^/api/admin/file/write$"),                   _h_admin_write_file),
    ("POST",   re.compile(r"^/api/set-pin$"),               _h_set_pin),
    ("POST",   re.compile(r"^/api/remove-pin$"),            _h_remove_pin),
    ("POST",   re.compile(r"^/api/unlock-pin$"),            _h_unlock_pin),
    ("GET",    re.compile(r"^/api/pin-info$"),              _h_pin_info),
    # TOTP 2FA
    ("POST",   re.compile(r"^/api/totp/enroll/begin$"),     _h_totp_enroll_begin),
    ("POST",   re.compile(r"^/api/totp/enroll/confirm$"),   _h_totp_enroll_confirm),
    ("POST",   re.compile(r"^/api/totp/disable$"),          _h_totp_disable),
    ("POST",   re.compile(r"^/api/totp/reset$"),            _h_totp_reset),
    ("POST",   re.compile(r"^/api/totp/verify-backup$"),    _h_totp_verify_backup),
    # DNS (7.4 split-DNS)
    ("GET",    re.compile(r"^/api/dns$"),                   _h_get_dns),
    ("POST",   re.compile(r"^/api/dns$"),                   _h_set_dns),
    ("POST",   re.compile(r"^/api/dns/([^/]+)$"),           _h_add_dns_mapping),
    ("DELETE", re.compile(r"^/api/dns/([^/]+)$"),           _h_remove_dns_mapping),
]

# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default access log
        pass

    def _cors(self) -> None:
        # Only allow requests from the same host — never wildcard.
        # The dashboard is served from the same origin so no CORS header
        # is strictly needed, but dev tools / local testing may use
        # 127.0.0.1 or localhost interchangeably.
        # When bound to 0.0.0.0 (headless/Pi), also allow the server's
        # actual IP so LAN browsers can reach the dashboard.
        origin = self.headers.get("Origin", "")
        _allowed = {"http://127.0.0.1", "http://localhost"}
        # Also allow the IP:port the client connected to (covers LAN access)
        host_header = self.headers.get("Host", "")
        if host_header:
            _allowed.add(f"http://{host_header.split(':')[0]}")
        if any(origin == a or origin.startswith(a + ":") for a in _allowed):
            self.send_header("Access-Control-Allow-Origin", origin)
        # No header at all for unknown origins — browser will block.
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise _ApiError("Invalid JSON in request body.", 400)

    def _send(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path = self.path.split("?")[0]
        for route_method, pattern, handler in _ROUTES:
            if route_method != method:
                continue
            m = pattern.match(path)
            if m:
                try:
                    self._send(handler(self, m.groups()))
                except _ApiError as exc:
                    self._send({"error": str(exc)}, exc.status)
                except Exception as exc:
                    import traceback
                    traceback.print_exc()
                    self._send({"error": f"Internal server error: {exc}"}, 500)
                return
        self._send({"error": "Not found"}, 404)

    def _serve_static(self, path: str) -> None:
        """Serve a file from the bundled React dist directory."""
        dist = _get_dist_dir()
        if dist is None:
            body = b"Dashboard not bundled. Run 'npm run build' in Dashboard/."
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        rel = path.lstrip("/")
        file_path = (dist / rel) if rel else (dist / "index.html")

        # SPA fallback: unknown paths (e.g. /clients, /about) → index.html
        if not file_path.exists() or file_path.is_dir():
            file_path = dist / "index.html"

        if not file_path.exists():
            self.send_response(404)
            self.end_headers()
            return

        data = file_path.read_bytes()
        suffix = file_path.suffix.lower()
        mime = _MIME.get(suffix, "application/octet-stream")
        # Long-lived cache for hashed assets; no-cache for index.html
        cache = "no-cache, no-store" if suffix == ".html" else "public, max-age=31536000, immutable"

        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        # API routes take priority; everything else is served as static frontend
        if self.path.split("?")[0].startswith("/api/") or self.path.split("?")[0] == "/api":
            self._dispatch("GET")
        else:
            self._serve_static(self.path.split("?")[0])

    def do_POST(self):   self._dispatch("POST")
    def do_DELETE(self): self._dispatch("DELETE")


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


_cleaned_up = False


def _cleanup_session(server: ThreadingHTTPServer) -> None:
    """Wipe vault state and shut down the HTTP server.

    Guarded by _cleaned_up flag to prevent double-cleanup when both
    atexit and signal handlers fire.
    """
    global _cleaned_up
    if _cleaned_up:
        return
    _cleaned_up = True
    _admin_deactivate()
    with _lock:
        if _session["passphrase"]:
            _session["passphrase"].wipe()
        _session.update(vault=None, passphrase=None, cache=None)
    try:
        from wireseal.security.audit import AuditLog
        AuditLog(_AUDIT_PATH).log("shutdown", {})
    except Exception:
        pass
    server.server_close()
    print("\n[wireseal] Server stopped. Vault state wiped.")


def serve(host: str = "127.0.0.1", port: int = 8080, gui: bool = True) -> None:
    """Start the WireSeal API server.

    gui=True  (default): opens a native pywebview desktop window.
    gui=False (headless): binds the server and blocks; no window opened.
    Falls back to the system browser if pywebview is unavailable.

    On Linux, if gui=True but no DISPLAY/WAYLAND_DISPLAY is set (headless
    server, SSH session, Raspberry Pi), automatically falls back to headless.
    """
    import threading
    import webbrowser

    # Auto-detect headless Linux (SSH, no display, Raspberry Pi, etc.)
    if gui and sys.platform == "linux":
        has_display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
        if not has_display:
            print("[wireseal] No display detected — switching to headless mode.")
            print(f"[wireseal] Open http://{host}:{port}/ in your browser.")
            gui = False

    global _cleaned_up, _server_start_time
    import time as _time
    _cleaned_up = False
    _server_start_time = _time.monotonic()

    server = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}/"

    # Register signal handlers for graceful shutdown (wipe secrets on exit)
    import atexit
    import signal as _signal
    atexit.register(lambda: _cleanup_session(server))

    def _signal_handler(signum, frame):
        _cleanup_session(server)
        sys.exit(0)

    _signal.signal(_signal.SIGTERM, _signal_handler)
    if hasattr(_signal, "SIGHUP"):
        _signal.signal(_signal.SIGHUP, _signal_handler)

    # In GUI mode on Windows (console=False binary), suppress prints to avoid
    # allocating a console window.  Headless mode keeps prints for terminal use.
    _quiet = gui and sys.platform == "win32"
    if not _quiet:
        print(f"[wireseal] Serving on {url}")

    if not gui:
        if not _quiet:
            print("[wireseal] Headless mode — press Ctrl+C to stop.")
        # Start TTL expiry watcher daemon thread (ZTNA-7.3)
        from wireseal.core.expiry import ExpiryWatcher
        _expiry_watcher = ExpiryWatcher(
            get_session=lambda: _session,
            session_lock=_lock,
            wg_iface=_WG_IFACE,
            audit_path=_AUDIT_PATH,
        )
        _expiry_watcher.start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            _cleanup_session(server)
        return

    # GUI mode: server runs in a daemon thread; pywebview owns the main thread.
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    # Start TTL expiry watcher daemon thread (ZTNA-7.3)
    from wireseal.core.expiry import ExpiryWatcher
    _expiry_watcher = ExpiryWatcher(
        get_session=lambda: _session,
        session_lock=_lock,
        wg_iface=_WG_IFACE,
        audit_path=_AUDIT_PATH,
    )
    _expiry_watcher.start()

    # Auto-lock daemon: wipes vault after SESSION_TIMEOUT seconds of inactivity
    def _auto_lock_loop():
        global _last_activity
        import time as _t
        while True:
            _t.sleep(60)
            with _lock:
                if _session["vault"] is None:
                    continue
                if _last_activity and (_t.monotonic() - _last_activity > _SESSION_TIMEOUT):
                    if _session["passphrase"]:
                        _session["passphrase"].wipe()
                    _session.update(vault=None, passphrase=None, cache=None)
            # Audit log OUTSIDE the lock to avoid deadlock
            if _last_activity and (_t.monotonic() - _last_activity > _SESSION_TIMEOUT + 60):
                continue  # Already logged
            try:
                from wireseal.security.audit import AuditLog
                AuditLog(_AUDIT_PATH).log("auto-lock", {"reason": "inactivity"})
            except Exception:
                pass
            if not _quiet:
                print("[wireseal] Vault auto-locked after inactivity.")

    _autolock_thread = threading.Thread(target=_auto_lock_loop, daemon=True)
    _autolock_thread.start()

    # Start system tray icon (best-effort — runs even if pywebview fails)
    _tray_thread = None
    try:
        from wireseal.tray import run_tray

        def _tray_stop_server() -> None:
            try:
                from wireseal.platform.detect import get_adapter
                adapter = get_adapter()
                adapter.wg_down("wg0")
            except Exception:
                pass

        def _tray_quit() -> None:
            server.shutdown()

        def _tray_status() -> str:
            try:
                from wireseal.platform.detect import get_adapter
                adapter = get_adapter()
                peers = adapter.wg_show("wg0")
                if peers is None:
                    return "Tunnel: stopped"
                return f"Tunnel: running ({len(peers)} peers)"
            except Exception:
                return "Tunnel: unknown"

        _tray_thread = run_tray(
            dashboard_url=url,
            on_stop=_tray_stop_server,
            on_quit=_tray_quit,
            status_getter=_tray_status,
        )
    except Exception:
        pass  # Tray is optional — never block startup

    try:
        # On Linux, ensure GI_TYPELIB_PATH includes system typelib dirs.
        # PyInstaller's runtime hook sets it to only the bundled dir; append system paths.
        if sys.platform == "linux":
            _sys_typelib_dirs = [
                "/usr/lib/girepository-1.0",
                "/usr/lib64/girepository-1.0",
                "/usr/lib/x86_64-linux-gnu/girepository-1.0",
                "/usr/lib/aarch64-linux-gnu/girepository-1.0",
                "/usr/lib/arm-linux-gnueabihf/girepository-1.0",
            ]
            existing = os.environ.get("GI_TYPELIB_PATH", "")
            extra = [d for d in _sys_typelib_dirs if os.path.isdir(d) and d not in existing]
            if extra:
                parts = ([existing] if existing else []) + extra
                os.environ["GI_TYPELIB_PATH"] = os.pathsep.join(parts)

        import webview  # pywebview — EdgeChromium on Windows, WKWebView on macOS, WebKitGTK on Linux
        window = webview.create_window(
            "WireSeal", url, width=1200, height=800, min_size=(900, 600),
        )
        webview.start()  # blocks until the native window is closed
    except ImportError:
        if not _quiet:
            print("[wireseal] Native window not available — falling back to system browser.")
            print("[wireseal] Press Ctrl+C to stop.")
        webbrowser.open(url)
        try:
            server_thread.join()
        except KeyboardInterrupt:
            pass
    except Exception as exc:
        if not _quiet:
            print(f"[wireseal] GUI failed ({exc}) — falling back to system browser.")
            if sys.platform == "linux":
                print("[wireseal] Install GUI dependencies for a native window:")
                print("[wireseal]   Arch:   sudo pacman -S python-gobject webkit2gtk")
                print("[wireseal]   Debian: sudo apt install python3-gi gir1.2-webkit2-4.1")
                print("[wireseal]   Fedora: sudo dnf install python3-gobject webkit2gtk4.1")
            print("[wireseal] Press Ctrl+C to stop.")
        webbrowser.open(url)
        try:
            server_thread.join()
        except KeyboardInterrupt:
            pass
    finally:
        _cleanup_session(server)
