"""WireSeal REST API server â€” stdlib only, no extra dependencies.

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
import logging
import os
import shutil

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
import re
import subprocess
import sys
import threading
import time as _time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from wireseal.config.settings import (
    ADMIN_MAX_FAILS as _ADMIN_MAX_FAILS_CFG,
    ADMIN_TIMEOUT as _ADMIN_TIMEOUT_CFG,
    CLIENT_CREATION_LIMIT as _CLIENT_CREATION_LIMIT_CFG,
    FRESH_START_TTL_SECONDS as _FRESH_START_TTL_SECONDS_CFG,
    HEARTBEAT_MIN_INTERVAL as _HEARTBEAT_MIN_INTERVAL_CFG,
    MAX_ADMIN_READ_SIZE as _MAX_ADMIN_READ_SIZE_CFG,
    MAX_BODY_SIZE as _MAX_BODY_SIZE_CFG,
    PIN_MAX_ATTEMPTS as _PIN_MAX_ATTEMPTS_CFG,
    RATE_LIMIT_10 as _RATE_LIMIT_10_CFG,
    RATE_LIMIT_20 as _RATE_LIMIT_20_CFG,
    RATE_LIMIT_5 as _RATE_LIMIT_5_CFG,
    SESSION_TIMEOUT as _SESSION_TIMEOUT_CFG,
    SFTP_MAX_BYTES as _SFTP_MAX_BYTES_CFG,
    SFTP_MIN_INTERVAL as _SFTP_MIN_INTERVAL_CFG,
    TOTP_BACKUP_MAX as _TOTP_BACKUP_MAX_CFG,
    TOTP_BACKUP_WINDOW as _TOTP_BACKUP_WINDOW_CFG,
    TOTP_LOCKOUT_SECS as _TOTP_LOCKOUT_SECS_CFG,
    TOTP_MAX_FAILS as _TOTP_MAX_FAILS_CFG,
    TOTP_SESSION_HOURS as _TOTP_SESSION_HOURS_CFG,
    TOTP_SESSION_MAX as _TOTP_SESSION_MAX_CFG,
    TOTP_USED_CODE_TTL as _TOTP_USED_CODE_TTL_CFG,
    TOTP_WINDOW as _TOTP_WINDOW_CFG,
    UNLOCK_MAX as _UNLOCK_MAX_CFG,
    UNLOCK_WINDOW as _UNLOCK_WINDOW_CFG,
    WG_IFACE as _WG_IFACE_CFG,
)

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
    1. PyInstaller one-file bundle  â†’ sys._MEIPASS / dashboard
    2. Development checkout         â†’ <repo root> / Dashboard / dist
    """
    # PyInstaller sets _MEIPASS to the temp extraction directory
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        d = Path(meipass) / "dashboard"
        if d.is_dir():
            return d

    # Development: api.py lives at src/wireseal/api.py â†’ go up 3 levels
    dev = Path(__file__).parent.parent.parent.parent / "Dashboard" / "dist"
    if dev.is_dir():
        return dev

    return None

# Lazy TOTP import â€” kept here so handlers can reference after module load.
# The actual import happens inside handlers; this symbol is set at first use.
from wireseal.security.totp import (  # noqa: E402 â€” placed after stdlib imports
    generate_totp_secret,
    totp_uri,
    verify_totp,
    generate_backup_codes,
    hash_backup_code,
    verify_backup_code,
    secret_to_b32,
    b32_to_secret,
)
from wireseal.backup.manager import BackupManager as _BackupManager
from wireseal.security.exceptions import VaultTamperedError

# Module-level BackupManager singleton (stateless, safe to share)
_backup_manager = _BackupManager()

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


def _wipe_session_on_fork() -> None:
    with _lock:
        vault = _session.get("vault")
        if vault is not None:
            try:
                if hasattr(vault, "_session_master_key"):
                    vault._session_master_key = None
            except Exception as exc:
                logging.getLogger("wireseal.security").error("Failed to wipe master key on fork: %s", exc)
        if _session["passphrase"]:
            try:
                _session["passphrase"].wipe()
            except Exception as exc:
                logging.getLogger("wireseal.security").error("Failed to wipe passphrase on fork: %s", exc)
        _session.update(vault=None, passphrase=None, cache=None,
                        admin_id=None, admin_role=None)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_wipe_session_on_fork)


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

def override_vault_dir(path: Path) -> None:
    """Override vault directory at startup (used by --vault-dir service flag)."""
    global _VAULT_DIR, _VAULT_PATH, _AUDIT_PATH, _PIN_PATH
    _VAULT_DIR  = path
    _VAULT_PATH = _VAULT_DIR / "vault.enc"
    _AUDIT_PATH = _VAULT_DIR / "audit.log"
    _PIN_PATH   = _VAULT_DIR / "pin.enc"
_WG_IFACE   = _WG_IFACE_CFG

# SEC-FIX-1: SSH target allowlist â€” prevents admins from proxying to arbitrary
# hosts. The allowlist is stored in _VAULT_DIR so it lives alongside the vault
# and is writable only by the process owner.
_SSH_TARGETS_CONFIG_PATH = _VAULT_DIR / "ssh_targets.json"
# SSH keys stored in vault state._data["ssh_keys"] via client.ssh_keys module

# Regex that a valid SSH target hostname must match (no wildcards, no slashes).
_SSH_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')

# PIN-based quick unlock â€” encrypts the passphrase with a PIN-derived key.
# After 5 wrong attempts the PIN file is wiped (must use full passphrase).
# SEC-014 / SEC-023: failures are tracked per-IP (not globally) and
# check-then-increment is atomic under _lock so two concurrent wrong PINs
# from different IPs can't both slip past the 5-attempt threshold.
_PIN_MAX_ATTEMPTS = _PIN_MAX_ATTEMPTS_CFG
_pin_fail_count   = 0  # legacy counter, retained for backward-compat tests
_pin_fail_by_ip: dict[str, int] = {}

# ---------------------------------------------------------------------------
# Rate limiting for /api/unlock â€” prevents brute-force passphrase guessing.
# Tracks failed attempts per IP in a sliding window. After _UNLOCK_MAX
# failures within _UNLOCK_WINDOW seconds, returns 429 Too Many Requests.
# ---------------------------------------------------------------------------
_unlock_attempts: dict[str, list[float]] = {}  # ip -> list of failure timestamps
_UNLOCK_WINDOW = _UNLOCK_WINDOW_CFG   # 5-minute sliding window
_UNLOCK_MAX    = _UNLOCK_MAX_CFG     # max failures per window

# Rate-limit heartbeat resets: maps client_name â†’ last_reset_timestamp
_heartbeat_cooldown: dict[str, float] = {}
_HEARTBEAT_MIN_INTERVAL = _HEARTBEAT_MIN_INTERVAL_CFG

# M-20: Rate limit client creation — max 50 per hour per admin session
_CLIENT_CREATION_LIMIT = _CLIENT_CREATION_LIMIT_CFG
_CLIENT_CREATIONS: dict[str, list[float]] = {}  # admin_id -> [timestamps]

# TOTP anti-replay: maps admin_id â†’ set of recently-used 6-digit codes.
# Guarded by _lock. Persisted to vault for cross-restart protection.
_totp_used_codes: dict[str, set[str]] = {}

# TOTP session validity: maps admin_id â†’ monotonic timestamp of last TOTP
# verification.  While within _TOTP_SESSION_HOURS, sensitive actions skip
# re-prompting for a TOTP code (TOTP-plan Â§8.2).  Guarded by _lock.
# Cleared on vault lock.
_TOTP_SESSION_HOURS: int = _TOTP_SESSION_HOURS_CFG
_totp_session_verified: dict[str, float] = {}

# â”€â”€ TOTP used_codes persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_TOTP_USED_CODE_TTL = _TOTP_USED_CODE_TTL_CFG  # seconds â€” prune codes older than this


def _persist_totp_used_codes(admin_id: str) -> None:
    """Save _totp_used_codes[admin_id] into the vault for restart durability.

    Stores ``[code, unix_epoch_seconds]`` pairs so codes can be pruned by age
    on reload.  Silently no-ops when the vault isn't open yet or the set is
    empty after pruning.
    """
    vault = _session.get("vault")
    passphrase = _session.get("passphrase")
    if not vault or not passphrase:
        return
    import time as _time
    now = _time.time()
    cutoff = now - _TOTP_USED_CODE_TTL
    with _lock:
        raw = _totp_used_codes.get(admin_id, set())
        codes_with_ts = [[c, now] for c in raw]
        # Also prune in-memory set while we have the lock
        _totp_used_codes[admin_id] = {c for c in raw}
    if not codes_with_ts:
        return
    try:
        with vault.open(passphrase, admin_id=admin_id) as state:
            admins_dict = state.data.setdefault("admins", {})
            admin_data = admins_dict.setdefault(admin_id, {})
            admin_data["totp_used_codes"] = codes_with_ts
            vault.save(state, passphrase)
    except Exception:
        pass  # best-effort persistence


def _load_totp_used_codes(state_data: dict, admin_id: str) -> set[str]:
    """Load and time-prune persisted used_codes from vault into memory.

    Codes older than ``_TOTP_USED_CODE_TTL`` seconds are discarded on load
    so they don't accumulate across restarts.
    """
    admins = state_data.get("admins", {})
    admin_data = admins.get(admin_id, {})
    raw = admin_data.get("totp_used_codes", [])
    import time as _time
    now = _time.time()
    cutoff = now - _TOTP_USED_CODE_TTL
    fresh: set[str] = set()
    for item in raw:
        if isinstance(item, list) and len(item) == 2:
            code, ts = item
            if isinstance(code, str) and code.isdigit() and len(code) == 6 and isinstance(ts, (int, float)):
                if ts >= cutoff:
                    fresh.add(code)
        elif isinstance(item, str) and item.isdigit() and len(item) == 6:
            fresh.add(item)
    with _lock:
        _totp_used_codes[admin_id] = fresh
    return fresh

# Maps peer public_key â†’ last_handshake_seconds from previous _h_status call.
# Used to detect new handshake events for the audit log (DASH-06).
_peer_handshake_cache: dict[str, int] = {}

# SFTP per-session rate limiting: 50ms min interval, 50MB/min transfer
_sftp_rate_last: dict[str, float] = {}
_sftp_rate_bytes: dict[str, float] = {}
_SFTP_MIN_INTERVAL = _SFTP_MIN_INTERVAL_CFG
_SFTP_MAX_BYTES = _SFTP_MAX_BYTES_CFG


# ---------------------------------------------------------------------------
# Security hardening constants & helpers (SEC-002, 004, 005, 007, 008, 010, 018)
# ---------------------------------------------------------------------------

# SEC-004: hard cap on request body size â€” prevents OOM DoS via large
# Content-Length. 1 MiB is 16x the largest legitimate body (a WireGuard
# config import of ~40 KiB) and comfortably fits all vault backup payloads.
_MAX_BODY_SIZE = _MAX_BODY_SIZE_CFG

# SEC-002: fresh-start challenge lives on the filesystem inside _VAULT_DIR.
# Possession of the token proves local filesystem read access â€” a browser
# CSRF attack cannot read it. Token rotates on every challenge request and
# is consumed (deleted) on successful fresh-start.
_FRESH_START_CHALLENGE_NAME = ".reset-challenge"
_FRESH_START_TTL_SECONDS    = _FRESH_START_TTL_SECONDS_CFG

# SEC-008: admin/file/* may only touch files under these roots, resolved
# once at import. Callers submit a path; we verify it resolves inside one
# of these trees (after following symlinks) before shelling out to cat/tee.
def _admin_file_roots() -> tuple[Path, ...]:
    """Return the allowlisted root directories for admin file read/write."""
    roots: list[Path] = [_VAULT_DIR]
    if sys.platform == "linux":
        roots.extend([
            Path("/etc/wireguard"),
            Path("/etc/nftables.d"),
            Path("/var/lib/wireseal"),
            Path("/var/log/wireseal"),
        ])
    elif sys.platform == "darwin":
        roots.extend([
            Path("/usr/local/etc/wireguard"),
            Path("/opt/homebrew/etc/wireguard"),
            Path("/Library/Application Support/WireSeal"),
        ])
    elif sys.platform == "win32":
        prog = os.environ.get("ProgramData", r"C:\ProgramData")
        roots.append(Path(prog) / "WireGuard")
        roots.append(Path(prog) / "WireSeal")
    # Resolve only ones that exist â€” non-existent roots can't be traversed to.
    resolved: list[Path] = []
    for r in roots:
        try:
            if r.exists():
                resolved.append(r.resolve())
        except OSError:
            pass
    return tuple(resolved)


_ADMIN_FILE_ROOTS: tuple[Path, ...] = _admin_file_roots()

# SEC-008: cap admin read size to prevent exfiltrating huge files in one shot.
_MAX_ADMIN_READ_SIZE = _MAX_ADMIN_READ_SIZE_CFG


def _validate_admin_path(path_str: str) -> Path:
    """Resolve ``path_str`` and ensure it lives under an allowlisted root.

    Raises _ApiError(403) if the path escapes the allowlist. Raises
    _ApiError(400) for syntactic issues (empty, relative, .. components).
    """
    if not path_str or not isinstance(path_str, str):
        raise _ApiError("path is required", 400)
    path_str = path_str.strip()
    if not path_str:
        raise _ApiError("path is required", 400)
    p = Path(path_str)
    if not p.is_absolute():
        raise _ApiError("path must be absolute", 400)
    # Reject literal traversal components pre-resolve so the error is clear
    # even when the resolved path happens to land inside an allowed root.
    if any(part == ".." for part in p.parts):
        raise _ApiError("path traversal not allowed", 400)
    try:
        resolved = p.resolve(strict=False)
    except (OSError, ValueError):
        raise _ApiError("invalid path", 400)
    if not _ADMIN_FILE_ROOTS:
        # No allowlist configured â€” refuse rather than fail open.
        raise _ApiError("admin file access is disabled on this platform", 403)
    for allowed in _ADMIN_FILE_ROOTS:
        try:
            resolved.relative_to(allowed)
            return resolved
        except ValueError:
            continue
    allowed_display = ", ".join(str(r) for r in _ADMIN_FILE_ROOTS)
    raise _ApiError(
        f"path outside allowlist. Permitted roots: {allowed_display}",
        403,
    )


def _fresh_start_challenge_path() -> Path:
    """Path to the fresh-start challenge file (inside the vault dir)."""
    return _VAULT_DIR / _FRESH_START_CHALLENGE_NAME


def _create_fresh_start_challenge() -> str:
    """Generate and persist a fresh-start challenge token.

    The token is written to ``_VAULT_DIR/.reset-challenge`` with mode 0o600
    and an embedded expiry timestamp. The caller must read this file (proving
    local filesystem access) to obtain the token value they submit to
    ``/api/fresh-start``. A browser CSRF cannot read local files, so this
    gates destructive reset behind a capability the attacker lacks.
    """
    import secrets as _secrets
    import time as _time
    token   = _secrets.token_hex(32)  # 64 hex chars, 256 bits
    expires = int(_time.time()) + _FRESH_START_TTL_SECONDS
    payload = f"{token}\n{expires}\n".encode("ascii")
    _VAULT_DIR.mkdir(parents=True, exist_ok=True)
    path = _fresh_start_challenge_path()
    # Atomic write with strict mode so a racing read from another process
    # can't observe a partial write.
    from wireseal.security.vault import atomic_write
    atomic_write(path, payload, mode=0o600)
    return token


def _consume_fresh_start_challenge(submitted: str) -> None:
    """Validate submitted token against on-disk challenge. Consumes it on success.

    Raises _ApiError(400/401/410) on invalid/expired/missing tokens. On
    success, deletes the challenge file so each token is strictly single-use.
    """
    import hmac as _hmac
    import time as _time
    if not submitted or not isinstance(submitted, str):
        raise _ApiError("challenge_token is required", 400)
    path = _fresh_start_challenge_path()
    if not path.exists():
        raise _ApiError(
            "No active fresh-start challenge. "
            "POST /api/fresh-start/challenge first, then read the token file.",
            410,
        )
    try:
        raw = path.read_text(encoding="ascii")
    except OSError:
        raise _ApiError("Could not read challenge file.", 500)
    lines = raw.strip().split("\n")
    if len(lines) != 2:
        path.unlink(missing_ok=True)
        raise _ApiError("Corrupt challenge file â€” regenerate.", 410)
    expected_token, expires_str = lines
    try:
        expires = int(expires_str)
    except ValueError:
        path.unlink(missing_ok=True)
        raise _ApiError("Corrupt challenge file â€” regenerate.", 410)
    if _time.time() > expires:
        path.unlink(missing_ok=True)
        raise _ApiError("Fresh-start challenge expired. Request a new one.", 410)
    # Constant-time compare â€” avoid timing leaks on token prefix matches.
    if not _hmac.compare_digest(submitted.strip(), expected_token):
        raise _ApiError("Invalid challenge token.", 401)
    # Consume: delete so the same token can't be replayed.
    path.unlink(missing_ok=True)


def _require_same_origin(req: "_Handler") -> None:
    """Reject requests whose Origin header is not a local loopback origin.

    Applied to destructive state-changing endpoints as defense-in-depth
    against browser-initiated CSRF. Requests without an Origin header
    (curl, native clients) are allowed â€” only explicit cross-origin is
    blocked.
    """
    origin = req.headers.get("Origin", "")
    if not origin:
        return  # Non-browser clients don't send Origin
    # Accept only loopback origins the dashboard itself is served from.
    allowed_prefixes = (
        "http://127.0.0.1", "http://localhost",
        "https://127.0.0.1", "https://localhost",
    )
    if not any(origin == p or origin.startswith(p + ":") for p in allowed_prefixes):
        raise _ApiError("Cross-origin request rejected.", 403)


def _check_unlock_rate_limit(ip: str) -> None:
    """Raise 429 if this IP has exceeded the unlock attempt limit (legacy)."""
    import time as _time
    now = _time.time()
    with _lock:
        attempts = _unlock_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < _UNLOCK_WINDOW]
        _unlock_attempts[ip] = attempts
        if len(attempts) >= _UNLOCK_MAX:
            from wireseal.security.audit import AuditLog
            AuditLog(_AUDIT_PATH).log("unlock-ratelimited", {"ip": ip}, actor="system")
            raise _ApiError("Too many unlock attempts. Try again later.", 429)


def _record_unlock_failure(ip: str) -> None:
    """Record a failed unlock attempt for rate limiting."""
    import time as _time
    with _lock:
        _unlock_attempts.setdefault(ip, []).append(_time.time())
    from wireseal.security.audit import AuditLog
    AuditLog(_AUDIT_PATH).log("unlock-failed", {"ip": ip}, actor="system")


def _clear_unlock_failures(ip: str) -> None:
    """Clear failed attempts after a successful unlock."""
    with _lock:
        _unlock_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# Unified exponential-backoff rate limiting â€” per-IP per-action.
# Thresholds: 5 failures â†’ 30s, 10 â†’ 5min, 20 â†’ 30min lockout.
# ---------------------------------------------------------------------------
_RATE_LIMIT_BACKOFF: dict[tuple[str, str], dict] = {}
_RATE_LIMIT_5  = _RATE_LIMIT_5_CFG
_RATE_LIMIT_10 = _RATE_LIMIT_10_CFG
_RATE_LIMIT_20 = _RATE_LIMIT_20_CFG


def _check_rate_limit(ip: str, action: str) -> bool:
    import time as _time
    with _lock:
        rec = _RATE_LIMIT_BACKOFF.get((ip, action))
        if rec and _time.time() < rec.get("lockout_until", 0):
            return True
        return False


def _record_rate_limit_failure(ip: str, action: str) -> None:
    import time as _time
    now = _time.time()
    with _lock:
        key = (ip, action)
        rec = _RATE_LIMIT_BACKOFF.setdefault(key, {"failures": 0, "lockout_until": 0})
        rec["failures"] += 1
        f = rec["failures"]
        if f >= 20:
            rec["lockout_until"] = now + _RATE_LIMIT_20
        elif f >= 10:
            rec["lockout_until"] = now + _RATE_LIMIT_10
        elif f >= 5:
            rec["lockout_until"] = now + _RATE_LIMIT_5


def _clear_rate_limit(ip: str, action: str) -> None:
    with _lock:
        _RATE_LIMIT_BACKOFF.pop((ip, action), None)


# ---------------------------------------------------------------------------
# Admin mode â€” full system access via verified root/sudo credentials.
# Activated by POST /api/admin/authenticate with the root password.
# Expires after _ADMIN_TIMEOUT seconds or on vault lock / shutdown.
# ---------------------------------------------------------------------------

_admin_session: dict = {
    "active":     False,
    "password":   None,   # SecretBytes â€” cached sudo password
    "expires_at": None,   # monotonic clock timestamp
}
_ADMIN_TIMEOUT   = _ADMIN_TIMEOUT_CFG
_ADMIN_MAX_FAILS = _ADMIN_MAX_FAILS_CFG
_admin_lock      = threading.Lock()
_admin_attempts: dict[str, list[float]] = {}

# SEC-016: serialise /api/init concurrency so two racing POSTs cannot both
# observe an absent vault and both call Vault.create â€” the second would
# silently discard the first caller's passphrase, leaving that session
# holding a passphrase that no longer decrypts the vault.
_init_lock = threading.Lock()


def _check_admin_rate_limit(ip: str) -> None:
    """Raise 429 if this IP has exceeded admin authentication attempts."""
    import time as _time
    now = _time.time()
    with _admin_lock:
        attempts = [t for t in _admin_attempts.get(ip, []) if now - t < _UNLOCK_WINDOW]
        _admin_attempts[ip] = attempts
        if len(attempts) >= _ADMIN_MAX_FAILS:
            from wireseal.security.audit import AuditLog
            AuditLog(_AUDIT_PATH).log("admin-auth-ratelimited", {"ip": ip}, actor="system")
            raise _ApiError("Too many admin authentication attempts. Try again later.", 429)


def _record_admin_failure(ip: str) -> None:
    import time as _time
    with _admin_lock:
        _admin_attempts.setdefault(ip, []).append(_time.time())


def _clear_admin_failures(ip: str) -> None:
    with _admin_lock:
        _admin_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# TOTP-specific rate limiting (TOTP-plan Â§6.4, Â§9.2)
# ---------------------------------------------------------------------------
_TOTP_WINDOW: int = _TOTP_WINDOW_CFG
_TOTP_MAX_FAILS: int = _TOTP_MAX_FAILS_CFG
_TOTP_LOCKOUT_SECS: int = _TOTP_LOCKOUT_SECS_CFG
_TOTP_SESSION_MAX: int = _TOTP_SESSION_MAX_CFG
_TOTP_BACKUP_WINDOW: int = _TOTP_BACKUP_WINDOW_CFG
_TOTP_BACKUP_MAX: int = _TOTP_BACKUP_MAX_CFG

import threading as _threading
_totp_rl_lock = _threading.Lock()
# {admin_id: {"attempts": [timestamps], "lockout_until": float, "session_count": int}}
_totp_attempts: dict[str, dict] = {}
# {admin_id: [timestamps]}
_totp_backup_attempts: dict[str, list[float]] = {}


def _check_totp_rate_limit(admin_id: str) -> None:
    """Raise 429 if TOTP rate limit exceeded for this admin."""
    import time as _time
    now = _time.time()
    with _totp_rl_lock:
        rec = _totp_attempts.get(admin_id, {})
        # Check lockout
        lockout_until = rec.get("lockout_until", 0)
        if now < lockout_until:
            raise _ApiError(
                f"Too many failed TOTP attempts. Wait {int(lockout_until - now)}s.", 429
            )
        # Check session max
        if rec.get("session_count", 0) >= _TOTP_SESSION_MAX:
            raise _ApiError("Maximum TOTP attempts for this session exceeded.", 429)


def _record_totp_failure(admin_id: str) -> None:
    """Record a failed TOTP attempt and apply lockout if threshold hit."""
    import time as _time
    now = _time.time()
    with _totp_rl_lock:
        rec = _totp_attempts.setdefault(
            admin_id, {"attempts": [], "lockout_until": 0, "session_count": 0}
        )
        rec["session_count"] = rec.get("session_count", 0) + 1
        attempts = rec["attempts"]
        attempts.append(now)
        # Trim to window
        cutoff = now - _TOTP_WINDOW
        rec["attempts"] = [t for t in attempts if t > cutoff]
        if len(rec["attempts"]) >= _TOTP_MAX_FAILS:
            rec["lockout_until"] = now + _TOTP_LOCKOUT_SECS
            from wireseal.security.audit import AuditLog
            AuditLog(_AUDIT_PATH).log(
                "totp-ratelimited", {"admin_id": admin_id}, actor="system"
            )


def _clear_totp_failures(admin_id: str) -> None:
    with _totp_rl_lock:
        _totp_attempts.pop(admin_id, None)


def _check_totp_backup_rate_limit(admin_id: str) -> None:
    """Raise 429 if backup code rate limit exceeded."""
    import time as _time
    now = _time.time()
    with _totp_rl_lock:
        attempts = _totp_backup_attempts.get(admin_id, [])
        cutoff = now - _TOTP_BACKUP_WINDOW
        recent = [t for t in attempts if t > cutoff]
        if len(recent) >= _TOTP_BACKUP_MAX:
            raise _ApiError(
                "Too many backup code attempts. Wait 5 minutes.", 429
            )


def _record_totp_backup_failure(admin_id: str) -> None:
    import time as _time
    with _totp_rl_lock:
        _totp_backup_attempts.setdefault(admin_id, []).append(_time.time())


def _clear_totp_backup_failures(admin_id: str) -> None:
    with _totp_rl_lock:
        _totp_backup_attempts.pop(admin_id, None)


def _verify_root_password(password: str) -> bool:
    """Return True if the given password proves admin authority.

    SEC-006 fix: when the WireSeal process is already running as root (or
    elevated on Windows), we no longer accept an empty/arbitrary password.
    Instead, the caller must re-present the current vault passphrase â€”
    proving they still hold the credential that decrypted the vault, not
    just that the process is elevated. This stops a browser CSRF or a
    co-resident unprivileged process from activating admin mode when the
    vault happens to be unlocked.

    Non-root processes continue to validate against the sudo password.
    """
    if not password:
        return False  # SEC-006: reject empty regardless of platform
    already_root = (sys.platform == "win32") or (os.geteuid() == 0)
    if already_root:
        # Require the vault passphrase as the proof-of-authority.
        with _lock:
            vault_pass = _session.get("passphrase")
        if vault_pass is None:
            return False  # Vault is locked â€” no reference secret to compare against
        try:
            import hmac as _hmac
            expected = bytes(vault_pass.expose_secret())
            submitted = password.encode("utf-8")
            return _hmac.compare_digest(expected, submitted)
        except Exception:
            return False
    # Non-root: validate against sudo.
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
            except Exception as exc:
                logging.getLogger("wireseal.security").error("Failed to wipe admin password on deactivate: %s", exc)
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


def _resolve_wg_tool(tool: str) -> str:
    """Resolve wg/wg-quick to absolute path, probing fallback locations.

    On Linux/macOS, systemd services and launchd agents have minimal PATH
    that may exclude /usr/sbin or /opt/homebrew/bin where WireGuard tools
    are installed.
    """
    found = shutil.which(tool)
    if found:
        return found
    if sys.platform == "darwin":
        fallbacks = ["/opt/homebrew/bin", "/usr/local/bin"]
    else:
        fallbacks = ["/usr/sbin", "/usr/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]
    for d in fallbacks:
        candidate = os.path.join(d, tool)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return tool  # bare name — let subprocess raise FileNotFoundError


def _require_admin_role() -> None:
    """Require admin or owner role for the current session (write operations).

    Raises 403 if the session role is ``readonly``.
    """
    with _lock:
        role = _session.get("admin_role", "owner")
    if role == "readonly":
        raise _ApiError("Admin privileges required for this operation.", 403)


def _require_unlocked() -> None:
    """SEC-009: require vault to be unlocked."""
    if _session["vault"] is None:
        raise _ApiError("Vault is locked.", 401)
    _last_activity[0] = _time.monotonic()


def _require_server_mode() -> None:
    """Reject the request if the current vault is in client mode.

    Server-only endpoints (tunnel start/stop, add/remove client, server-key
    rotation, status) must never execute against a client vault â€” the client
    vault has no server keypair, no IP pool, and no adapter state.
    """
    cache = _session.get("cache")
    if cache is not None and cache.get("mode") == "client":
        raise _ApiError(
            "This operation is not available in client mode.", 409
        )


def _require_client_mode() -> None:
    """Reject the request if the current vault is in server mode.

    Client-only endpoints (import/list/update/delete imported configs,
    bring up/down the wg-client interface) must never execute against a
    server vault â€” the server vault has no client_configs and `wg-client`
    would conflict with the server's wg0 interface.
    """
    cache = _session.get("cache")
    if cache is not None and cache.get("mode") == "server":
        raise _ApiError(
            "This operation is not available in server mode. "
            "Server and client roles are mutually exclusive on a single device.",
            409,
        )


def _require_confirmation(body: dict, allow_session_skip: bool = False) -> None:
    """Verify TOTP or passphrase confirmation for sensitive actions.

    Checks in order:
    1. If ``allow_session_skip`` is True and a TOTP session is still valid â€” skip.
    2. If admin has TOTP enrolled and body contains ``totp_code`` â€” verify it.
    3. If body contains ``confirm_passphrase`` â€” verify against vault.
    4. Otherwise raise 401.

    Irreversible operations (passphrase change, admin add/remove, key rotation,
    uninstall, TOTP disable/reset, TOTP re-enrollment) MUST NOT set
    ``allow_session_skip`` â€” they require fresh credentials every call.
    """
    _require_unlocked()
    with _lock:
        admin_id = _session.get("admin_id", "owner")
        cache = _session.get("cache") or {}
        vault = _session["vault"]
        passphrase = _session["passphrase"]

    admins = cache.get("admins", {})
    admin = admins.get(admin_id, {})
    totp_b32 = admin.get("totp_secret_b32")

    totp_code = body.get("totp_code")
    confirm_pass = body.get("confirm_passphrase")

    # Path 0: TOTP session still valid â€” skip re-prompt
    # Only allowed for low-risk reversible operations (client management).
    if allow_session_skip and totp_b32 is not None:
        import time as _time
        with _lock:
            verified_at = _totp_session_verified.get(admin_id)
        if verified_at is not None:
            elapsed_h = (_time.monotonic() - verified_at) / 3600
            if elapsed_h < _TOTP_SESSION_HOURS:
                return  # still within TOTP session window

    # Path 1: TOTP verification (preferred when enrolled)
    if totp_b32 is not None and totp_code:
        _check_totp_rate_limit(admin_id)
        from wireseal.security.totp import verify_totp, b32_to_secret
        from wireseal.security.secret_types import SecretBytes
        # SEC-CC-02: totp_secret_b32 is SecretBytes after _wrap_secrets;
        # unwrap to str, then decode base32 to raw secret bytes.
        if isinstance(totp_b32, SecretBytes):
            totp_b32_str = bytes(totp_b32.expose_secret()).decode("utf-8")
        else:
            totp_b32_str = str(totp_b32)
        secret_raw = b32_to_secret(totp_b32_str)
        with _lock:
            used_set = _totp_used_codes.setdefault(admin_id, set())
            ok = verify_totp(secret_raw, str(totp_code), used_codes=used_set)
        if not ok:
            from wireseal.security.audit import AuditLog
            AuditLog(_AUDIT_PATH).log("totp-failed", {"admin_id": admin_id}, actor=admin_id)
            _record_totp_failure(admin_id)
            raise _ApiError("Invalid TOTP code.", 401)
        import time as _time
        with _lock:
            _totp_session_verified[admin_id] = _time.monotonic()
        _persist_totp_used_codes(admin_id)
        return

    # Path 2: Passphrase re-entry
    if confirm_pass:
        from wireseal.security.secret_types import SecretBytes
        test_pass = SecretBytes(bytearray(confirm_pass.encode()))
        try:
            with vault.open(test_pass, admin_id=admin_id) as _st:
                pass  # passphrase valid
        except Exception:
            test_pass.wipe()
            raise _ApiError("Incorrect passphrase.", 401)
        test_pass.wipe()
        return

    # Path 3: If TOTP enrolled but no code provided
    if totp_b32 is not None:
        raise _ApiError("totp_code required for this action.", 401)

    raise _ApiError(
        "Confirmation required. Provide totp_code or confirm_passphrase.", 401
    )


def _require_totp_for_reveal(req: "_Handler") -> None:
    """Require TOTP verification before revealing client config/QR.

    If the current admin has TOTP enrolled, reads ``totp_code`` from the
    request body (POST) or query string (GET) and verifies it.
    Raises 401 if the code is missing or wrong.
    If the admin does NOT have TOTP enrolled, this is a no-op.
    """
    _require_unlocked()
    with _lock:
        admin_id = _session.get("admin_id", "owner")
        cache = _session.get("cache") or {}
    admins = cache.get("admins", {})
    admin = admins.get(admin_id, {})
    totp_b32 = admin.get("totp_secret_b32")
    if not totp_b32:
        return

    # Read code from body (POST) or query string (GET)
    totp_code = None
    try:
        body = req._json()
        totp_code = body.get("totp_code") if isinstance(body, dict) else None
    except Exception as exc:
        logging.getLogger("wireseal.security").warning("TOTP code parse failed (body): %s", exc)
    if not totp_code:
        try:
            from urllib.parse import urlsplit, parse_qs as _parse_qs
            q = urlsplit(getattr(req, "path", "") or "").query
            qs = _parse_qs(q)
            vals = qs.get("code", [])
            if vals:
                totp_code = vals[0]
        except Exception as exc:
            logging.getLogger("wireseal.security").warning("TOTP code parse failed (query): %s", exc)
    if not totp_code:
        raise _ApiError("totp_code required to reveal client config.", 401)

    _check_totp_rate_limit(admin_id)
    # SEC-CC-02: totp_secret_b32 is SecretBytes after _wrap_secrets;
    # unwrap to str, then decode base32 to raw secret bytes.
    from wireseal.security.secret_types import SecretBytes
    if isinstance(totp_b32, SecretBytes):
        totp_b32_str = bytes(totp_b32.expose_secret()).decode("utf-8")
    else:
        totp_b32_str = str(totp_b32)
    secret_raw = b32_to_secret(totp_b32_str)
    with _lock:
        used_set = _totp_used_codes.setdefault(admin_id, set())
    ok = verify_totp(secret_raw, str(totp_code), used_codes=used_set)
    if not ok:
        from wireseal.security.audit import AuditLog
        AuditLog(_AUDIT_PATH).log("totp-failed", {"admin_id": admin_id}, actor=admin_id)
        _record_totp_failure(admin_id)
        raise _ApiError("Invalid TOTP code.", 401)
    import time as _time
    with _lock:
        _totp_session_verified[admin_id] = _time.monotonic()
    _persist_totp_used_codes(admin_id)


def _get_actor_access_level() -> str:
    """Return the access level of the current admin (from vault cache)."""
    with _lock:
        admin_id = _session.get("admin_id", "owner")
    if admin_id == "owner":
        return "owner"
    with _lock:
        cache = _session.get("cache") or {}
    admin = cache.get("admins", {}).get(admin_id, {})
    return admin.get("role", "admin")


# ---------------------------------------------------------------------------
# PIN helpers â€” encrypt/decrypt passphrase with a short PIN
# ---------------------------------------------------------------------------

# SEC-FIX-2: PIN KDF upgraded from PBKDF2-SHA256 to Argon2id.
#
# Migration strategy (dual-path):
#   - New PIN files are written with a version prefix "argon2id:v1:" so future
#     code can detect the algorithm without guessing.
#   - Legacy files that start with "pbkdf2:" are still verified via the old
#     PBKDF2 path. On success the file is immediately re-written using Argon2id
#     so that the user is silently migrated on next unlock.
#   - The PIN file is wiped after _PIN_MAX_ATTEMPTS wrong guesses, which limits
#     offline brute-force exposure regardless of KDF strength â€” but Argon2id
#     raises the cost for any window where an attacker has obtained the file
#     before it is wiped.
#
# Argon2id parameters (OWASP recommended minimum for interactive use):
#   time_cost=3, memory_cost=65536 (64 MiB), parallelism=4, hash_len=32
#
# Version tag format stored in pin.enc (text header + binary payload):
#   "argon2id:v1:<base64(salt)>:<base64(hash)>\n" + nonce(12) + ciphertext
#   "pbkdf2:<base64(salt)>\n" + nonce(12) + ciphertext   â† legacy

_PIN_ARGON2_TAG   = b"argon2id:v1:"
_PIN_PBKDF2_TAG   = b"pbkdf2:"


def _pin_derive_key_argon2id(pin: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a PIN using Argon2id (OWASP interactive tier)."""
    import argon2.low_level as _a2
    return _a2.hash_secret_raw(
        secret=pin.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=_a2.Type.ID,
    )


def _pin_derive_key_pbkdf2(pin: str, salt: bytes) -> bytes:
    """Legacy PBKDF2-SHA256 key derivation â€” used only for migration reads."""
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, iterations=600_000, dklen=32)


def _pin_save(passphrase_bytes: bytes, pin: str) -> None:
    """Encrypt the passphrase with the PIN and save to pin.enc (Argon2id)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _pin_derive_key_argon2id(pin, salt)
    ct = AESGCM(key).encrypt(nonce, passphrase_bytes, salt)
    # Header: "argon2id:v1:<b64salt>:<b64hash_ignored>\n" is intentionally
    # minimal â€” the actual key is re-derived at load time; we store just the
    # salt so the header remains self-describing.
    salt_b64 = base64.b64encode(salt).decode()
    header = f"argon2id:v1:{salt_b64}\n".encode()
    _VAULT_DIR.mkdir(parents=True, exist_ok=True)
    from wireseal.security.vault import atomic_write
    atomic_write(_PIN_PATH, header + nonce + ct, mode=0o600)
    try:
        if sys.platform != "win32":
            os.chmod(_PIN_PATH, 0o600)
    except OSError as _exc:
        logging.getLogger("wireseal").warning("Failed to set PIN file permissions: %s", _exc)


def _pin_load(pin: str) -> bytes | None:
    """Decrypt the passphrase from pin.enc. Returns None on failure.

    Handles both the current Argon2id format and the legacy PBKDF2 format.
    On a successful PBKDF2 verify the file is silently re-written using
    Argon2id (transparent migration on next unlock).
    """
    if not _PIN_PATH.exists():
        return None
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    raw = _PIN_PATH.read_bytes()

    # ---- Argon2id path (current format) ------------------------------------
    if raw.startswith(_PIN_ARGON2_TAG):
        try:
            header_end = raw.index(b"\n")
        except ValueError:
            return None
        header = raw[len(_PIN_ARGON2_TAG):header_end].decode()
        # header = "<b64salt>"
        parts = header.split(":")
        try:
            salt = base64.b64decode(parts[0])
        except Exception:
            return None
        payload = raw[header_end + 1:]
        if len(payload) < 13:  # 12 nonce + 1 min ct
            return None
        nonce, ct = payload[:12], payload[12:]
        key = _pin_derive_key_argon2id(pin, salt)
        try:
            return AESGCM(key).decrypt(nonce, ct, salt)
        except InvalidTag:
            return None

    # ---- Legacy PBKDF2 path (migration) ------------------------------------
    # Format: "pbkdf2:<b64salt>\n" + nonce(12) + ciphertext
    if raw.startswith(_PIN_PBKDF2_TAG):
        try:
            header_end = raw.index(b"\n")
        except ValueError:
            # Older files had no text header â€” treat entire blob as binary.
            # Binary layout: salt(16) + nonce(12) + ciphertext
            if len(raw) < 29:
                return None
            salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
            key = _pin_derive_key_pbkdf2(pin, salt)
            try:
                plaintext = AESGCM(key).decrypt(nonce, ct, salt)
            except InvalidTag:
                return None
            # Migrate to Argon2id
            _pin_save(plaintext, pin)
            return plaintext

        b64_salt = raw[len(_PIN_PBKDF2_TAG):header_end].decode()
        try:
            salt = base64.b64decode(b64_salt)
        except Exception:
            return None
        payload = raw[header_end + 1:]
        if len(payload) < 13:
            return None
        nonce, ct = payload[:12], payload[12:]
        key = _pin_derive_key_pbkdf2(pin, salt)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ct, salt)
        except InvalidTag:
            return None
        # Migrate to Argon2id on successful verify
        _pin_save(plaintext, pin)
        return plaintext

    # ---- Raw binary legacy (pre-versioning, no header) ---------------------
    if len(raw) < 29:
        return None
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = _pin_derive_key_pbkdf2(pin, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, salt)
    except InvalidTag:
        return None
    # Migrate to Argon2id on successful verify
    _pin_save(plaintext, pin)
    return plaintext


def _pin_wipe() -> None:
    """Delete the PIN file."""
    try:
        _PIN_PATH.unlink(missing_ok=True)
    except OSError as _exc:
        logging.getLogger("wireseal").warning("Failed to remove PIN file: %s", _exc)



def _refresh_cache(state: Any) -> dict:
    """Build a non-secret snapshot from an open VaultState.

    Handles both server-mode vaults (have .server/.clients/.ip_pool) and
    client-mode vaults (only have client_configs).

    IMPORTANT: Admin dicts are deep-copied with SecretBytes unwrapped to plain
    strings.  A shallow copy shares inner dict references with the vault state;
    when ``VaultState.__exit__`` wipes SecretBytes on close, the cache would
    hold zeroed objects â€” breaking TOTP enrollment checks and verification.
    """
    from wireseal.security.vault import VaultState

    mode = state.data.get("mode", "server")
    admins_raw = state.data.get("admins", {})
    admins_cache = {
        k: VaultState._unwrap_secrets(dict(v)) if isinstance(v, dict) else v
        for k, v in admins_raw.items()
    }
    if mode == "client":
        return {
            "mode": "client",
            "server": {},
            "clients": {},
            "ip_pool": {},
            "admins": admins_cache,
            "dns_mappings": {},
            "backup_config": {},
        }
    return {
        "mode": "server",
        "server": {
            "ip":         state.server.get("ip", ""),
            "subnet":     state.server.get("subnet",
                              state.ip_pool.get("subnet", "")),
            "port":       state.server.get("port", 51820),
            "endpoint":   state.server.get("endpoint", ""),
            "duckdns":    state.server.get("duckdns_domain", ""),
            "lan_subnet": state.server.get("lan_subnet", ""),
        },
        "clients": {
            name: {
                "ip":               data["ip"],
                "permanent":        data.get("permanent", True),
                "ttl_seconds":      data.get("ttl_seconds"),
                "ttl_expires_at":   data.get("ttl_expires_at"),
                "access_level":     data.get("access_level", "standard"),
                "status":           data.get("status", "active"),
                "description":      data.get("description", ""),
                "privileges":       data.get("privileges"),
                "auto_revoke":      data.get("auto_revoke", True),
                "created_at":       data.get("created_at"),
                "heartbeat_token":  data.get("heartbeat_token", ""),
            }
            for name, data in state.clients.items()
        },
        "ip_pool": dict(state.ip_pool),
        "admins": admins_cache,
        "dns_mappings": dict(state.data.get("dns_mappings", {})),
        "backup_config": dict(state.data.get("backup_config", {})),
    }


def _refresh_cache_unlocked(vault: Any, passphrase: Any, admin_id: str = "owner") -> None:
    """Open vault and refresh in-memory cache. Called after writes that happen
    outside the context manager pattern (heartbeat, set-ttl, expiry watcher).
    """
    try:
        with vault.open(passphrase, admin_id=admin_id) as state:
            with _lock:
                _session["cache"] = _refresh_cache(state)
    except VaultTamperedError:
        logging.getLogger("wireseal").critical(
            "Vault payload integrity check failed during cache refresh. "
            "The vault data has been corrupted. Restore from backup."
        )
    except Exception as _e:
        logging.getLogger("wireseal").warning("Cache refresh failed: %s", _e)


def _migrate_legacy_client_tokens(state: Any, vault: Any, passphrase: Any) -> None:
    """Phase 5.4: assign heartbeat tokens to legacy clients missing them.

    Called during vault unlock so every client has a bearer token before the
    cache is built.  Idempotent — skips clients that already have a token.
    """
    import secrets as _secrets_hb
    modified = False
    for cname, cdata in state.clients.items():
        if not cdata.get("heartbeat_token"):
            cdata["heartbeat_token"] = _secrets_hb.token_hex(32)
            modified = True
    if modified:
        vault.save(state, passphrase)


def _extract(value: Any) -> str:
    """Return plain str from either str or SecretBytes."""
    from wireseal.security.secret_types import SecretBytes
    if isinstance(value, SecretBytes):
        return value.expose_secret().decode("utf-8")
    return str(value)


def _dns_for_tunnel_mode(
    tunnel_mode: str,
    lan_subnet: str = "",
    lan_gateway: str = "",
) -> str:
    """Compute DNS server(s) appropriate for the tunnel mode.

    - full:      public DNS (all traffic tunneled, always reachable)
    - split-lan: LAN gateway IP (routed through tunnel -- works even when
                 the client's local network blocks external DNS)
    - split-vpn: empty string (use system DNS -- tunnel only carries VPN subnet)

    The split-lan fix is critical: hardcoded public DNS (1.1.1.1, 8.8.8.8)
    is NOT in AllowedIPs for split modes, so DNS goes via the client's local
    network. WiFi/VPN networks that block or intercept external DNS break
    the tunnel. Using the LAN gateway (which IS in AllowedIPs) routes DNS
    through the tunnel reliably.

    Args:
        lan_gateway: Actual default gateway IP detected from routing table.
                     Preferred over guessing first usable IP from subnet.
    """
    if tunnel_mode == "full":
        return "1.1.1.1, 8.8.8.8"
    if tunnel_mode == "split-lan":
        # Prefer actual detected gateway over first-usable-IP guess.
        # Routers use .1, .254, or anything — only the real gateway is reliable.
        if lan_gateway:
            return lan_gateway
        if lan_subnet:
            import ipaddress as _ipa
            try:
                net = _ipa.IPv4Network(lan_subnet, strict=False)
                return str(next(net.hosts()))
            except (ValueError, StopIteration):
                pass
    # split-vpn or fallback: no DNS override, use system DNS
    return ""


def _detect_mtu() -> int:
    """Detect optimal WireGuard client MTU based on outbound interface MTU.

    WireGuard adds 80 bytes overhead (60 IPv4/IPv6 + 20 WireGuard header).
    We subtract that from the outbound interface MTU to get the optimal client MTU.
    Falls back to 1420 if detection fails.
    """
    try:
        if sys.platform == "win32":
            import subprocess as _sp
            import re as _re
            # Primary: find the default-route interface, get its MTU
            try:
                route_result = _sp.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
                     "| Sort-Object RouteMetric "
                     "| Select-Object -First 1).InterfaceIndex"],
                    capture_output=True, text=True, timeout=10,
                )
                if_index = route_result.stdout.strip()
                if if_index and if_index.isdigit():
                    mtu_result = _sp.run(
                        ["powershell", "-NoProfile", "-Command",
                         f"(Get-NetIPInterface -InterfaceIndex {if_index} "
                         "-AddressFamily IPv4).NlMtu"],
                        capture_output=True, text=True, timeout=10,
                    )
                    mtu_str = mtu_result.stdout.strip()
                    if mtu_str and mtu_str.isdigit():
                        return min(int(mtu_str) - 80, 1420)
            except (OSError, _sp.TimeoutExpired):
                pass
            # Fallback: parse netsh output, use LOWEST MTU (safe for WiFi/VPN)
            result = _sp.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                capture_output=True, text=True, timeout=10,
            )
            mtus = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0].isdigit() and parts[1].isdigit():
                    mtu_val = int(parts[1])
                    if 500 < mtu_val <= 9000:
                        mtus.append(mtu_val)
            if mtus:
                return min(min(mtus) - 80, 1420)
        elif sys.platform == "darwin":
            import subprocess as _sp
            import re as _re
            # macOS: route -n get + networksetup/ifconfig for MTU
            result = _sp.run(
                ["route", "-n", "get", "8.8.8.8"],
                capture_output=True, text=True, timeout=10,
            )
            iface_match = _re.search(r"interface:\s*(\S+)", result.stdout)
            if iface_match:
                iface = iface_match.group(1)
                ifcfg = _sp.run(
                    ["ifconfig", iface],
                    capture_output=True, text=True, timeout=5,
                )
                mtu_match = _re.search(r"\bmtu\s+(\d+)", ifcfg.stdout)
                if mtu_match:
                    return min(int(mtu_match.group(1)) - 80, 1420)
        else:
            import subprocess as _sp
            import re as _re
            # Linux: ip route to find outbound interface, then read its MTU
            result = _sp.run(
                ["ip", "route", "get", "8.8.8.8"],
                capture_output=True, text=True, timeout=10,
            )
            iface_match = _re.search(r"\bdev\s+(\S+)", result.stdout)
            if iface_match:
                iface = iface_match.group(1)
                mtu_result = _sp.run(
                    ["cat", f"/sys/class/net/{iface}/mtu"],
                    capture_output=True, text=True, timeout=5,
                )
                if mtu_result.returncode == 0:
                    return min(int(mtu_result.stdout.strip()) - 80, 1420)
    except Exception as _exc:
        logging.getLogger("wireseal").warning("MTU detection failed: %s", _exc)
    return 1420  # optimal default for standard 1500 ethernet â€” WG overhead is 80 bytes


def _resolve_client_endpoint(server_state: dict) -> str:
    """Return the endpoint string clients use to reach the server.

    Priority: DuckDNS domain â†’ stored endpoint â†’ auto-detect public IP.
    Never falls back to the internal VPN IP (e.g. 10.0.0.1) because it is
    unreachable from outside the tunnel.
    """
    port = server_state["port"]
    duckdns_domain = server_state.get("duckdns_domain")
    if duckdns_domain:
        return f"{duckdns_domain}.duckdns.org:{port}"
    stored_endpoint = server_state.get("endpoint")
    if stored_endpoint:
        # If the stored endpoint already contains a port, use it as-is.
        # This avoids producing "host:port:port" when the user configured
        # an endpoint like "myserver.com:51820".
        if ":" in stored_endpoint and not stored_endpoint.startswith("["):
            # Could be IPv4:port or hostname:port â€” check if last segment is numeric
            last_colon = stored_endpoint.rfind(":")
            after_colon = stored_endpoint[last_colon + 1:]
            if after_colon.isdigit():
                return stored_endpoint
        elif stored_endpoint.startswith("[") and "]:" in stored_endpoint:
            # Bracketed IPv6 with port: [::1]:51820
            return stored_endpoint
        return f"{stored_endpoint}:{port}"
    # Last resort: try to auto-detect public IP instead of using VPN IP.
    try:
        from wireseal.dns.ip_resolver import resolve_public_ip
        public_ip = str(resolve_public_ip())
        return f"{public_ip}:{port}"
    except Exception as _exc:
        logging.getLogger("wireseal").warning(
            "No endpoint configured and public IP detection failed (%s); "
            "client config will use internal VPN IP %s which is likely unreachable.",
            _exc, server_state["ip"],
        )
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
        from wireseal.platform.windows import WG_EXE as wg_exe
        dpapi_path = config_path.with_suffix(".conf.dpapi")
        if config_path.exists() and wg_exe.exists():
            # Plain .conf available — full uninstall/reinstall cycle
            subprocess.run(
                [str(wg_exe), "/uninstalltunnelservice", interface],
                check=False, capture_output=True, timeout=10, creationflags=_no_win,
            )
            subprocess.run(
                [str(wg_exe), "/installtunnelservice", str(config_path)],
                check=False, capture_output=True, timeout=10, creationflags=_no_win,
            )
        elif dpapi_path.exists():
            # Only DPAPI-encrypted config exists — service was previously
            # installed.  Cannot reinstall without plain .conf, just restart.
            subprocess.run(
                ["sc.exe", "start", svc],
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
        # Interface not up â€” bring it up
        result = subprocess.run(
            _sudo([_resolve_wg_tool("wg-quick"), "up", interface]),
            shell=False, check=False, capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            err = result.stderr.decode("utf-8", errors="replace")
            print(f"[wireseal] wg-quick up failed: {err}", file=sys.stderr)
            return f"wg-quick up failed: {err}"
        return ""

    # Interface is up â€” try syncconf (hot reload, no disconnect)
    sync_err = ""
    try:
        strip_result = subprocess.run(
            _sudo([_resolve_wg_tool("wg-quick"), "strip", str(config_path)]),
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
                _sudo([_resolve_wg_tool("wg"), "syncconf", interface, tmp_path]),
                shell=False, check=False, capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                return ""  # Success
            sync_err = result.stderr.decode("utf-8", errors="replace")
            print(f"[wireseal] wg syncconf failed: {sync_err}", file=sys.stderr)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError as _exc:
                logging.getLogger("wireseal").warning("Failed to clean up temp WG config: %s", _exc)
    except Exception as exc:
        sync_err = str(exc)
        print(f"[wireseal] wg syncconf exception: {exc}", file=sys.stderr)

    # Fallback: full restart (brief disconnect but guarantees config is loaded)
    print("[wireseal] Falling back to wg-quick down/up...", file=sys.stderr)
    subprocess.run(
        _sudo([_resolve_wg_tool("wg-quick"), "down", interface]),
        shell=False, check=False, capture_output=True, timeout=15,
    )
    result = subprocess.run(
        _sudo([_resolve_wg_tool("wg-quick"), "up", interface]),
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
_last_activity: list[float] = [0.0]
_SESSION_TIMEOUT = _SESSION_TIMEOUT_CFG


def _h_health(req: "_Handler", _groups: tuple) -> dict:
    """Lightweight health endpoint for monitoring -- no auth, no subprocess."""
    import shutil
    import sys as _sys
    import time

    # Read from wireseal.api module so tests that patch api._server_start_time work
    import wireseal.api as _api_mod
    start_time = getattr(_api_mod, "_server_start_time", _server_start_time)
    uptime = int(time.monotonic() - start_time) if start_time else 0

    try:
        from wireseal import __version__ as _wireseal_version
    except Exception:
        _wireseal_version = "unknown"

    disk_free = -1
    try:
        du = shutil.disk_usage(str(_VAULT_DIR) if _VAULT_DIR else ".")
        disk_free = du.free
    except Exception:
        pass

    mem_avail = -1
    try:
        if _sys.platform == "win32":
            import ctypes as _ctypes

            class _MEMORYSTATUSEX(_ctypes.Structure):
                _fields_ = [
                    ("dwLength", _ctypes.c_ulong),
                    ("dwMemoryLoad", _ctypes.c_ulong),
                    ("ullTotalPhys", _ctypes.c_ulonglong),
                    ("ullAvailPhys", _ctypes.c_ulonglong),
                    ("ullTotalPageFile", _ctypes.c_ulonglong),
                    ("ullAvailPageFile", _ctypes.c_ulonglong),
                    ("ullTotalVirtual", _ctypes.c_ulonglong),
                    ("ullAvailVirtual", _ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", _ctypes.c_ulonglong),
                ]

            _mem = _MEMORYSTATUSEX()
            _mem.dwLength = _ctypes.sizeof(_MEMORYSTATUSEX)
            _ctypes.windll.kernel32.GlobalMemoryStatusEx(_ctypes.byref(_mem))
            mem_avail = _mem.ullAvailPhys
        elif _sys.platform == "linux":
            with open("/proc/meminfo") as _f:
                for _line in _f:
                    if _line.startswith("MemAvailable:"):
                        mem_avail = int(_line.split()[1]) * 1024
                        break
    except Exception:
        pass

    return {
        "status": "ok",
        "vault_initialized": _VAULT_PATH.exists(),
        "vault_locked": _session["vault"] is None,
        "uptime_seconds": uptime,
        "version": _wireseal_version,
        "disk_free_bytes": disk_free,
        "memory_available_bytes": mem_avail,
    }


def _h_ready(req: "_Handler", _groups: tuple) -> dict:
    """Readiness probe -- is the vault unlocked and WireGuard running?

    Separate from /api/health (which is purely about process liveness).
    Monitoring tools should check this before routing traffic.
    """
    vault_unlocked = _session["vault"] is not None

    wg_running = False
    if vault_unlocked:
        try:
            import subprocess as _sp
            _sp.run(
                [_resolve_wg_tool("wg"), "show", _WG_IFACE],
                capture_output=True, timeout=5, check=True,
            )
            wg_running = True
        except Exception:
            pass

    return {
        "ready": vault_unlocked and wg_running,
        "vault_unlocked": vault_unlocked,
        "wg_running": wg_running,
    }


def _h_status(req: "_Handler", _groups: tuple) -> dict:
    """Server status -- running, peers, interface info."""
    _require_unlocked()

    with _lock:
        cache = _session["cache"] or {}

    running = False
    peers: list[dict] = []

    try:
        result = subprocess.run(
            _sudo([_resolve_wg_tool("wg"), "show", _WG_IFACE]), capture_output=True, text=True, timeout=5,
            creationflags=_SP_FLAGS,
        )
        if result.returncode == 0 and result.stdout.strip():
            running = True
            from wireseal.api.service import _parse_wg_show
            peers = _parse_wg_show(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
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
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    ip_to_name = {
        data["ip"].split("/")[0]: name
        for name, data in cache.get("clients", {}).items()
    }
    for p in peers:
        ip = p.get("allowed_ips", "").split("/")[0]
        p["name"] = ip_to_name.get(ip, "unknown")

    iface = cache.get("server", {}).get("interface", _WG_IFACE)
    server_ip = cache.get("server", {}).get("ip", "")
    endpoint = cache.get("server", {}).get("endpoint", "")
    port = cache.get("server", {}).get("port", 0)
    lan_subnet = cache.get("server", {}).get("lan_subnet", "")
    total_clients = len(cache.get("clients", {}))

    # Windows: check if IP forwarding requires a pending reboot
    needs_reboot = False
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                0, winreg.KEY_READ,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "IPEnableRouter")
                if val == 1:
                    # Registry says enabled — check if routing is actually active
                    check = subprocess.run(
                        ["powershell", "-NoProfile", "-Command",
                         "(Get-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue).ifIndex.Count"],
                        capture_output=True, text=True, timeout=10,
                        creationflags=_SP_FLAGS,
                    )
                    forwarding_active = (check.stdout.strip() or "0") != "0"
                    if not forwarding_active:
                        needs_reboot = True
        except Exception:
            pass

    return {
        "running": running,
        "interface": iface,
        "server_ip": server_ip,
        "endpoint": endpoint,
        "port": port,
        "lan_subnet": lan_subnet,
        "peers": peers,
        "total_clients": total_clients,
        "needs_reboot": needs_reboot,
    }
# ---------------------------------------------------------------------------
# Port validation policy (used by /api/init and /api/change-port)
#
# Three categories:
#
#   BLOCK   â€” reject outright. Out-of-range or critical-system UDP ports
#             where binding WireGuard is virtually guaranteed to break the
#             host (DNS, DHCP, NetBIOS, IKE, mDNS).
#
#   WARN    â€” accept but return a `warning` field so the UI can prompt for
#             confirmation. Privileged range 1..1023 (Unix needs root,
#             Windows binds fine but the port is well-known and may be
#             rejected by managed firewalls / corporate proxies). Also
#             non-fatal collisions like 8080 (proxies), 5353 (mDNS â€” was
#             also blocked, choose one), 3389 (RDP).
#
#   OK      â€” 1024..65535 with no known UDP service conflict. The WireGuard
#             default 51820 falls here, as do recommended "stealth" choices
#             like 4500, 443, and any user-picked random ephemeral port.
#
# This list is intentionally minimal: every entry is a UDP service that
# overlaps with WireGuard's transport, AND is part of the default OS install
# on at least one of (Linux, macOS, Windows). TCP-only services (22, 80,
# 25, 110, 3306, 6379, 8080â€¦) are NOT included â€” WireGuard is UDP, so the
# OS can host both simultaneously without conflict.
# ---------------------------------------------------------------------------

# UDP ports we reject outright. Binding WG here will break the host.
_PORT_BLOCKLIST_UDP: dict[int, str] = {
    0:    "Port 0 is reserved.",
    53:   "UDP/53 is the DNS resolver port.",
    67:   "UDP/67 is the DHCP server port.",
    68:   "UDP/68 is the DHCP client port.",
    69:   "UDP/69 is TFTP.",
    123:  "UDP/123 is NTP â€” picking it breaks system clock sync.",
    137:  "UDP/137 is NetBIOS Name Service (Windows).",
    138:  "UDP/138 is NetBIOS Datagram Service (Windows).",
    161:  "UDP/161 is SNMP.",
    162:  "UDP/162 is SNMP Trap.",
    500:  "UDP/500 is IKE â€” conflicts with IPsec/L2TP.",
    514:  "UDP/514 is syslog.",
    520:  "UDP/520 is RIP routing.",
    1900: "UDP/1900 is SSDP/UPnP discovery.",
    5353: "UDP/5353 is mDNS / Bonjour.",
    5355: "UDP/5355 is LLMNR.",
}

# UDP ports we accept but flag with a warning. UI should ask for confirmation.
_PORT_WARN_UDP: dict[int, str] = {
    443:  "UDP/443 (HTTP/3 â€” QUIC). Useful for bypassing restrictive "
          "firewalls but may collide with web servers running QUIC.",
    4500: "UDP/4500 (IPsec NAT-T) â€” common for VPNs; collides with "
          "IKEv2 / L2TP-over-IPsec setups.",
    3389: "UDP/3389 (RDP UDP transport, Windows).",
    8080: "UDP/8080 â€” common HTTP-alt port; some scanners flag it.",
}


def _validate_wg_port(port: int) -> tuple[bool, str | None]:
    """Validate a WireGuard listen port.

    Returns ``(ok, warning_or_None)``. Raises ``_ApiError`` on hard reject
    so callers in handler context can let it bubble up.

    Privileged range 1-1023 is allowed but warned: Linux/macOS need root
    (which `wireseal serve` already does); Windows accepts but the port is
    likely owned by a system service. The WireGuard default 51820 returns
    ``(True, None)`` with no warning.
    """
    if not isinstance(port, int) or isinstance(port, bool):
        raise _ApiError("Port must be an integer.", 400)
    if not (1 <= port <= 65535):
        raise _ApiError("Port must be in range 1-65535.", 400)
    if port in _PORT_BLOCKLIST_UDP:
        raise _ApiError(
            f"Port {port} is reserved: {_PORT_BLOCKLIST_UDP[port]}", 400
        )
    warnings: list[str] = []
    if port in _PORT_WARN_UDP:
        warnings.append(_PORT_WARN_UDP[port])
    if 1 <= port <= 1023:
        warnings.append(
            f"Port {port} is in the privileged range (1-1023). On Linux/macOS "
            f"WireSeal already runs as root so this works, but the port is "
            f"well-known and may be filtered by upstream firewalls."
        )
    # NB: IANA's "dynamic/ephemeral" range (49152-65535) is for *outbound*
    # connection source ports. A bound listening socket stays bound â€” the OS
    # won't steal it. The WireGuard default 51820 falls in this range and is
    # perfectly fine, so we deliberately do NOT warn on it.
    return True, ("; ".join(warnings) if warnings else None)


_ENDPOINT_RE = re.compile(
    # host = IPv4 / bracketed IPv6 / hostname-or-FQDN; optional :port
    r"^(?:"
        r"(?P<ipv4>\d{1,3}(?:\.\d{1,3}){3})"
        r"|"
        r"\[(?P<ipv6>[0-9a-fA-F:]+)\]"
        r"|"
        r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*)"
    r")"
    r"(?::(?P<port>\d{1,5}))?$"
)



def _validate_endpoint(endpoint: str) -> str:
    """Normalise + validate user-supplied endpoint string.

    Accepts IPv4, [IPv6], hostname/FQDN, with optional `:port`. Rejects
    schemes (`http://`), whitespace, control characters, and over-long
    inputs that would break wg-quick's PostUp/Endpoint parser.
    """
    if not isinstance(endpoint, str):
        raise _ApiError("Endpoint must be a string.", 400)
    endpoint = endpoint.strip()
    if not endpoint:
        raise _ApiError("Endpoint must not be empty.", 400)
    if len(endpoint) > 255:
        raise _ApiError("Endpoint too long (max 255 chars).", 400)
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in endpoint):
        raise _ApiError("Endpoint contains control characters.", 400)
    if "://" in endpoint:
        raise _ApiError(
            "Endpoint must be host[:port], not a URL with a scheme.", 400
        )
    m = _ENDPOINT_RE.match(endpoint)
    if not m:
        raise _ApiError(
            "Endpoint must be IPv4, [IPv6], or hostname, with optional :port.",
            400,
        )
    if m.group("port"):
        port = int(m.group("port"))
        if not (1 <= port <= 65535):
            raise _ApiError("Endpoint port must be 1â€“65535.", 400)
        # Strip the port â€” _resolve_client_endpoint appends the server's
        # listen port from the vault. Storing "host:port" would produce
        # "host:port:port" in the generated client config.
        host_part = endpoint[:endpoint.rfind(":" + m.group("port"))]
        return host_part
    return endpoint

