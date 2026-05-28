"""Configurable settings with environment variable overrides.

Phase 5.3: centralises hardcoded constants scattered across the codebase.
Each constant can be overridden via a ``WIRESEAL_<NAME>`` environment variable.

Env-var conventions:
  - Integers: ``WIRESEAL_SESSION_TIMEOUT=1800``
  - Floats:   ``WIRESEAL_HEARTBEAT_MIN_INTERVAL=15.0``
  - Strings:  ``WIRESEAL_WG_IFACE=wg1``

Path overrides (via ``override_vault_dir()``) remain in ``api/_shared.py``
because they affect runtime state, not startup defaults.
"""

import os
from typing import Any


def _env_int(name: str, default: int) -> int:
    val = os.environ.get(f"WIRESEAL_{name}")
    if val is not None:
        try:
            return int(val)
        except (ValueError, TypeError):
            pass
    return default


def _env_float(name: str, default: float) -> float:
    val = os.environ.get(f"WIRESEAL_{name}")
    if val is not None:
        try:
            return float(val)
        except (ValueError, TypeError):
            pass
    return default


def _env_str(name: str, default: str) -> str:
    return os.environ.get(f"WIRESEAL_{name}", default)


# ---------------------------------------------------------------------------
# Session & auto-lock
# ---------------------------------------------------------------------------
SESSION_TIMEOUT: int = _env_int("SESSION_TIMEOUT", 900)
"""Seconds of inactivity before the vault auto-locks (default 15 min)."""

# ---------------------------------------------------------------------------
# Admin mode
# ---------------------------------------------------------------------------
ADMIN_TIMEOUT: int = _env_int("ADMIN_TIMEOUT", 1800)
"""Admin session lifetime in seconds (default 30 min)."""

ADMIN_MAX_FAILS: int = _env_int("ADMIN_MAX_FAILS", 3)
"""Maximum failed admin auth attempts before rate-limit."""

# ---------------------------------------------------------------------------
# Unlock rate limiting
# ---------------------------------------------------------------------------
UNLOCK_WINDOW: int = _env_int("UNLOCK_WINDOW", 300)
"""Sliding window (seconds) for unlock attempt tracking (default 5 min)."""

UNLOCK_MAX: int = _env_int("UNLOCK_MAX", 5)
"""Max unlock failures within UNLOCK_WINDOW before rate-limit."""

# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------
HEARTBEAT_MIN_INTERVAL: float = _env_float("HEARTBEAT_MIN_INTERVAL", 30.0)
"""Minimum seconds between heartbeat resets per client."""

# ---------------------------------------------------------------------------
# Client creation rate limit
# ---------------------------------------------------------------------------
CLIENT_CREATION_LIMIT: int = _env_int("CLIENT_CREATION_LIMIT", 50)
"""Max client creations per admin session per hour."""

# ---------------------------------------------------------------------------
# PIN
# ---------------------------------------------------------------------------
PIN_MAX_ATTEMPTS: int = _env_int("PIN_MAX_ATTEMPTS", 5)
"""Wrong PIN attempts before PIN file is wiped."""

# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------
TOTP_SESSION_HOURS: int = _env_int("TOTP_SESSION_HOURS", 1)
"""Hours a TOTP verification session remains valid."""

TOTP_USED_CODE_TTL: int = _env_int("TOTP_USED_CODE_TTL", 90)
"""Seconds before a used TOTP code is pruned from the anti-replay set."""

TOTP_WINDOW: int = _env_int("TOTP_WINDOW", 60)
"""Sliding window (seconds) for TOTP failure tracking."""

TOTP_MAX_FAILS: int = _env_int("TOTP_MAX_FAILS", 3)
"""Max TOTP failures within window before lockout."""

TOTP_LOCKOUT_SECS: int = _env_int("TOTP_LOCKOUT_SECS", 30)
"""Lockout duration (seconds) after exceeding TOTP_MAX_FAILS."""

TOTP_SESSION_MAX: int = _env_int("TOTP_SESSION_MAX", 10)
"""Absolute max TOTP attempts per session."""

TOTP_BACKUP_WINDOW: int = _env_int("TOTP_BACKUP_WINDOW", 300)
"""Sliding window (seconds) for backup code tracking."""

TOTP_BACKUP_MAX: int = _env_int("TOTP_BACKUP_MAX", 3)
"""Max backup code attempts within window."""

# ---------------------------------------------------------------------------
# Request / payload limits
# ---------------------------------------------------------------------------
MAX_BODY_SIZE: int = _env_int("MAX_BODY_SIZE", 1 * 1024 * 1024)
"""Max HTTP request body size in bytes (default 1 MiB)."""

MAX_ADMIN_READ_SIZE: int = _env_int("MAX_ADMIN_READ_SIZE", 1 * 1024 * 1024)
"""Max file read size for admin/file endpoints (default 1 MiB)."""

# ---------------------------------------------------------------------------
# Fresh-start challenge
# ---------------------------------------------------------------------------
FRESH_START_TTL_SECONDS: int = _env_int("FRESH_START_TTL_SECONDS", 120)
"""Challenge token TTL in seconds (default 2 min)."""

# ---------------------------------------------------------------------------
# SFTP
# ---------------------------------------------------------------------------
SFTP_MIN_INTERVAL: float = _env_float("SFTP_MIN_INTERVAL", 0.05)
"""Min seconds between SFTP operations (default 50ms)."""

SFTP_MAX_BYTES: int = _env_int("SFTP_MAX_BYTES", 50 * 1024 * 1024)
"""Max bytes transferred per minute via SFTP (default 50 MiB)."""

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
WG_IFACE: str = _env_str("WG_IFACE", "wg0")
"""Default WireGuard interface name."""

# ---------------------------------------------------------------------------
# Rate-limit escalation (generic, not endpoint-specific)
# ---------------------------------------------------------------------------
RATE_LIMIT_5: int = _env_int("RATE_LIMIT_5", 30)
"""Backoff seconds after 5 failures on any rate-limited endpoint."""

RATE_LIMIT_10: int = _env_int("RATE_LIMIT_10", 300)
"""Backoff seconds after 10 failures."""

RATE_LIMIT_20: int = _env_int("RATE_LIMIT_20", 1800)
"""Backoff seconds after 20 failures."""
