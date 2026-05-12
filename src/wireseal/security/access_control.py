"""Access control and expiry logic for WireSeal clients.

Provides role-based access levels, privilege management, client status
tracking, and expiry configuration — all as pure data structures and
validation functions with no API or vault coupling.
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Access Levels
# ---------------------------------------------------------------------------

class AccessLevel(str, Enum):
    """Role-based access levels ordered by privilege (highest first)."""
    OWNER = "owner"
    ADMIN = "admin"
    STANDARD = "standard"
    GUEST = "guest"
    CUSTOM = "custom"

    @classmethod
    def from_str(cls, value: str) -> "AccessLevel":
        """Parse a string into an AccessLevel, defaulting to STANDARD."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.STANDARD

    @property
    def rank(self) -> int:
        """Numeric rank for comparison (higher = more privileged)."""
        return _LEVEL_RANK.get(self, 0)

    def can_manage(self, other: "AccessLevel") -> bool:
        """Whether this level can manage (edit/revoke) a client at *other* level."""
        if self == AccessLevel.OWNER:
            return True
        if self == AccessLevel.ADMIN:
            return other not in (AccessLevel.OWNER,)
        return False


_LEVEL_RANK = {
    AccessLevel.OWNER: 100,
    AccessLevel.ADMIN: 80,
    AccessLevel.STANDARD: 50,
    AccessLevel.GUEST: 20,
    AccessLevel.CUSTOM: 40,
}


# ---------------------------------------------------------------------------
# Client Status
# ---------------------------------------------------------------------------

class ClientStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


# ---------------------------------------------------------------------------
# Privileges
# ---------------------------------------------------------------------------

# Default privilege sets per access level
_DEFAULT_PRIVILEGES: dict[str, dict[str, Any]] = {
    "owner": {
        "full_network_access": True,
        "ssh_access": True,
        "smb_access": True,
        "http_access": True,
        "camera_access": True,
        "server_management": True,
        "client_management": True,
        "view_audit_logs": True,
        "configure_2fa": True,
        "backup_restore": True,
        "configure_dns": True,
        "bandwidth_limit_mbps": None,
        "specific_ip_ranges": None,
        "custom_ports": None,
        "dns_only": True,
        "vpn_internal_only": True,
        "manage_pin": True,
        "change_own_access": True,
        "change_passphrase": True,
    },
    "admin": {
        "full_network_access": True,
        "ssh_access": True,
        "smb_access": True,
        "http_access": True,
        "camera_access": True,
        "server_management": True,
        "client_management": True,
        "view_audit_logs": True,
        "configure_2fa": True,
        "backup_restore": True,
        "configure_dns": True,
        "bandwidth_limit_mbps": None,
        "specific_ip_ranges": None,
        "custom_ports": None,
        "dns_only": True,
        "vpn_internal_only": True,
        "manage_pin": True,
        "change_own_access": True,
        "change_passphrase": True,
    },
    "standard": {
        "full_network_access": False,
        "ssh_access": True,
        "smb_access": True,
        "http_access": True,
        "camera_access": True,
        "server_management": False,
        "client_management": False,
        "view_audit_logs": False,
        "configure_2fa": False,
        "backup_restore": False,
        "configure_dns": False,
        "bandwidth_limit_mbps": None,
        "specific_ip_ranges": None,
        "custom_ports": None,
        "dns_only": False,
        "vpn_internal_only": False,
        "manage_pin": True,
        "change_own_access": False,
        "change_passphrase": True,
    },
    "guest": {
        "full_network_access": False,
        "ssh_access": False,
        "smb_access": False,
        "http_access": True,
        "camera_access": True,
        "server_management": False,
        "client_management": False,
        "view_audit_logs": False,
        "configure_2fa": False,
        "backup_restore": False,
        "configure_dns": False,
        "bandwidth_limit_mbps": None,
        "specific_ip_ranges": None,
        "custom_ports": None,
        "dns_only": True,
        "vpn_internal_only": False,
        "manage_pin": False,
        "change_own_access": False,
        "change_passphrase": False,
    },
}


def default_privileges(level: AccessLevel) -> dict[str, Any]:
    """Return a fresh copy of default privileges for the given access level."""
    base = _DEFAULT_PRIVILEGES.get(level.value, _DEFAULT_PRIVILEGES["standard"])
    return dict(base)


def merge_privileges(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Merge user-supplied privilege overrides onto a base set.

    Only known keys are accepted; unknown keys are silently dropped.
    """
    known_keys = set(_DEFAULT_PRIVILEGES["owner"].keys())
    result = dict(base)
    for k, v in overrides.items():
        if k in known_keys:
            result[k] = v
    return result


def check_privilege(client_data: dict[str, Any], privilege: str) -> bool:
    """Check if a client record has a specific privilege.

    Falls back to access-level defaults when no explicit privileges are stored.
    """
    level = AccessLevel.from_str(client_data.get("access_level", "standard"))
    if level in (AccessLevel.OWNER, AccessLevel.ADMIN):
        return True
    privileges = client_data.get("privileges", default_privileges(level))
    return bool(privileges.get(privilege, False))


# ---------------------------------------------------------------------------
# Expiry helpers
# ---------------------------------------------------------------------------

def compute_expires_at(
    *,
    ttl_seconds: int | None = None,
    expires_at: float | None = None,
    now: float | None = None,
) -> float | None:
    """Compute an absolute expiry timestamp from either duration or absolute time.

    Returns None for permanent (no expiry).
    """
    if expires_at is not None:
        return float(expires_at)
    if ttl_seconds is not None and int(ttl_seconds) > 0:
        return (now or time.time()) + int(ttl_seconds)
    return None


def check_expiry_status(client_data: dict[str, Any], now: float | None = None) -> ClientStatus:
    """Determine a client's status based on its expiry and stored status.

    Priority: explicit revoked/suspended status > expiry check > active.
    """
    status_str = client_data.get("status", "active")
    if status_str == ClientStatus.REVOKED.value:
        return ClientStatus.REVOKED
    if status_str == ClientStatus.SUSPENDED.value:
        return ClientStatus.SUSPENDED

    expires_at = client_data.get("ttl_expires_at")
    if expires_at is not None:
        _now = now or time.time()
        if expires_at <= _now:
            return ClientStatus.EXPIRED
    return ClientStatus.ACTIVE


def expiry_warning_days(client_data: dict[str, Any], now: float | None = None) -> int | None:
    """Return days until expiry, or None if permanent/already expired."""
    expires_at = client_data.get("ttl_expires_at")
    if expires_at is None:
        return None
    _now = now or time.time()
    remaining = expires_at - _now
    if remaining <= 0:
        return 0
    return int(remaining / 86400)


# ---------------------------------------------------------------------------
# Client record helpers
# ---------------------------------------------------------------------------

def build_client_access_fields(
    *,
    access_level: str = "standard",
    privileges: dict[str, Any] | None = None,
    description: str | None = None,
    ttl_seconds: int | None = None,
    expires_at: float | None = None,
    auto_revoke: bool = True,
) -> dict[str, Any]:
    """Build the access-control fields to merge into a client vault record.

    Returns a dict of fields to be merged into the client entry — does NOT
    include WireGuard keys or IP addresses (those come from existing logic).
    """
    level = AccessLevel.from_str(access_level)
    base_privs = default_privileges(level)
    if privileges and level == AccessLevel.CUSTOM:
        base_privs = merge_privileges(base_privs, privileges)

    computed_expiry = compute_expires_at(
        ttl_seconds=ttl_seconds,
        expires_at=expires_at,
    )

    return {
        "access_level": level.value,
        "privileges": base_privs,
        "description": description or "",
        "status": ClientStatus.ACTIVE.value,
        "auto_revoke": auto_revoke,
        "created_at": time.time(),
    }


def validate_access_level_change(
    actor_level: str,
    target_current_level: str,
    target_new_level: str,
) -> str | None:
    """Validate an access level change. Returns error message or None if ok."""
    actor = AccessLevel.from_str(actor_level)
    current = AccessLevel.from_str(target_current_level)
    new = AccessLevel.from_str(target_new_level)

    if new == AccessLevel.OWNER:
        return "Cannot assign owner access level."
    if not actor.can_manage(current):
        return "Insufficient privileges to modify this client."
    if not actor.can_manage(new):
        return "Insufficient privileges to assign this access level."
    return None


VALID_ACCESS_LEVELS = ("admin", "standard", "guest", "custom")
