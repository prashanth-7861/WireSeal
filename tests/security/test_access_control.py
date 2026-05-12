"""Tests for wireseal.security.access_control module."""
from __future__ import annotations

import time

import pytest

from wireseal.security.access_control import (
    AccessLevel,
    ClientStatus,
    VALID_ACCESS_LEVELS,
    build_client_access_fields,
    check_expiry_status,
    check_privilege,
    compute_expires_at,
    default_privileges,
    expiry_warning_days,
    merge_privileges,
    validate_access_level_change,
)


# ---------------------------------------------------------------------------
# AccessLevel
# ---------------------------------------------------------------------------


class TestAccessLevel:
    def test_from_str_valid(self):
        assert AccessLevel.from_str("admin") == AccessLevel.ADMIN
        assert AccessLevel.from_str("GUEST") == AccessLevel.GUEST
        assert AccessLevel.from_str("Owner") == AccessLevel.OWNER

    def test_from_str_invalid_defaults_to_standard(self):
        assert AccessLevel.from_str("unknown") == AccessLevel.STANDARD
        assert AccessLevel.from_str("") == AccessLevel.STANDARD

    def test_rank_ordering(self):
        assert AccessLevel.OWNER.rank > AccessLevel.ADMIN.rank
        assert AccessLevel.ADMIN.rank > AccessLevel.STANDARD.rank
        assert AccessLevel.STANDARD.rank > AccessLevel.GUEST.rank

    def test_can_manage_owner(self):
        assert AccessLevel.OWNER.can_manage(AccessLevel.ADMIN)
        assert AccessLevel.OWNER.can_manage(AccessLevel.GUEST)
        assert AccessLevel.OWNER.can_manage(AccessLevel.OWNER)

    def test_can_manage_admin(self):
        assert AccessLevel.ADMIN.can_manage(AccessLevel.STANDARD)
        assert AccessLevel.ADMIN.can_manage(AccessLevel.GUEST)
        assert not AccessLevel.ADMIN.can_manage(AccessLevel.OWNER)

    def test_can_manage_standard_cannot(self):
        assert not AccessLevel.STANDARD.can_manage(AccessLevel.GUEST)
        assert not AccessLevel.STANDARD.can_manage(AccessLevel.STANDARD)

    def test_valid_access_levels_excludes_owner(self):
        assert "owner" not in VALID_ACCESS_LEVELS
        assert "admin" in VALID_ACCESS_LEVELS
        assert "custom" in VALID_ACCESS_LEVELS


# ---------------------------------------------------------------------------
# Privileges
# ---------------------------------------------------------------------------


class TestPrivileges:
    def test_default_admin_has_full_access(self):
        privs = default_privileges(AccessLevel.ADMIN)
        assert privs["full_network_access"] is True
        assert privs["server_management"] is True
        assert privs["client_management"] is True

    def test_default_guest_is_restricted(self):
        privs = default_privileges(AccessLevel.GUEST)
        assert privs["full_network_access"] is False
        assert privs["ssh_access"] is False
        assert privs["smb_access"] is False
        assert privs["http_access"] is True  # guests can browse

    def test_default_standard_middle_ground(self):
        privs = default_privileges(AccessLevel.STANDARD)
        assert privs["ssh_access"] is True
        assert privs["server_management"] is False
        assert privs["client_management"] is False

    def test_merge_only_known_keys(self):
        base = default_privileges(AccessLevel.GUEST)
        merged = merge_privileges(base, {"ssh_access": True, "bogus_key": True})
        assert merged["ssh_access"] is True
        assert "bogus_key" not in merged

    def test_merge_preserves_unmentioned(self):
        base = default_privileges(AccessLevel.STANDARD)
        merged = merge_privileges(base, {"ssh_access": False})
        assert merged["ssh_access"] is False
        assert merged["http_access"] is True  # untouched


class TestCheckPrivilege:
    def test_admin_always_has_privilege(self):
        client = {"access_level": "admin"}
        assert check_privilege(client, "ssh_access")
        assert check_privilege(client, "server_management")

    def test_guest_lacks_ssh(self):
        client = {"access_level": "guest"}
        assert not check_privilege(client, "ssh_access")

    def test_explicit_privileges_override(self):
        client = {
            "access_level": "guest",
            "privileges": {**default_privileges(AccessLevel.GUEST), "ssh_access": True},
        }
        assert check_privilege(client, "ssh_access")

    def test_missing_access_level_defaults_standard(self):
        client = {}
        assert check_privilege(client, "ssh_access")
        assert not check_privilege(client, "server_management")


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


class TestComputeExpiresAt:
    def test_no_expiry(self):
        assert compute_expires_at() is None

    def test_ttl_seconds(self):
        now = 1000.0
        result = compute_expires_at(ttl_seconds=3600, now=now)
        assert result == 4600.0

    def test_absolute_expires_at(self):
        result = compute_expires_at(expires_at=9999.0)
        assert result == 9999.0

    def test_expires_at_takes_precedence(self):
        result = compute_expires_at(ttl_seconds=100, expires_at=5000.0, now=1000.0)
        assert result == 5000.0

    def test_zero_ttl_returns_none(self):
        assert compute_expires_at(ttl_seconds=0) is None


class TestCheckExpiryStatus:
    def test_active_no_expiry(self):
        client = {"status": "active"}
        assert check_expiry_status(client) == ClientStatus.ACTIVE

    def test_active_not_yet_expired(self):
        client = {"status": "active", "ttl_expires_at": time.time() + 3600}
        assert check_expiry_status(client) == ClientStatus.ACTIVE

    def test_expired(self):
        client = {"status": "active", "ttl_expires_at": time.time() - 100}
        assert check_expiry_status(client) == ClientStatus.EXPIRED

    def test_revoked_overrides_expiry(self):
        client = {"status": "revoked", "ttl_expires_at": time.time() + 3600}
        assert check_expiry_status(client) == ClientStatus.REVOKED

    def test_suspended(self):
        client = {"status": "suspended"}
        assert check_expiry_status(client) == ClientStatus.SUSPENDED

    def test_missing_status_defaults_active(self):
        client = {}
        assert check_expiry_status(client) == ClientStatus.ACTIVE


class TestExpiryWarningDays:
    def test_permanent_returns_none(self):
        assert expiry_warning_days({}) is None

    def test_expired_returns_zero(self):
        client = {"ttl_expires_at": time.time() - 100}
        assert expiry_warning_days(client) == 0

    def test_days_remaining(self):
        client = {"ttl_expires_at": time.time() + 86400 * 5}
        days = expiry_warning_days(client)
        assert days == 4 or days == 5  # depends on timing


# ---------------------------------------------------------------------------
# Build & Validate
# ---------------------------------------------------------------------------


class TestBuildClientAccessFields:
    def test_defaults(self):
        fields = build_client_access_fields()
        assert fields["access_level"] == "standard"
        assert fields["status"] == "active"
        assert fields["auto_revoke"] is True
        assert fields["description"] == ""
        assert "privileges" in fields
        assert isinstance(fields["created_at"], float)

    def test_custom_level_with_overrides(self):
        fields = build_client_access_fields(
            access_level="custom",
            privileges={"ssh_access": True, "camera_access": False},
        )
        assert fields["access_level"] == "custom"
        assert fields["privileges"]["ssh_access"] is True
        assert fields["privileges"]["camera_access"] is False

    def test_admin_level(self):
        fields = build_client_access_fields(access_level="admin")
        assert fields["privileges"]["full_network_access"] is True


class TestValidateAccessLevelChange:
    def test_owner_can_change_anything(self):
        assert validate_access_level_change("owner", "admin", "guest") is None

    def test_admin_can_change_standard(self):
        assert validate_access_level_change("admin", "standard", "guest") is None

    def test_cannot_assign_owner(self):
        err = validate_access_level_change("owner", "admin", "owner")
        assert err is not None
        assert "owner" in err.lower()

    def test_admin_cannot_modify_owner(self):
        err = validate_access_level_change("admin", "owner", "standard")
        assert err is not None

    def test_standard_cannot_modify(self):
        err = validate_access_level_change("standard", "guest", "admin")
        assert err is not None
