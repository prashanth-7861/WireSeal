"""Tests for Phase 5.3: configurable settings with env-var overrides."""

import importlib
import os

import pytest


def _reload_settings():
    """Force-reload the settings module to pick up fresh env vars."""
    from wireseal.config import settings
    importlib.reload(settings)
    return settings


class TestConfigDefaults:
    """All settings must have sensible default values (no env needed)."""

    def test_session_timeout_default(self):
        s = _reload_settings()
        assert s.SESSION_TIMEOUT == 900

    def test_admin_timeout_default(self):
        s = _reload_settings()
        assert s.ADMIN_TIMEOUT == 1800

    def test_unlock_window_default(self):
        s = _reload_settings()
        assert s.UNLOCK_WINDOW == 300

    def test_unlock_max_default(self):
        s = _reload_settings()
        assert s.UNLOCK_MAX == 5

    def test_heartbeat_interval_default(self):
        s = _reload_settings()
        assert s.HEARTBEAT_MIN_INTERVAL == 30.0

    def test_float_type(self):
        s = _reload_settings()
        assert isinstance(s.HEARTBEAT_MIN_INTERVAL, float)

    def test_int_type(self):
        s = _reload_settings()
        assert isinstance(s.SESSION_TIMEOUT, int)

    def test_wg_iface_default(self):
        s = _reload_settings()
        assert s.WG_IFACE == "wg0"

    def test_max_body_size_default(self):
        s = _reload_settings()
        assert s.MAX_BODY_SIZE == 1048576

    def test_pin_max_attempts_default(self):
        s = _reload_settings()
        assert s.PIN_MAX_ATTEMPTS == 5

    def test_totp_window_default(self):
        s = _reload_settings()
        assert s.TOTP_WINDOW == 60

    def test_totp_max_fails_default(self):
        s = _reload_settings()
        assert s.TOTP_MAX_FAILS == 3

    def test_fresh_start_ttl_default(self):
        s = _reload_settings()
        assert s.FRESH_START_TTL_SECONDS == 120

    def test_admin_max_fails_default(self):
        s = _reload_settings()
        assert s.ADMIN_MAX_FAILS == 3

    def test_client_creation_limit_default(self):
        s = _reload_settings()
        assert s.CLIENT_CREATION_LIMIT == 50

    def test_sftp_min_interval_default(self):
        s = _reload_settings()
        assert s.SFTP_MIN_INTERVAL == 0.05

    def test_sftp_max_bytes_default(self):
        s = _reload_settings()
        assert s.SFTP_MAX_BYTES == 52428800

    def test_rate_limit_defaults(self):
        s = _reload_settings()
        assert s.RATE_LIMIT_5 == 30
        assert s.RATE_LIMIT_10 == 300
        assert s.RATE_LIMIT_20 == 1800


class TestConfigEnvOverrides:
    """Environment variables must override default values."""

    def test_env_override_int(self, monkeypatch):
        monkeypatch.setenv("WIRESEAL_SESSION_TIMEOUT", "1800")
        s = _reload_settings()
        assert s.SESSION_TIMEOUT == 1800

    def test_env_override_float(self, monkeypatch):
        monkeypatch.setenv("WIRESEAL_HEARTBEAT_MIN_INTERVAL", "15.5")
        s = _reload_settings()
        assert s.HEARTBEAT_MIN_INTERVAL == 15.5

    def test_env_override_str(self, monkeypatch):
        monkeypatch.setenv("WIRESEAL_WG_IFACE", "wg1")
        s = _reload_settings()
        assert s.WG_IFACE == "wg1"

    def test_env_override_zero(self, monkeypatch):
        monkeypatch.setenv("WIRESEAL_UNLOCK_WINDOW", "0")
        s = _reload_settings()
        assert s.UNLOCK_WINDOW == 0

    def test_env_override_big_value(self, monkeypatch):
        monkeypatch.setenv("WIRESEAL_MAX_BODY_SIZE", "9999999")
        s = _reload_settings()
        assert s.MAX_BODY_SIZE == 9999999

    def test_env_override_invalid_int_ignored(self, monkeypatch):
        monkeypatch.setenv("WIRESEAL_SESSION_TIMEOUT", "not-a-number")
        s = _reload_settings()
        assert s.SESSION_TIMEOUT == 900  # falls back to default

    def test_env_override_invalid_float_ignored(self, monkeypatch):
        monkeypatch.setenv("WIRESEAL_HEARTBEAT_MIN_INTERVAL", "bad-float")
        s = _reload_settings()
        assert s.HEARTBEAT_MIN_INTERVAL == 30.0  # falls back to default

    def test_env_override_negative_int(self, monkeypatch):
        monkeypatch.setenv("WIRESEAL_ADMIN_TIMEOUT", "-1")
        s = _reload_settings()
        assert s.ADMIN_TIMEOUT == -1

    def test_env_override_multiple(self, monkeypatch):
        monkeypatch.setenv("WIRESEAL_SESSION_TIMEOUT", "300")
        monkeypatch.setenv("WIRESEAL_ADMIN_TIMEOUT", "600")
        monkeypatch.setenv("WIRESEAL_WG_IFACE", "wg-custom")
        s = _reload_settings()
        assert s.SESSION_TIMEOUT == 300
        assert s.ADMIN_TIMEOUT == 600
        assert s.WG_IFACE == "wg-custom"

    def test_env_not_set_uses_default(self):
        """When no env var is set, the default must be used."""
        s = _reload_settings()
        assert s.SESSION_TIMEOUT == 900


class TestConfigSharedWiring:
    """Verify that _shared.py correctly picks up settings values."""

    def test_shared_session_timeout_matches_config(self):
        from wireseal.api._shared import _SESSION_TIMEOUT
        from wireseal.config.settings import SESSION_TIMEOUT
        assert _SESSION_TIMEOUT == SESSION_TIMEOUT

    def test_shared_admin_timeout_matches_config(self):
        from wireseal.api._shared import _ADMIN_TIMEOUT
        from wireseal.config.settings import ADMIN_TIMEOUT
        assert _ADMIN_TIMEOUT == ADMIN_TIMEOUT

    def test_shared_max_body_size_matches_config(self):
        from wireseal.api._shared import _MAX_BODY_SIZE
        from wireseal.config.settings import MAX_BODY_SIZE
        assert _MAX_BODY_SIZE == MAX_BODY_SIZE

    def test_shared_totp_window_matches_config(self):
        from wireseal.api._shared import _TOTP_WINDOW
        from wireseal.config.settings import TOTP_WINDOW
        assert _TOTP_WINDOW == TOTP_WINDOW

    def test_shared_wg_iface_matches_config(self):
        from wireseal.api._shared import _WG_IFACE
        from wireseal.config.settings import WG_IFACE
        assert _WG_IFACE == WG_IFACE

    def test_shared_totp_session_hours_matches_config(self):
        from wireseal.api._shared import _TOTP_SESSION_HOURS
        from wireseal.config.settings import TOTP_SESSION_HOURS
        assert _TOTP_SESSION_HOURS == TOTP_SESSION_HOURS


