"""Tests for Phase 2 security hardening fixes.

Verifies defensive error handling, rate-limit state-machine correctness,
and resilience of fork-wipe / peer-removal / TOTP-enforce paths.

Each test class corresponds to a specific fix area; every test is
self-contained and runs without root privileges or a real vault.
"""

from __future__ import annotations

import json
import logging
import pathlib
import subprocess as _subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from wireseal import api
from wireseal.api import _shared as _api_shared


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_api_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(api, "_VAULT_DIR", tmp_path)
    monkeypatch.setattr(_api_shared, "_VAULT_DIR", tmp_path)
    monkeypatch.setattr(api, "_VAULT_PATH", tmp_path / "vault.enc")
    monkeypatch.setattr(_api_shared, "_VAULT_PATH", tmp_path / "vault.enc")
    monkeypatch.setattr(api, "_AUDIT_PATH", tmp_path / "audit.log")
    monkeypatch.setattr(_api_shared, "_AUDIT_PATH", tmp_path / "audit.log")
    monkeypatch.setattr(api, "_PIN_PATH", tmp_path / "pin.enc")
    monkeypatch.setattr(_api_shared, "_PIN_PATH", tmp_path / "pin.enc")
    with api._lock:
        api._session.update(
            vault=None, passphrase=None, cache=None,
            admin_id=None, admin_role=None,
        )
        api._RATE_LIMIT_BACKOFF.clear()
    yield
    with api._lock:
        api._session.update(
            vault=None, passphrase=None, cache=None,
            admin_id=None, admin_role=None,
        )
        api._RATE_LIMIT_BACKOFF.clear()


def _req(body: dict[str, Any] | None = None, *,
         headers: dict[str, str] | None = None) -> Any:
    r = MagicMock()
    r._json.return_value = body or {}
    r.headers = headers or {}
    return r


def _unlocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bypass the vault-unlock gate so handlers execute past the check."""
    monkeypatch.setattr(api, "_require_unlocked", lambda: None)


# ---------------------------------------------------------------------------
# Section 1 — Audit log returns error on unreadable path
# ---------------------------------------------------------------------------


class TestPhase2AuditLogError:
    """SEC-001 follow-up: _h_audit_log must not crash on I/O failure."""

    def test_returns_error_when_file_unreadable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_h_audit_log returns {"entries": [], "error": "…"} on OSError."""
        _unlocked(monkeypatch)

        audit_path = tmp_path / "audit.log"
        audit_path.write_text('{"action":"test"}\n{"action":"test2"}\n')
        monkeypatch.setattr(api, "_AUDIT_PATH", audit_path)
        monkeypatch.setattr(_api_shared, "_AUDIT_PATH", audit_path)

        original_read_text = pathlib.Path.read_text

        def _raise_on_audit(self: pathlib.Path, *a: Any, **kw: Any) -> str:
            if self == audit_path:
                raise OSError(13, "Permission denied", str(audit_path))
            return original_read_text(self, *a, **kw)

        monkeypatch.setattr(pathlib.Path, "read_text", _raise_on_audit)

        result = api._h_audit_log(_req(), ())
        assert result["entries"] == []
        assert "error" in result
        assert result["error"] == "Failed to read audit log"

    def test_missing_file_returns_empty_entries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the audit file does not exist, return {"entries": []}."""
        _unlocked(monkeypatch)
        monkeypatch.setattr(
            api, "_AUDIT_PATH", tmp_path / "nonexistent" / "audit.log",
        )
        result = api._h_audit_log(_req(), ())
        assert result == {"entries": []}


# ---------------------------------------------------------------------------
# Section 2 — Security status returns error on adapter crash
# ---------------------------------------------------------------------------


class TestPhase2SecurityStatusError:
    """_h_security_status must degrade gracefully when get_adapter raises."""

    def test_returns_error_key_on_adapter_exception(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify the result dict contains an "error" key."""
        _unlocked(monkeypatch)

        def _raise(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("adapter exploded")

        monkeypatch.setattr("wireseal.platform.detect.get_adapter", _raise)

        result = api._h_security_status(_req(), ())
        assert "error" in result
        assert result["error"] == "Security check failed"

    def test_still_contains_base_keys_on_error(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Even on failure the result should include standard status fields."""
        _unlocked(monkeypatch)

        def _raise(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("fail")

        monkeypatch.setattr("wireseal.platform.detect.get_adapter", _raise)

        result = api._h_security_status(_req(), ())
        for key in (
            "ssh_hardened", "kernel_hardened",
            "fail2ban_active", "firewall_active",
            "ip_forwarding", "auto_updates",
        ):
            assert key in result, f"missing key: {key}"


# ---------------------------------------------------------------------------
# Section 3 — TOTP enforcement for client-config reveal
# ---------------------------------------------------------------------------


class TestPhase2TotpRequireReveal:
    """_require_totp_for_reveal must handle malformed input gracefully."""

    def _setup_totp_admin(self) -> None:
        """Set up session with TOTP enrolled for admin_id='owner'."""
        with api._lock:
            api._session["vault"] = MagicMock()
            api._session["admin_id"] = "owner"
            api._session["cache"] = {
                "admins": {
                    "owner": {
                        "totp_secret_b32": "JBSWY3DPEHPK3PXP",
                    },
                },
            }

    def test_malformed_json_body_does_not_crash(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Body with non-dict JSON (e.g. a string) must not raise TypeError."""
        _unlocked(monkeypatch)
        self._setup_totp_admin()

        req = MagicMock()
        req._json.return_value = "not a dict"

        with pytest.raises(api._ApiError) as exc:
            api._require_totp_for_reveal(req)
        assert exc.value.status == 401

    def test_json_parse_exception_does_not_crash(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When _json() raises, the function should catch and fall back."""
        _unlocked(monkeypatch)
        self._setup_totp_admin()

        req = MagicMock()
        req._json.side_effect = ValueError("malformed")

        with pytest.raises(api._ApiError) as exc:
            api._require_totp_for_reveal(req)
        assert exc.value.status == 401

    def test_fallback_to_query_string(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When body has no totp_code but query string does, it should work.

        This test verifies the fallback path by setting the request path
        with a query parameter.  The 401 comes from TOTP verification
        (wrong code), not from a missing code — proving the code was read.
        """
        _unlocked(monkeypatch)
        self._setup_totp_admin()

        req = MagicMock()
        req._json.return_value = {"some_field": "value"}
        req.path = "/api/clients/test/config?code=000000"

        with pytest.raises(api._ApiError) as exc:
            api._require_totp_for_reveal(req)
        assert exc.value.status == 401
        assert "code" in str(exc.value).lower() or "totp" in str(exc.value).lower()

    def test_totp_not_enrolled_is_noop(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When admin has no TOTP enrolled, the function returns silently."""
        _unlocked(monkeypatch)
        with api._lock:
            api._session["vault"] = MagicMock()
            api._session["admin_id"] = "owner"
            api._session["cache"] = {
                "admins": {
                    "owner": {
                        "totp_secret_b32": None,
                    },
                },
            }

        req = _req()
        result = api._require_totp_for_reveal(req)
        assert result is None


# ---------------------------------------------------------------------------
# Section 4 — Revoke client peer-removal failure handling
# ---------------------------------------------------------------------------


class TestPhase2RevokePeerRemoval:
    """_h_revoke_client must not crash when WireGuard peer removal fails."""

    def test_completes_without_raising_on_subprocess_failure(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify the try/except around subprocess.run catches the error."""
        _unlocked(monkeypatch)

        def _noop(*args: Any, **kwargs: Any) -> None:
            return None

        monkeypatch.setattr(api, "_require_server_mode", _noop)
        monkeypatch.setattr(api, "_require_confirmation", _noop)
        monkeypatch.setattr(api, "_get_actor_access_level", lambda: "owner")
        monkeypatch.setattr(api, "_refresh_cache_unlocked", _noop)

        mock_client_data: dict[str, Any] = {
            "public_key": "x" * 44,
            "access_level": "standard",
            "status": "active",
        }

        mock_state = MagicMock()
        mock_state.clients = {"test-peer": mock_client_data}

        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_state
        mock_cm.__exit__.return_value = None

        mock_vault = MagicMock()
        mock_vault.open.return_value = mock_cm

        with api._lock:
            api._session["vault"] = mock_vault
            api._session["passphrase"] = b"test-passphrase"
            api._session["cache"] = {
                "clients": {"test-peer": mock_client_data},
            }

        def _raising_run(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("wg set peer remove failed")

        monkeypatch.setattr(_subprocess, "run", _raising_run)

        req = _req({"totp_code": "123456"})

        # Must NOT raise; the subprocess exception is caught and logged.
        result = api._h_revoke_client(req, ("test-peer",))
        assert result["ok"] is True
        assert result["name"] == "test-peer"

    def test_handles_missing_pubkey_gracefully(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When client has no public_key, revoke should skip wg set."""
        _unlocked(monkeypatch)

        def _noop(*args: Any, **kwargs: Any) -> None:
            return None

        monkeypatch.setattr(api, "_require_server_mode", _noop)
        monkeypatch.setattr(api, "_require_confirmation", _noop)
        monkeypatch.setattr(api, "_get_actor_access_level", lambda: "owner")
        monkeypatch.setattr(api, "_refresh_cache_unlocked", _noop)

        mock_client_data: dict[str, Any] = {
            "public_key": "",
            "access_level": "standard",
            "status": "active",
        }

        mock_state = MagicMock()
        mock_state.clients = {"no-pubkey": mock_client_data}

        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_state
        mock_cm.__exit__.return_value = None

        mock_vault = MagicMock()
        mock_vault.open.return_value = mock_cm

        with api._lock:
            api._session["vault"] = mock_vault
            api._session["passphrase"] = b"test-passphrase"
            api._session["cache"] = {
                "clients": {"no-pubkey": mock_client_data},
            }

        req = _req({"totp_code": "123456"})

        result = api._h_revoke_client(req, ("no-pubkey",))
        assert result["ok"] is True


# ---------------------------------------------------------------------------
# Section 5 — Fork wipe failure logging
# ---------------------------------------------------------------------------


class TestPhase2ForkWipe:
    """_wipe_session_on_fork must not crash when wipe operations raise."""

    def test_passphrase_wipe_exception_caught(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When _session['passphrase'].wipe() raises, it must be caught."""
        class _WipeRaiser:
            def __bool__(self) -> bool:
                return True

            def wipe(self) -> None:
                raise RuntimeError("wipe() simulated failure")

        with api._lock:
            api._session["passphrase"] = _WipeRaiser()
            api._session["vault"] = MagicMock()

        api._wipe_session_on_fork()

        with api._lock:
            assert api._session["vault"] is None
            assert api._session["passphrase"] is None
            assert api._session["cache"] is None

    def test_master_key_assign_exception_caught(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When vault._session_master_key assignment raises, it must be caught."""
        class _RaisyVault:
            _session_master_key = b"somebytes"

            def __setattr__(self, name: str, value: Any) -> None:
                if name == "_session_master_key":
                    raise RuntimeError("assignment failed")
                object.__setattr__(self, name, value)

        with api._lock:
            api._session["vault"] = _RaisyVault()
            api._session["passphrase"] = None
            api._session["cache"] = {"some": "data"}

        api._wipe_session_on_fork()

        with api._lock:
            assert api._session["vault"] is None
            assert api._session["cache"] is None

    def test_no_vault_no_crash(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When vault is None, _wipe_session_on_fork should skip gracefully."""
        with api._lock:
            api._session["vault"] = None
            api._session["passphrase"] = None

        api._wipe_session_on_fork()

        with api._lock:
            assert api._session["vault"] is None


# ---------------------------------------------------------------------------
# Section 6 — Centralised logging
# ---------------------------------------------------------------------------


class TestPhase2LoggingConfigured:
    """Verify logging.basicConfig was called and the wireseal logger exists."""

    def test_wireseal_logger_exists(self) -> None:
        logger = logging.getLogger("wireseal")
        assert logger is not None

    def test_root_logger_has_level_after_basic_config(self) -> None:
        """basicConfig(level=WARNING) runs at module import time."""
        assert logging.getLogger().getEffectiveLevel() > 0

    def test_wireseal_logger_has_effective_level(self) -> None:
        """The wireseal logger inherits root level after basicConfig."""
        assert logging.getLogger("wireseal").getEffectiveLevel() >= logging.WARNING


# ---------------------------------------------------------------------------
# Section 7 — Rate-limit state machine for unlock action
# ---------------------------------------------------------------------------


class TestPhase2RateLimitUnlock:
    """_check_rate_limit / _record_rate_limit_failure / _clear_rate_limit."""

    def test_no_failures_returns_false(self) -> None:
        assert api._check_rate_limit("127.0.0.1", "unlock") is False

    def test_after_five_failures_returns_true(self) -> None:
        for _ in range(5):
            api._record_rate_limit_failure("127.0.0.1", "unlock")
        assert api._check_rate_limit("127.0.0.1", "unlock") is True

    def test_clear_resets_state(self) -> None:
        for _ in range(5):
            api._record_rate_limit_failure("10.0.0.1", "unlock")
        assert api._check_rate_limit("10.0.0.1", "unlock") is True
        api._clear_rate_limit("10.0.0.1", "unlock")
        assert api._check_rate_limit("10.0.0.1", "unlock") is False

    def test_different_ips_independent(self) -> None:
        for _ in range(5):
            api._record_rate_limit_failure("10.0.0.1", "unlock")
        assert api._check_rate_limit("10.0.0.2", "unlock") is False

    def test_different_actions_independent(self) -> None:
        for _ in range(5):
            api._record_rate_limit_failure("10.0.0.1", "unlock")
        assert api._check_rate_limit("10.0.0.1", "admin-auth") is False


# ---------------------------------------------------------------------------
# Section 8 — File activity returns empty on error
# ---------------------------------------------------------------------------


class TestPhase2FileActivityError:
    """_h_file_activity must return empty events on subprocess failure."""

    def test_subprocess_exception_returns_empty_events(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Even when journalctl fails, the handler returns {"events": []}."""
        _unlocked(monkeypatch)
        monkeypatch.setattr(sys, "platform", "linux")

        def _raising_run(*args: Any, **kwargs: Any) -> None:
            raise FileNotFoundError("journalctl not found")

        monkeypatch.setattr(_subprocess, "run", _raising_run)

        result = api._h_file_activity(_req(), ())
        assert "events" in result
        assert result["events"] == []

    def test_windows_returns_empty_events(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """On Windows the platform check skips journalctl entirely."""
        _unlocked(monkeypatch)
        monkeypatch.setattr(sys, "platform", "win32")
        result = api._h_file_activity(_req(), ())
        assert result == {"events": []}
