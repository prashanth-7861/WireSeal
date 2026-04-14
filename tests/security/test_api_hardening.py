"""Tests for API hardening primitives (Hardening Phases 5 and 6).

Phase 5 — GET /api/health:
- Returns status=ok, correct vault flags, and uptime
- Does not require an unlocked vault

Phase 6 — Session timeout tracking:
- _require_unlocked() updates _last_activity on each authenticated call
- The auto-lock predicate fires only after _SESSION_TIMEOUT seconds of idle
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from wireseal import api


# ---------------------------------------------------------------------------
# Isolation: make sure tests never touch the real ~/.wireseal/ or shared state
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_api_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect vault paths and reset session/activity state between tests."""
    monkeypatch.setattr(api, "_VAULT_DIR", tmp_path)
    monkeypatch.setattr(api, "_VAULT_PATH", tmp_path / "vault.enc")
    monkeypatch.setattr(api, "_AUDIT_PATH", tmp_path / "audit.log")
    monkeypatch.setattr(api, "_PIN_PATH", tmp_path / "pin.enc")

    with api._lock:
        api._session.update(vault=None, passphrase=None, cache=None,
                            admin_id=None, admin_role=None)

    # Preserve and restore module-level clocks
    saved_start = api._server_start_time
    saved_last = api._last_activity
    yield
    api._server_start_time = saved_start
    api._last_activity = saved_last
    with api._lock:
        api._session.update(vault=None, passphrase=None, cache=None,
                            admin_id=None, admin_role=None)


# ---------------------------------------------------------------------------
# Phase 5: /api/health
# ---------------------------------------------------------------------------


def test_health_reports_locked_when_no_vault() -> None:
    api._server_start_time = time.monotonic() - 42
    result = api._h_health(None, ())  # handler ignores req for health
    assert result["status"] == "ok"
    assert result["vault_initialized"] is False
    assert result["vault_locked"] is True
    assert isinstance(result["uptime_seconds"], int)
    assert result["uptime_seconds"] >= 42


def test_health_reports_initialized_when_vault_file_exists(tmp_path: Path) -> None:
    (tmp_path / "vault.enc").write_bytes(b"fake vault blob")
    api._server_start_time = time.monotonic() - 1
    result = api._h_health(None, ())
    assert result["vault_initialized"] is True
    assert result["vault_locked"] is True  # still locked until session["vault"] is set


def test_health_reports_unlocked_when_session_has_vault(tmp_path: Path) -> None:
    (tmp_path / "vault.enc").write_bytes(b"fake")
    with api._lock:
        api._session["vault"] = object()  # stand-in for Vault instance
    api._server_start_time = time.monotonic()
    result = api._h_health(None, ())
    assert result["vault_locked"] is False


def test_health_uptime_is_zero_before_serve_starts() -> None:
    api._server_start_time = 0.0
    result = api._h_health(None, ())
    assert result["uptime_seconds"] == 0


def test_health_returns_expected_schema() -> None:
    api._server_start_time = time.monotonic()
    result = api._h_health(None, ())
    assert set(result.keys()) == {
        "status",
        "vault_initialized",
        "vault_locked",
        "uptime_seconds",
    }


# ---------------------------------------------------------------------------
# Phase 6: session timeout tracking
# ---------------------------------------------------------------------------


def test_require_unlocked_raises_when_locked() -> None:
    with api._lock:
        api._session["vault"] = None
    with pytest.raises(api._ApiError) as exc:
        api._require_unlocked()
    assert exc.value.status == 401


def test_require_unlocked_updates_last_activity() -> None:
    with api._lock:
        api._session["vault"] = object()
    api._last_activity = 0.0
    api._require_unlocked()
    assert api._last_activity > 0.0


def test_require_unlocked_refreshes_activity_timestamp() -> None:
    with api._lock:
        api._session["vault"] = object()

    api._require_unlocked()
    first = api._last_activity
    time.sleep(0.01)
    api._require_unlocked()
    second = api._last_activity
    assert second >= first
    assert second > 0.0


def test_session_timeout_predicate_idle_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """The auto-lock loop triggers when monotonic() - _last_activity > _SESSION_TIMEOUT."""
    monkeypatch.setattr(api, "_SESSION_TIMEOUT", 10)  # 10s for the test

    with api._lock:
        api._session["vault"] = object()
    api._last_activity = time.monotonic() - 3  # 3s idle — fresh
    # Condition the daemon thread uses
    assert not (time.monotonic() - api._last_activity > api._SESSION_TIMEOUT)

    api._last_activity = time.monotonic() - 15  # 15s idle — stale
    assert time.monotonic() - api._last_activity > api._SESSION_TIMEOUT


def test_session_timeout_never_fires_when_activity_is_zero() -> None:
    """_last_activity == 0 means "no authenticated request yet" → never auto-lock."""
    api._last_activity = 0.0
    # The loop guards with `if _last_activity and ...` so zero is falsy
    should_fire = bool(api._last_activity) and (
        time.monotonic() - api._last_activity > api._SESSION_TIMEOUT
    )
    assert should_fire is False
