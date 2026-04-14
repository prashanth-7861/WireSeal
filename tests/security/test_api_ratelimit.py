"""Tests for /api/unlock rate limiting (Hardening Phase 1).

Covers:
- _check_rate_limit raises 429 after _UNLOCK_MAX failures in _UNLOCK_WINDOW
- _record_unlock_failure appends a timestamp to the per-IP list
- _clear_unlock_failures wipes the IP's counter after a successful unlock
- Stale entries outside the sliding window are pruned
- Failures from different IPs are tracked independently
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from wireseal import api


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_rate_limit_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Reset module-level rate-limit state and redirect the audit log.

    Rate-limiting uses global dicts; tests must start from a clean slate, and
    the audit-log writes that _check_rate_limit / _record_unlock_failure emit
    must not touch the real ~/.wireseal/audit.log.
    """
    with api._lock:
        api._unlock_attempts.clear()
    monkeypatch.setattr(api, "_AUDIT_PATH", tmp_path / "audit.log")
    yield
    with api._lock:
        api._unlock_attempts.clear()


# ---------------------------------------------------------------------------
# _record_unlock_failure / _clear_unlock_failures
# ---------------------------------------------------------------------------


def test_record_failure_appends_timestamp() -> None:
    api._record_unlock_failure("10.0.0.1")
    assert len(api._unlock_attempts["10.0.0.1"]) == 1
    api._record_unlock_failure("10.0.0.1")
    assert len(api._unlock_attempts["10.0.0.1"]) == 2


def test_different_ips_tracked_independently() -> None:
    api._record_unlock_failure("10.0.0.1")
    api._record_unlock_failure("10.0.0.1")
    api._record_unlock_failure("10.0.0.2")
    assert len(api._unlock_attempts["10.0.0.1"]) == 2
    assert len(api._unlock_attempts["10.0.0.2"]) == 1


def test_clear_removes_ip_entry() -> None:
    api._record_unlock_failure("10.0.0.1")
    api._record_unlock_failure("10.0.0.1")
    api._clear_unlock_failures("10.0.0.1")
    assert "10.0.0.1" not in api._unlock_attempts


def test_clear_nonexistent_ip_is_noop() -> None:
    # Should not raise KeyError
    api._clear_unlock_failures("10.9.9.9")
    assert "10.9.9.9" not in api._unlock_attempts


# ---------------------------------------------------------------------------
# _check_rate_limit — threshold and 429
# ---------------------------------------------------------------------------


def test_check_allows_below_threshold() -> None:
    for _ in range(api._UNLOCK_MAX - 1):
        api._record_unlock_failure("10.0.0.1")
    # 4 failures < 5 → no raise
    api._check_rate_limit("10.0.0.1")


def test_check_raises_429_at_threshold() -> None:
    for _ in range(api._UNLOCK_MAX):
        api._record_unlock_failure("10.0.0.1")
    with pytest.raises(api._ApiError) as excinfo:
        api._check_rate_limit("10.0.0.1")
    assert excinfo.value.status == 429
    assert "too many" in str(excinfo.value).lower()


def test_check_raises_429_above_threshold() -> None:
    for _ in range(api._UNLOCK_MAX + 3):
        api._record_unlock_failure("10.0.0.1")
    with pytest.raises(api._ApiError) as excinfo:
        api._check_rate_limit("10.0.0.1")
    assert excinfo.value.status == 429


def test_rate_limit_is_per_ip() -> None:
    # Blow past the limit on IP 1
    for _ in range(api._UNLOCK_MAX):
        api._record_unlock_failure("10.0.0.1")
    with pytest.raises(api._ApiError):
        api._check_rate_limit("10.0.0.1")
    # IP 2 still has a clean slate
    api._check_rate_limit("10.0.0.2")


# ---------------------------------------------------------------------------
# Sliding-window pruning
# ---------------------------------------------------------------------------


def test_stale_entries_are_pruned(monkeypatch: pytest.MonkeyPatch) -> None:
    """Attempts older than _UNLOCK_WINDOW should be discarded."""
    # Plant stale timestamps directly
    with api._lock:
        stale_ts = time.time() - (api._UNLOCK_WINDOW + 10)
        api._unlock_attempts["10.0.0.1"] = [stale_ts] * api._UNLOCK_MAX

    # Check should prune all stale entries and NOT raise
    api._check_rate_limit("10.0.0.1")
    assert api._unlock_attempts["10.0.0.1"] == []


def test_mixed_stale_and_fresh_prunes_stale_only() -> None:
    now = time.time()
    with api._lock:
        api._unlock_attempts["10.0.0.1"] = [
            now - (api._UNLOCK_WINDOW + 5),  # stale
            now - (api._UNLOCK_WINDOW + 1),  # stale
            now - 5,                          # fresh
            now - 1,                          # fresh
        ]
    api._check_rate_limit("10.0.0.1")
    # Only the two fresh entries survive
    assert len(api._unlock_attempts["10.0.0.1"]) == 2


# ---------------------------------------------------------------------------
# Clear-on-success behavior
# ---------------------------------------------------------------------------


def test_successful_unlock_clears_failures() -> None:
    """After a user recovers from near-lockout, the counter should reset."""
    for _ in range(api._UNLOCK_MAX - 1):
        api._record_unlock_failure("10.0.0.1")
    api._clear_unlock_failures("10.0.0.1")
    # Five NEW failures should be tolerated before 429 fires
    for _ in range(api._UNLOCK_MAX - 1):
        api._record_unlock_failure("10.0.0.1")
    api._check_rate_limit("10.0.0.1")  # should NOT raise


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def test_ratelimit_trip_writes_audit_entry(tmp_path: Path) -> None:
    """Hitting the 429 path should emit an 'unlock-ratelimited' audit entry."""
    for _ in range(api._UNLOCK_MAX):
        api._record_unlock_failure("10.0.0.1")
    with pytest.raises(api._ApiError):
        api._check_rate_limit("10.0.0.1")

    audit_file = api._AUDIT_PATH
    assert audit_file.exists()
    content = audit_file.read_text(encoding="utf-8")
    assert "unlock-ratelimited" in content
    # Failures from _record_unlock_failure should also be recorded
    assert "unlock-failed" in content
