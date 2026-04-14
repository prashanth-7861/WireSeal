"""Tests for AuditLog rotation (Hardening Phase 2).

Covers:
- Rotation fires when the current log exceeds MAX_LOG_SIZE
- Rotated files are named audit.log.1 through audit.log.5
- The oldest rotated file is deleted when the archive exceeds MAX_ROTATED
- get_recent_entries() spans rotated files to return the full recent history
- Thread safety: concurrent log() calls never corrupt the file
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from wireseal.security import audit as audit_mod
from wireseal.security.audit import AuditLog, MAX_ROTATED


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for _ in path.read_text(encoding="utf-8").splitlines())


# ---------------------------------------------------------------------------
# Basic rotation
# ---------------------------------------------------------------------------


def test_no_rotation_below_threshold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Entries below MAX_LOG_SIZE should not trigger rotation."""
    # Use a 1 KiB ceiling so we can exercise the threshold cheaply
    monkeypatch.setattr(audit_mod, "MAX_LOG_SIZE", 1024)
    log = AuditLog(tmp_path / "audit.log")
    log.log("action", {"i": 1})
    log.log("action", {"i": 2})

    assert (tmp_path / "audit.log").exists()
    assert not (tmp_path / "audit.log.1").exists()
    assert _count_lines(tmp_path / "audit.log") == 2


def test_rotation_fires_at_threshold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Crossing MAX_LOG_SIZE should rotate audit.log → audit.log.1."""
    monkeypatch.setattr(audit_mod, "MAX_LOG_SIZE", 200)  # tiny ceiling
    log = AuditLog(tmp_path / "audit.log")

    # Write several entries; each JSON line is ~80-100 bytes
    for i in range(10):
        log.log("action", {"index": i, "padding": "x" * 20})

    assert (tmp_path / "audit.log").exists()
    assert (tmp_path / "audit.log.1").exists()


def test_rotation_shifts_existing_archives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existing audit.log.N files should shift to audit.log.(N+1)."""
    monkeypatch.setattr(audit_mod, "MAX_LOG_SIZE", 150)
    log = AuditLog(tmp_path / "audit.log")

    # Force multiple rotations
    for i in range(40):
        log.log("action", {"index": i, "padding": "y" * 20})

    # At least audit.log.1 should exist; with enough churn, .2 and .3 too
    assert (tmp_path / "audit.log.1").exists()
    # The current log should contain the most recent entries
    cur = (tmp_path / "audit.log").read_text(encoding="utf-8").strip().splitlines()
    assert len(cur) >= 1
    last = json.loads(cur[-1])
    assert last["metadata"]["index"] == 39


def test_oldest_rotated_file_is_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Archive depth must be capped at MAX_ROTATED."""
    monkeypatch.setattr(audit_mod, "MAX_LOG_SIZE", 100)  # very tight
    log = AuditLog(tmp_path / "audit.log")

    # Churn enough to force > MAX_ROTATED rotations
    for i in range(200):
        log.log("action", {"index": i, "padding": "z" * 20})

    # Only .1..MAX_ROTATED should be present, never a .(MAX_ROTATED+1)
    overflow = tmp_path / f"audit.log.{MAX_ROTATED + 1}"
    assert not overflow.exists()


# ---------------------------------------------------------------------------
# Cross-file reads
# ---------------------------------------------------------------------------


def test_get_recent_reads_from_rotated_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """get_recent_entries should span current + rotated logs to fill n."""
    # ~1 KiB per file fits several entries and still rotates quickly
    monkeypatch.setattr(audit_mod, "MAX_LOG_SIZE", 1_000)
    log = AuditLog(tmp_path / "audit.log")

    for i in range(30):
        log.log("action", {"index": i, "padding": "a" * 20})

    # At least one rotation should have occurred
    assert (tmp_path / "audit.log.1").exists()

    recent = log.get_recent_entries(n=20)
    assert len(recent) == 20
    # Entries are returned oldest-first within the tail window
    indices = [e.metadata["index"] for e in recent]
    # Must be contiguous and end at 29 (newest)
    assert indices == list(range(10, 30))


def test_get_recent_fewer_than_n_entries(tmp_path: Path) -> None:
    """Requesting more entries than exist returns everything."""
    log = AuditLog(tmp_path / "audit.log")
    log.log("action", {"i": 1})
    log.log("action", {"i": 2})
    log.log("action", {"i": 3})

    recent = log.get_recent_entries(n=100)
    assert len(recent) == 3


def test_get_recent_on_empty_log(tmp_path: Path) -> None:
    """No log file → empty list, no raise."""
    log = AuditLog(tmp_path / "audit.log")
    assert log.get_recent_entries(n=10) == []


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_concurrent_writes_produce_clean_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent log() calls must not interleave or corrupt lines."""
    # Ceiling large enough that rotation does not fire during this test
    # (8 * 25 = 200 entries * ~100 bytes ≈ 20 KiB).
    monkeypatch.setattr(audit_mod, "MAX_LOG_SIZE", 1_000_000)
    log = AuditLog(tmp_path / "audit.log")

    WRITES_PER_THREAD = 25
    THREADS = 8

    def worker(tid: int) -> None:
        for i in range(WRITES_PER_THREAD):
            log.log("action", {"thread": tid, "seq": i})

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # No rotation should have fired at this ceiling
    assert not (tmp_path / "audit.log.1").exists()

    # Every line must parse as JSON and all writes must be accounted for
    lines = (tmp_path / "audit.log").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == THREADS * WRITES_PER_THREAD

    # Track (thread, seq) pairs to confirm nothing was lost or duplicated
    seen: set[tuple[int, int]] = set()
    for line in lines:
        entry = json.loads(line)  # raises on corruption
        assert entry["action"] == "action"
        meta = entry["metadata"]
        pair = (meta["thread"], meta["seq"])
        assert pair not in seen
        seen.add(pair)

    expected = {(t, s) for t in range(THREADS) for s in range(WRITES_PER_THREAD)}
    assert seen == expected
