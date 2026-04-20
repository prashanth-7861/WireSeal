"""Tests for the HIGH-severity security fixes in SECURITY_AUDIT_2026-04-18.

Coverage:
  SEC-001  /api/audit-log now requires an unlocked vault.
  SEC-003  Cross-origin state-changing requests are rejected before the
           handler runs (pre-dispatch, not just in response headers).
  SEC-009  /api/backup/restore rejects backup_path outside the configured
           backup directory / vault dir, plus non-regular files.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from wireseal import api


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_api_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(api, "_VAULT_DIR", tmp_path)
    monkeypatch.setattr(api, "_VAULT_PATH", tmp_path / "vault.enc")
    monkeypatch.setattr(api, "_AUDIT_PATH", tmp_path / "audit.log")
    monkeypatch.setattr(api, "_PIN_PATH", tmp_path / "pin.enc")
    with api._lock:
        api._session.update(vault=None, passphrase=None, cache=None,
                            admin_id=None, admin_role=None)
    yield
    with api._lock:
        api._session.update(vault=None, passphrase=None, cache=None,
                            admin_id=None, admin_role=None)


def _req(body: dict[str, Any] | None = None, *, headers: dict[str, str] | None = None) -> Any:
    r = MagicMock()
    r._json.return_value = body or {}
    r.headers = headers or {}
    return r


# ---------------------------------------------------------------------------
# SEC-001: audit-log authentication
# ---------------------------------------------------------------------------


class TestAuditLogAuth:
    def test_locked_vault_returns_401(self) -> None:
        with pytest.raises(api._ApiError) as exc:
            api._h_audit_log(_req(), ())
        assert exc.value.status == 401

    def test_unlocked_vault_returns_entries(self, tmp_path: Path) -> None:
        (tmp_path / "audit.log").write_text(
            '{"t":"2026-01-01","action":"unlock","actor":"owner"}\n',
            encoding="utf-8",
        )
        with api._lock:
            api._session["vault"] = object()  # stand-in
        result = api._h_audit_log(_req(), ())
        assert "entries" in result
        assert len(result["entries"]) == 1


# ---------------------------------------------------------------------------
# SEC-003: pre-dispatch same-origin enforcement
# ---------------------------------------------------------------------------


class TestSameOriginFilter:
    def _mk_handler(self, method: str, headers: dict[str, str], path: str = "/api/fresh-start") -> api._Handler:
        h = api._Handler.__new__(api._Handler)
        h.rfile = io.BytesIO(b"")
        h.wfile = io.BytesIO()
        h.headers = headers
        h.path = path
        h.command = method
        h.request_version = "HTTP/1.1"

        # Minimal stand-ins for the superclass helpers.
        h.send_response = lambda *a, **kw: None
        h.send_header = lambda *a, **kw: None
        h.end_headers = lambda: None
        h.client_address = ("127.0.0.1", 0)
        return h

    def test_state_changing_method_without_origin_allowed(self) -> None:
        h = self._mk_handler("POST", {})
        # No Origin header → native CLI / curl → must NOT be rejected
        assert h._enforce_same_origin() is False

    def test_state_changing_method_with_allowed_origin(self) -> None:
        h = self._mk_handler("POST", {"Origin": "http://127.0.0.1:8080", "Host": "127.0.0.1:8080"})
        assert h._enforce_same_origin() is False

    def test_state_changing_method_with_localhost_origin(self) -> None:
        h = self._mk_handler("POST", {"Origin": "http://localhost:8080", "Host": "localhost:8080"})
        assert h._enforce_same_origin() is False

    def test_state_changing_method_with_cross_origin_rejected(self) -> None:
        # Capture the _send call to verify the 403 was written.
        sent = []
        h = self._mk_handler("POST", {"Origin": "https://evil.example.com"})
        h._send = lambda data, status=200: sent.append((data, status))
        assert h._enforce_same_origin() is True
        assert sent[0][1] == 403
        assert "Cross-origin" in sent[0][0]["error"]

    def test_state_changing_method_with_subdomain_of_allowed_rejected(self) -> None:
        """Origin must be exactly one of the allowed prefixes — not a suffix."""
        sent = []
        h = self._mk_handler("POST", {"Origin": "http://127.0.0.1.evil.com"})
        h._send = lambda data, status=200: sent.append((data, status))
        assert h._enforce_same_origin() is True
        assert sent[0][1] == 403

    def test_state_changing_methods_list(self) -> None:
        assert "POST"   in api._Handler._STATE_CHANGING_METHODS
        assert "DELETE" in api._Handler._STATE_CHANGING_METHODS
        assert "PUT"    in api._Handler._STATE_CHANGING_METHODS
        assert "PATCH"  in api._Handler._STATE_CHANGING_METHODS
        # GET / OPTIONS must NOT be in the set — browsers' same-origin policy
        # handles reads, and /api/health must stay callable without Origin
        # gymnastics.
        assert "GET"     not in api._Handler._STATE_CHANGING_METHODS
        assert "OPTIONS" not in api._Handler._STATE_CHANGING_METHODS

    def test_https_loopback_origin_allowed(self) -> None:
        """SEC-003 allowlist must accept https://127.0.0.1 (reverse-proxy TLS)."""
        h = self._mk_handler("POST", {"Origin": "https://127.0.0.1:8443", "Host": "127.0.0.1:8443"})
        assert h._enforce_same_origin() is False

    def test_https_localhost_origin_allowed(self) -> None:
        h = self._mk_handler("POST", {"Origin": "https://localhost:8443", "Host": "localhost:8443"})
        assert h._enforce_same_origin() is False


# ---------------------------------------------------------------------------
# SEC-009: backup restore path allowlist
# ---------------------------------------------------------------------------


class TestBackupRestoreAllowlist:
    def _install_unlocked_session(self, tmp_path: Path, backup_dir: Path | None) -> None:
        vault = MagicMock()
        vault._path = tmp_path / "vault.enc"
        cache: dict = {"backup_config": {}}
        if backup_dir is not None:
            cache["backup_config"] = {"local_path": str(backup_dir)}
        with api._lock:
            api._session["vault"] = vault
            api._session["passphrase"] = None
            api._session["cache"] = cache
            api._session["admin_id"] = "owner"

    def test_rejects_missing_backup_path(self, tmp_path: Path) -> None:
        self._install_unlocked_session(tmp_path, backup_dir=tmp_path / "backups")
        with pytest.raises(api._ApiError) as exc:
            api._h_backup_restore(_req({"backup_path": "", "passphrase": "x"}), ())
        assert exc.value.status == 400

    def test_rejects_nonexistent_file(self, tmp_path: Path) -> None:
        self._install_unlocked_session(tmp_path, backup_dir=tmp_path / "backups")
        with pytest.raises(api._ApiError) as exc:
            api._h_backup_restore(_req({
                "backup_path": str(tmp_path / "nope.enc"),
                "passphrase": "x",
            }), ())
        assert exc.value.status == 404

    def test_rejects_backup_outside_allowlist(self, tmp_path: Path) -> None:
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        self._install_unlocked_session(tmp_path, backup_dir=backup_dir)
        # File exists, but is OUTSIDE the allowlisted backup dir and vault dir.
        import tempfile
        with tempfile.TemporaryDirectory() as outside:
            outside_file = Path(outside) / "foreign.enc"
            outside_file.write_bytes(b"fake ciphertext")
            with pytest.raises(api._ApiError) as exc:
                api._h_backup_restore(_req({
                    "backup_path":  str(outside_file),
                    "passphrase":   "wrong",
                }), ())
            assert exc.value.status == 403
            assert "allowlisted" in str(exc.value).lower()

    def test_rejects_dotdot_in_path(self, tmp_path: Path) -> None:
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        self._install_unlocked_session(tmp_path, backup_dir=backup_dir)
        # Even if the resolved path happens to land inside the allowed dir,
        # literal ``..`` in the request is rejected to remove ambiguity.
        bad = backup_dir / "x"
        bad.write_bytes(b"x")
        traversal = str(backup_dir / ".." / "backups" / "x")
        with pytest.raises(api._ApiError) as exc:
            api._h_backup_restore(_req({
                "backup_path": traversal,
                "passphrase":  "x",
            }), ())
        assert exc.value.status == 400

    def test_rejects_directory_as_backup(self, tmp_path: Path) -> None:
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        subdir = backup_dir / "not-a-file"
        subdir.mkdir()
        self._install_unlocked_session(tmp_path, backup_dir=backup_dir)
        with pytest.raises(api._ApiError) as exc:
            api._h_backup_restore(_req({
                "backup_path": str(subdir),
                "passphrase":  "x",
            }), ())
        assert exc.value.status == 400

    def test_rejects_symlink_to_device_inside_allowed_dir(self, tmp_path: Path) -> None:
        """SEC-009 defense-in-depth: a symlink inside an allowlisted dir that
        resolves to a device file must still be rejected.

        `resolve(strict=True)` follows the symlink; `is_file()` on the
        resulting device path returns False; handler raises 400.
        """
        import os
        if not hasattr(os, "symlink"):
            pytest.skip("symlink unsupported")
        import sys
        device_path = "/dev/null" if sys.platform != "win32" else None
        if device_path is None or not os.path.exists(device_path):
            pytest.skip("no device file available on this platform")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        self._install_unlocked_session(tmp_path, backup_dir=backup_dir)
        symlink = backup_dir / "evil.enc"
        try:
            os.symlink(device_path, symlink)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation not permitted")
        with pytest.raises(api._ApiError) as exc:
            api._h_backup_restore(_req({
                "backup_path": str(symlink),
                "passphrase":  "x",
            }), ())
        # Either 400 (not a regular file) or 404 (resolve couldn't stat device)
        # — both are correct rejections, neither proceeds to restore.
        assert exc.value.status in (400, 404)

    def test_rejects_when_no_backup_config(self, tmp_path: Path) -> None:
        """If the vault has no local_path AND file is outside vault dir → 400."""
        self._install_unlocked_session(tmp_path, backup_dir=None)
        # Put the backup inside the vault dir so resolve() succeeds; with no
        # local_path set, the vault dir is the only allowed root.
        f = tmp_path / "emergency.enc"
        f.write_bytes(b"x")
        # This path is inside _VAULT_DIR → passes allowlist, reaches the
        # restore engine, which will fail decryption and raise _ApiError.
        # The point of this test: we exercise the "no config, but vault dir
        # is still a fallback root" branch.
        # We don't require success — only that allowlist doesn't 403.
        with pytest.raises(api._ApiError) as exc:
            api._h_backup_restore(_req({
                "backup_path": str(f),
                "passphrase":  "x",
            }), ())
        # Not 403 — so allowlist accepted it. 401/500 come from restore engine.
        assert exc.value.status != 403

    def test_locked_vault_rejects_before_path_check(self, tmp_path: Path) -> None:
        # No session installed → _require_unlocked fires first.
        with pytest.raises(api._ApiError) as exc:
            api._h_backup_restore(_req({
                "backup_path": str(tmp_path),
                "passphrase":  "x",
            }), ())
        assert exc.value.status == 401
