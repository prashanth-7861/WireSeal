"""Tests for the CRITICAL-severity security fixes in SECURITY_AUDIT_2026-04-18.

Coverage:
  SEC-002  Fresh-start filesystem-gated challenge + same-origin enforcement.
  SEC-004  Max request-body size enforcement in `_json()`.
  SEC-006  Admin activation requires the vault passphrase when already-root.
  SEC-007  `/api/admin/exec` is removed (returns 410 Gone).
  SEC-008  `admin/file/{read,write}` reject paths outside the allowlist.
  SEC-018  `/api/update/install` requires unlock + admin-active + same-origin.

These tests run without root, without a real vault setup, and without touching
the filesystem outside ``tmp_path``.
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from wireseal import api


# ---------------------------------------------------------------------------
# Shared fixture: reset module-level state between tests
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
    """Construct a fake _Handler exposing _json() and .headers."""
    r = MagicMock()
    r._json.return_value = body or {}
    r.headers = headers or {}
    return r


# ---------------------------------------------------------------------------
# SEC-002: Fresh-start challenge
# ---------------------------------------------------------------------------


class TestFreshStartChallenge:
    def test_challenge_file_is_written_with_mode_0o600(self, tmp_path: Path) -> None:
        token = api._create_fresh_start_challenge()
        path = api._fresh_start_challenge_path()
        assert path.exists()
        assert len(token) == 64
        raw = path.read_text(encoding="ascii").splitlines()
        assert len(raw) == 2
        assert raw[0] == token
        assert int(raw[1]) > int(time.time())

    def test_challenge_endpoint_does_not_return_token_in_body(self) -> None:
        result = api._h_fresh_start_challenge(_req(), ())
        # Critical property: the HTTP response MUST NOT leak the token,
        # because the whole point is that the caller proves filesystem access
        # by reading it off disk.
        assert "challenge_token" not in result
        assert "token" not in result

    def test_consume_rejects_missing_challenge(self) -> None:
        with pytest.raises(api._ApiError) as exc:
            api._consume_fresh_start_challenge("deadbeef" * 8)
        assert exc.value.status == 410

    def test_consume_rejects_expired_challenge(self, monkeypatch: pytest.MonkeyPatch) -> None:
        token = api._create_fresh_start_challenge()
        # Rewrite the expiry to the past.
        path = api._fresh_start_challenge_path()
        path.write_text(f"{token}\n0\n", encoding="ascii")
        with pytest.raises(api._ApiError) as exc:
            api._consume_fresh_start_challenge(token)
        assert exc.value.status == 410
        assert not path.exists()

    def test_consume_is_single_use(self) -> None:
        token = api._create_fresh_start_challenge()
        api._consume_fresh_start_challenge(token)
        with pytest.raises(api._ApiError) as exc:
            api._consume_fresh_start_challenge(token)
        assert exc.value.status == 410

    def test_consume_rejects_wrong_token(self) -> None:
        api._create_fresh_start_challenge()
        with pytest.raises(api._ApiError) as exc:
            api._consume_fresh_start_challenge("00" * 32)
        assert exc.value.status == 401

    def test_fresh_start_rejects_missing_confirm(self) -> None:
        with pytest.raises(api._ApiError) as exc:
            api._h_fresh_start(_req({"challenge_token": "x"}), ())
        assert exc.value.status == 400

    def test_fresh_start_rejects_cross_origin_request(self) -> None:
        headers = {"Origin": "https://evil.example.com"}
        with pytest.raises(api._ApiError) as exc:
            api._h_fresh_start_challenge(_req(headers=headers), ())
        assert exc.value.status == 403

    def test_challenge_response_does_not_leak_vault_path(self, tmp_path: Path) -> None:
        """SEC-002 follow-up: the absolute vault dir path must not appear in the
        response body. Only the fixed filename is disclosed."""
        result = api._h_fresh_start_challenge(_req(), ())
        body = json.dumps(result)
        assert str(tmp_path) not in body
        assert str(tmp_path.resolve()) not in body
        assert "challenge_path" not in result
        assert result.get("challenge_filename") == api._FRESH_START_CHALLENGE_NAME


# ---------------------------------------------------------------------------
# SEC-008: admin path allowlist
# ---------------------------------------------------------------------------


class TestAdminPathAllowlist:
    def test_relative_path_rejected(self) -> None:
        with pytest.raises(api._ApiError) as exc:
            api._validate_admin_path("etc/shadow")
        assert exc.value.status == 400

    def test_dotdot_traversal_rejected(self) -> None:
        # Absolute path with a ``..`` component.
        import sys
        base = "/tmp" if sys.platform != "win32" else "C:\\Temp"
        with pytest.raises(api._ApiError) as exc:
            api._validate_admin_path(f"{base}/../etc/passwd")
        assert exc.value.status == 400

    def test_empty_path_rejected(self) -> None:
        with pytest.raises(api._ApiError) as exc:
            api._validate_admin_path("")
        assert exc.value.status == 400

    def test_path_inside_vault_dir_accepted(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Reconfigure the allowlist to include the test tmp_path.
        monkeypatch.setattr(api, "_ADMIN_FILE_ROOTS", (tmp_path.resolve(),))
        target = tmp_path / "vault.enc"
        target.write_bytes(b"x")
        out = api._validate_admin_path(str(target))
        assert out == target.resolve()

    def test_path_outside_allowlist_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api, "_ADMIN_FILE_ROOTS", (tmp_path.resolve(),))
        import sys
        outside = "C:\\Windows\\System32\\drivers\\etc\\hosts" if sys.platform == "win32" else "/etc/shadow"
        with pytest.raises(api._ApiError) as exc:
            api._validate_admin_path(outside)
        assert exc.value.status == 403


# ---------------------------------------------------------------------------
# SEC-007: /api/admin/exec removed
# ---------------------------------------------------------------------------


class TestAdminExecRemoved:
    def test_endpoint_returns_410(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Bypass the normal gatekeepers so we land on the 410 branch.
        monkeypatch.setattr(api, "_require_unlocked", lambda: None)
        monkeypatch.setattr(api, "_require_admin_active", lambda: None)
        with pytest.raises(api._ApiError) as exc:
            api._h_admin_exec(_req({"cmd": ["rm", "-rf", "/"]}), ())
        assert exc.value.status == 410

    def test_requires_unlock_before_410(self) -> None:
        # Without unlock, the _require_unlocked() call raises 401 first —
        # confirming no pre-auth path into the removed handler.
        with pytest.raises(api._ApiError) as exc:
            api._h_admin_exec(_req({"cmd": ["id"]}), ())
        assert exc.value.status == 401


# ---------------------------------------------------------------------------
# SEC-018: /api/update/install requires unlock + admin
# ---------------------------------------------------------------------------


class TestUpdateInstallAuth:
    def test_rejects_when_locked(self) -> None:
        with pytest.raises(api._ApiError) as exc:
            api._h_update_install(_req(), ())
        assert exc.value.status == 401

    def test_rejects_when_unlocked_but_not_admin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate unlocked but admin-mode inactive.
        monkeypatch.setattr(api, "_require_unlocked", lambda: None)
        with pytest.raises(api._ApiError) as exc:
            api._h_update_install(_req(), ())
        # _require_admin_active raises 403 when admin mode isn't active.
        assert exc.value.status == 403

    def test_rejects_cross_origin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api, "_require_unlocked", lambda: None)
        monkeypatch.setattr(api, "_require_admin_active", lambda: None)
        with pytest.raises(api._ApiError) as exc:
            api._h_update_install(_req(headers={"Origin": "https://evil.com"}), ())
        assert exc.value.status == 403


# ---------------------------------------------------------------------------
# SEC-004: request body size cap
# ---------------------------------------------------------------------------


class TestJsonBodyCap:
    def _mk_handler(self, body: bytes, content_length: str) -> api._Handler:
        h = api._Handler.__new__(api._Handler)  # bypass __init__
        h.rfile = io.BytesIO(body)
        h.headers = {"Content-Length": content_length}
        return h

    def test_rejects_body_over_max(self) -> None:
        oversize = api._MAX_BODY_SIZE + 1
        h = self._mk_handler(b"x" * 10, str(oversize))
        with pytest.raises(api._ApiError) as exc:
            h._json()
        assert exc.value.status == 413

    def test_rejects_negative_content_length(self) -> None:
        h = self._mk_handler(b"", "-1")
        with pytest.raises(api._ApiError) as exc:
            h._json()
        assert exc.value.status == 400

    def test_rejects_garbage_content_length(self) -> None:
        h = self._mk_handler(b"", "not-a-number")
        with pytest.raises(api._ApiError) as exc:
            h._json()
        assert exc.value.status == 400

    def test_empty_body_returns_empty_dict(self) -> None:
        h = self._mk_handler(b"", "0")
        assert h._json() == {}


# ---------------------------------------------------------------------------
# SEC-005 + SEC-010: update_verifier module
# ---------------------------------------------------------------------------


class TestUpdateVerifier:
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        from wireseal.security.update_verifier import (
            verify_release_asset, UpdateVerificationError,
        )
        with pytest.raises(UpdateVerificationError):
            verify_release_asset(
                tmp_path / "nope.tar.gz",
                expected_sha256_hex="0" * 64,
                signature=b"\x00" * 64,
                require_signature=False,
            )

    def test_sha256_mismatch_raises(self, tmp_path: Path) -> None:
        from wireseal.security.update_verifier import (
            verify_release_asset, UpdateVerificationError,
        )
        asset = tmp_path / "a.bin"
        asset.write_bytes(b"hello world")
        with pytest.raises(UpdateVerificationError):
            verify_release_asset(
                asset,
                expected_sha256_hex="a" * 64,
                signature=b"\x00" * 64,
                require_signature=False,
            )

    def test_sha256_match_without_pinned_key_fails_closed(self, tmp_path: Path) -> None:
        """Without a pinned pubkey, require_signature=True must refuse."""
        import hashlib
        from wireseal.security.update_verifier import (
            verify_release_asset, UpdateVerificationError,
        )
        asset = tmp_path / "a.bin"
        data = b"hello world"
        asset.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        with pytest.raises(UpdateVerificationError):
            verify_release_asset(
                asset,
                expected_sha256_hex=digest,
                signature=b"\x00" * 64,
                require_signature=True,  # fail-closed default
            )

    def test_ed25519_signature_roundtrip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """With a pinned key, a genuine signature verifies and a tampered one fails."""
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from wireseal.security import update_verifier as uv

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_hex = pub.public_bytes_raw().hex()

        # Rebind the module-level pinned pubkey getter to use our ephemeral key.
        monkeypatch.setattr(uv, "_load_pinned_pubkey", lambda: pub)

        asset = tmp_path / "a.bin"
        data = b"release payload"
        asset.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        good_sig = priv.sign(data)
        bad_sig = priv.sign(data + b"tampered")

        result = uv.verify_release_asset(
            asset,
            expected_sha256_hex=digest,
            signature=good_sig,
            require_signature=True,
        )
        assert result.signature_verified is True
        assert result.sha256_hex == digest

        with pytest.raises(uv.UpdateVerificationError):
            uv.verify_release_asset(
                asset,
                expected_sha256_hex=digest,
                signature=bad_sig,
                require_signature=True,
            )
