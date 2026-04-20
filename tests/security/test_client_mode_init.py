"""Tests for client-mode vault initialization.

Client-mode init must:
  * Create an encrypted vault.
  * NOT generate a server keypair.
  * NOT call any platform adapter (no wg install, no firewall rules, no tunnel service).
  * Tag the vault with mode="client" so vault-info can report it.

This is the core fix for "while using client, server shouldn't start" —
previously, /api/init always ran full server provisioning regardless of
the user's intended role.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from wireseal import api
from wireseal.security.vault import Vault


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


def _make_req(body: dict[str, Any]) -> Any:
    """Build a minimal _Handler stand-in that returns `body` from _json()."""
    req = MagicMock()
    req._json.return_value = body
    return req


# ---------------------------------------------------------------------------


def test_client_init_creates_vault_with_mode_client(tmp_path: Path) -> None:
    req = _make_req({"passphrase": "correct-horse-battery-staple", "mode": "client"})
    result = api._h_init(req, ())
    assert result == {"ok": True, "mode": "client"}
    assert api._VAULT_PATH.exists()


def test_client_init_does_not_call_platform_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Client init must skip WireGuard install, firewall rules, tunnel service."""
    # Sentinel: if get_adapter is ever invoked, the test fails loudly.
    called = {"get_adapter": False}
    import wireseal.platform.detect as detect_mod

    def _poisoned(*a, **kw):
        called["get_adapter"] = True
        raise AssertionError("Client init must not touch the platform adapter")

    monkeypatch.setattr(detect_mod, "get_adapter", _poisoned)

    req = _make_req({"passphrase": "correct-horse-battery-staple", "mode": "client"})
    result = api._h_init(req, ())
    assert result["ok"] is True
    assert result["mode"] == "client"
    assert called["get_adapter"] is False


def test_client_init_does_not_generate_server_keypair(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"keygen": False}
    import wireseal.core.keygen as keygen_mod

    def _poisoned():
        called["keygen"] = True
        raise AssertionError("Client init must not generate a server keypair")

    monkeypatch.setattr(keygen_mod, "generate_keypair", _poisoned)

    req = _make_req({"passphrase": "correct-horse-battery-staple", "mode": "client"})
    result = api._h_init(req, ())
    assert result["ok"] is True
    assert called["keygen"] is False


def test_client_vault_has_no_server_keys() -> None:
    """Verify the persisted vault has NO server/ip_pool/clients sections."""
    req = _make_req({"passphrase": "correct-horse-battery-staple", "mode": "client"})
    api._h_init(req, ())

    # Reuse the session-owned vault + passphrase (ownership was transferred
    # into _session by _h_init). This avoids re-running Argon2id and matches
    # how the dashboard actually interacts with the vault.
    vault = api._session["vault"]
    passphrase = api._session["passphrase"]
    with vault.open(passphrase) as state:
        assert state.data.get("mode") == "client"
        assert "client_configs" in state.data
        # VaultState always exposes server/clients/ip_pool keys; for client
        # vaults they must be empty (no server keypair, no clients, no pool).
        assert state.data.get("server") == {}  # no server keypair
        assert state.data.get("clients") == {}
        assert state.data.get("ip_pool") == {}


def test_vault_info_reports_client_mode() -> None:
    req = _make_req({"passphrase": "correct-horse-battery-staple", "mode": "client"})
    api._h_init(req, ())
    info = api._h_vault_info(None, ())
    assert info["initialized"] is True
    assert info["locked"] is False
    assert info["mode"] == "client"


def test_init_rejects_invalid_mode() -> None:
    req = _make_req({"passphrase": "correct-horse-battery-staple", "mode": "hybrid"})
    with pytest.raises(api._ApiError) as exc:
        api._h_init(req, ())
    assert exc.value.status == 400
    assert "mode" in str(exc.value).lower()


def test_init_defaults_to_server_mode_when_mode_omitted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Back-compat: existing callers that didn't pass mode get server init.

    We short-circuit right before the adapter is touched by stubbing out
    check_privileges to fail — the handler then returns with warnings instead
    of attempting real platform work, but we still verify server keys were
    generated and the vault is tagged mode=server.
    """
    # Force the adapter path to no-op gracefully so the test doesn't need admin.
    import wireseal.platform.detect as detect_mod
    adapter = MagicMock()
    adapter.check_privileges.side_effect = RuntimeError("not admin — test")
    monkeypatch.setattr(detect_mod, "get_adapter", lambda: adapter)

    req = _make_req({"passphrase": "correct-horse-battery-staple"})  # no mode
    result = api._h_init(req, ())
    assert result["ok"] is True
    assert "public_key" in result  # server keypair was generated

    # Verify the vault itself is tagged mode=server (use session-owned vault)
    vault = api._session["vault"]
    passphrase = api._session["passphrase"]
    with vault.open(passphrase) as state:
        assert state.data.get("mode") == "server"
        assert "server" in state.data


# ---------------------------------------------------------------------------
# Defense-in-depth: server-only endpoints must reject client-mode vaults
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "handler_name,groups,body",
    [
        ("_h_add_client",          (),         {"name": "alice"}),
        ("_h_remove_client",       ("alice",), {}),
        ("_h_start_server",        (),         {}),
        ("_h_terminate",           (),         {}),
        ("_h_rotate_client_keys",  ("alice",), {}),
        ("_h_rotate_server_keys",  (),         {}),
    ],
)
def test_server_only_endpoints_reject_client_vault(
    handler_name: str, groups: tuple, body: dict
) -> None:
    """Server-only endpoints return 409 on a client-mode vault."""
    req = _make_req({"passphrase": "correct-horse-battery-staple", "mode": "client"})
    api._h_init(req, ())

    handler = getattr(api, handler_name)
    call_req = _make_req(body)
    with pytest.raises(api._ApiError) as exc:
        handler(call_req, groups)
    assert exc.value.status == 409
    assert "client mode" in str(exc.value).lower()
