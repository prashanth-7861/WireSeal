"""Smoke tests for the key-rotation API (Hardening Phase 7).

Full end-to-end rotation touches WireGuard, atomic_write, and requires a
real vault, so it belongs in an integration suite. These unit-level checks
verify the wiring that _does_ matter without that setup:

- Both rotation handlers are defined, callable, and wired into _ROUTES
- The route regex matches the expected URLs
- Both handlers reject requests when the vault is locked (401)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from wireseal import api


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _locked_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Start every test with a fully-locked vault so _require_unlocked fires."""
    monkeypatch.setattr(api, "_VAULT_DIR", tmp_path)
    monkeypatch.setattr(api, "_VAULT_PATH", tmp_path / "vault.enc")
    monkeypatch.setattr(api, "_AUDIT_PATH", tmp_path / "audit.log")
    with api._lock:
        api._session.update(vault=None, passphrase=None, cache=None,
                            admin_id=None, admin_role=None)
    yield
    with api._lock:
        api._session.update(vault=None, passphrase=None, cache=None,
                            admin_id=None, admin_role=None)


# ---------------------------------------------------------------------------
# Route wiring
# ---------------------------------------------------------------------------


def _find_route(method: str, path: str) -> tuple:
    """Return (method, pattern, handler) for the first route matching path."""
    for m, pattern, handler in api._ROUTES:
        if m == method and pattern.match(path):
            return (m, pattern, handler)
    raise AssertionError(f"No route found for {method} {path}")


def test_rotate_client_route_is_wired() -> None:
    _, pattern, handler = _find_route("POST", "/api/clients/laptop/rotate")
    assert handler is api._h_rotate_client_keys
    # Regex must capture the client name as a group
    match = pattern.match("/api/clients/laptop/rotate")
    assert match is not None
    assert match.group(1) == "laptop"


def test_rotate_server_route_is_wired() -> None:
    _, pattern, handler = _find_route("POST", "/api/rotate-server-keys")
    assert handler is api._h_rotate_server_keys
    assert pattern.match("/api/rotate-server-keys") is not None


def test_rotate_client_regex_handles_names_with_hyphens_and_dots() -> None:
    _, pattern, _ = _find_route("POST", "/api/clients/my-laptop-v2.local/rotate")
    match = pattern.match("/api/clients/my-laptop-v2.local/rotate")
    assert match is not None
    assert match.group(1) == "my-laptop-v2.local"


def test_rotate_client_regex_does_not_match_nested_paths() -> None:
    # Ensure [^/]+ is used, not .+, so nested segments don't leak through
    for _, pattern, _ in api._ROUTES:
        if pattern.pattern == r"^/api/clients/([^/]+)/rotate$":
            assert pattern.match("/api/clients/a/b/rotate") is None
            break
    else:
        raise AssertionError("rotate-client route pattern not found")


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------


def test_rotate_client_requires_unlocked_vault() -> None:
    with pytest.raises(api._ApiError) as exc:
        api._h_rotate_client_keys(None, ("laptop",))  # type: ignore[arg-type]
    assert exc.value.status == 401


def test_rotate_server_requires_unlocked_vault() -> None:
    with pytest.raises(api._ApiError) as exc:
        api._h_rotate_server_keys(None, ())  # type: ignore[arg-type]
    assert exc.value.status == 401


# ---------------------------------------------------------------------------
# Handler surface
# ---------------------------------------------------------------------------


def test_both_rotation_handlers_are_callable() -> None:
    assert callable(api._h_rotate_client_keys)
    assert callable(api._h_rotate_server_keys)


def test_rotate_handlers_exist_exactly_once_in_routes() -> None:
    client_matches = [h for _, _, h in api._ROUTES if h is api._h_rotate_client_keys]
    server_matches = [h for _, _, h in api._ROUTES if h is api._h_rotate_server_keys]
    assert len(client_matches) == 1
    assert len(server_matches) == 1
