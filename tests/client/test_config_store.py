"""Tests for the client config-store redaction policy.

These tests pin the security contract that v0.7.25 introduced:

* ``get_config_redacted`` MUST replace every ``PrivateKey =`` line with the
  literal ``<redacted>`` placeholder. A regression here means PrivateKey
  bytes leak into HTTP responses, browser DevTools history, screenshot
  shares, or proxy logs — the SEC-020 threat model. Browser-side code
  must never see real key material unless the user explicitly opts in.

* ``get_config_revealed`` MUST return the original ``config_text`` byte-
  for-byte. wg-quick + WebView native-bridge are the only legitimate
  consumers. A regression here breaks tunnel-up (the v0.7.24 user-
  reported "private keys deleted when applied" bug).

* The legacy ``get_config`` symbol MUST be absent. v0.7.24 had a single
  function with a ``reveal_private_key=False`` keyword default — easy
  for future maintainers to forget at a new call site, re-introducing
  the same bug. Splitting it into intent-typed accessors makes the
  redaction policy a property of the function NAME, so a wrong call site
  is a compile error rather than a silent leak.

* The vault dict the helpers receive MUST NOT be mutated. Both helpers
  return shallow copies so the encrypted on-disk vault is unaffected.
"""

from __future__ import annotations

import pytest

from wireseal.client import config_store
from wireseal.client.config_store import (
    _redact_private_key,
    get_config_redacted,
    get_config_revealed,
)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

_FULL_CONF = (
    "[Interface]\n"
    "PrivateKey = abcdEFGHijklMNOPqrstUVWXyz0123456789ABCDEF12345=\n"
    "Address = 10.0.0.2/32\n"
    "DNS = 1.1.1.1\n"
    "\n"
    "[Peer]\n"
    "PublicKey = serverPubKeyValueAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    "PresharedKey = preSharedKeyValueAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    "Endpoint = vpn.example.com:51820\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\n"
)


def _state(name: str = "alice") -> dict:
    """Build a vault-state-shaped dict containing one client profile."""
    return {
        "client_configs": {
            name: {
                "config_text": _FULL_CONF,
                "imported_at": "2026-04-30T00:00:00Z",
                "server_endpoint": "vpn.example.com:51820",
                "interface_ip": "10.0.0.2/32",
            },
        },
    }


# --------------------------------------------------------------------------- #
# get_config_redacted                                                         #
# --------------------------------------------------------------------------- #

def test_redacted_strips_private_key() -> None:
    state = _state()
    out = get_config_redacted(state, "alice")
    text = out["config_text"]
    assert "PrivateKey = <redacted>" in text
    # The original key bytes must NOT appear in the redacted output.
    assert "abcdEFGHijklMNOPqrstUVWXyz" not in text


def test_redacted_preserves_other_fields() -> None:
    state = _state()
    out = get_config_redacted(state, "alice")
    # Endpoint, IP, peer key, and PSK must survive — the dashboard's
    # Edit dialog renders them as read-only metadata.
    assert "Endpoint = vpn.example.com:51820" in out["config_text"]
    assert "Address = 10.0.0.2/32" in out["config_text"]
    assert "PublicKey = serverPubKeyValue" in out["config_text"]
    assert "PresharedKey = preSharedKeyValue" in out["config_text"]


def test_redacted_does_not_mutate_vault_state() -> None:
    state = _state()
    snapshot = state["client_configs"]["alice"]["config_text"]
    _ = get_config_redacted(state, "alice")
    assert state["client_configs"]["alice"]["config_text"] == snapshot, (
        "redacted helper leaked redaction into the stored vault state — "
        "next read would lose the real PrivateKey forever"
    )


def test_redacted_raises_keyerror_for_missing_profile() -> None:
    with pytest.raises(KeyError):
        get_config_redacted(_state(), "nonexistent")


# --------------------------------------------------------------------------- #
# get_config_revealed                                                         #
# --------------------------------------------------------------------------- #

def test_revealed_preserves_private_key() -> None:
    state = _state()
    out = get_config_revealed(state, "alice")
    # Full original content. Byte-for-byte equality is the contract.
    assert out["config_text"] == _FULL_CONF
    assert "PrivateKey = abcdEFGHijklMNOPqrstUVWXyz" in out["config_text"]
    # The placeholder must NOT appear — wg-quick would reject it.
    assert "<redacted>" not in out["config_text"]


def test_revealed_does_not_mutate_vault_state() -> None:
    state = _state()
    snapshot = state["client_configs"]["alice"]["config_text"]
    _ = get_config_revealed(state, "alice")
    assert state["client_configs"]["alice"]["config_text"] == snapshot


def test_revealed_returns_shallow_copy() -> None:
    """Mutating the returned dict must not affect the vault state."""
    state = _state()
    out = get_config_revealed(state, "alice")
    out["config_text"] = "tampered"
    assert state["client_configs"]["alice"]["config_text"] == _FULL_CONF


def test_revealed_raises_keyerror_for_missing_profile() -> None:
    with pytest.raises(KeyError):
        get_config_revealed(_state(), "nonexistent")


# --------------------------------------------------------------------------- #
# Legacy symbol must NOT exist (compile-error guarantee for future callers)   #
# --------------------------------------------------------------------------- #

def test_legacy_get_config_symbol_removed() -> None:
    """The pre-v0.7.25 ``get_config`` symbol must not be importable.

    Keeping a backwards-compat shim would defeat the entire reason for
    splitting the function: any new caller could still write
    ``get_config(..., reveal_private_key=True)`` and forget the audit
    log. Treat the symbol as gone forever.
    """
    assert not hasattr(config_store, "get_config"), (
        "Legacy get_config() symbol re-appeared. The split into "
        "get_config_redacted / get_config_revealed is the entire "
        "v0.7.25 mitigation — restoring the old name re-opens the bug."
    )


# --------------------------------------------------------------------------- #
# _redact_private_key — direct sanity                                         #
# --------------------------------------------------------------------------- #

def test_redact_helper_handles_indented_private_key() -> None:
    text = "[Interface]\n    PrivateKey = secret123=\n"
    out = _redact_private_key(text)
    assert "    PrivateKey = <redacted>" in out
    assert "secret123" not in out


def test_redact_helper_preserves_trailing_newline() -> None:
    with_nl = "PrivateKey = x=\n"
    no_nl = "PrivateKey = x="
    assert _redact_private_key(with_nl).endswith("\n")
    assert not _redact_private_key(no_nl).endswith("\n")


def test_redact_helper_is_case_insensitive() -> None:
    # WireGuard's wg-quick parser accepts mixed case for key names.
    text = "privatekey = lower=\nPRIVATEKEY = upper=\nPrivateKey = mixed=\n"
    out = _redact_private_key(text)
    assert "lower" not in out
    assert "upper" not in out
    assert "mixed" not in out
    assert out.count("<redacted>") == 3
