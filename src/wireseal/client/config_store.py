"""Store and retrieve imported WireGuard client configs in the vault.

Client configs are stored in vault state under the "client_configs" key:

    state._data["client_configs"] = {
        "profile-name": {
            "config_text": "<full .conf content>",
            "imported_at": "2026-04-13T12:00:00Z",
            "server_endpoint": "1.2.3.4:51820",
            "interface_ip": "10.0.0.2/32",
        },
        ...
    }

The config text is encrypted at rest inside the vault (dual-layer AEAD).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def _parse_conf_metadata(config_text: str) -> dict[str, str]:
    """Extract endpoint and interface IP from a WireGuard .conf file."""
    meta: dict[str, str] = {}
    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("endpoint"):
            match = re.match(r"endpoint\s*=\s*(.+)", stripped, re.IGNORECASE)
            if match:
                meta["server_endpoint"] = match.group(1).strip()
        elif stripped.lower().startswith("address"):
            match = re.match(r"address\s*=\s*(.+)", stripped, re.IGNORECASE)
            if match:
                meta["interface_ip"] = match.group(1).strip()
    return meta


def validate_conf(config_text: str) -> list[str]:
    """Validate a WireGuard .conf file. Returns list of errors (empty = valid)."""
    errors: list[str] = []
    if not config_text.strip():
        return ["Config file is empty"]

    has_interface = False
    has_peer = False
    has_private_key = False

    for line in config_text.splitlines():
        stripped = line.strip().lower()
        if stripped == "[interface]":
            has_interface = True
        elif stripped == "[peer]":
            has_peer = True
        elif stripped.startswith("privatekey") and has_interface:
            has_private_key = True

    if not has_interface:
        errors.append("Missing [Interface] section")
    if not has_peer:
        errors.append("Missing [Peer] section")
    if not has_private_key:
        errors.append("Missing PrivateKey in [Interface]")

    return errors


def import_config(
    state_data: dict[str, Any],
    name: str,
    config_text: str,
) -> dict[str, str]:
    """Import a WireGuard client config into vault state.

    Args:
        state_data: The vault state's _data dict (mutated in place).
        name: Profile name for this config.
        config_text: Raw .conf file content.

    Returns:
        Metadata dict with server_endpoint, interface_ip, imported_at.

    Raises:
        ValueError: If name already exists or config is invalid.
    """
    errors = validate_conf(config_text)
    if errors:
        raise ValueError(f"Invalid config: {'; '.join(errors)}")

    configs = state_data.setdefault("client_configs", {})
    if name in configs:
        raise ValueError(f"Profile '{name}' already exists")

    meta = _parse_conf_metadata(config_text)
    now = datetime.now(timezone.utc).isoformat()

    configs[name] = {
        "config_text": config_text,
        "imported_at": now,
        **meta,
    }

    return {"imported_at": now, **meta}


def list_configs(state_data: dict[str, Any]) -> list[dict[str, str]]:
    """List all imported client configs (without the raw config text)."""
    configs = state_data.get("client_configs", {})
    result = []
    for name, entry in configs.items():
        result.append({
            "name": name,
            "imported_at": entry.get("imported_at", ""),
            "server_endpoint": entry.get("server_endpoint", ""),
            "interface_ip": entry.get("interface_ip", ""),
        })
    return result


def _redact_private_key(config_text: str) -> str:
    """Replace PrivateKey values in a WireGuard .conf with '<redacted>'.

    SEC-020: client config JSON responses must not expose raw private keys
    by default. The sanitised text is still enough to display peer info,
    endpoint, addresses, and QR metadata.
    """
    out_lines: list[str] = []
    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("privatekey"):
            # Preserve indentation if any
            prefix_len = len(line) - len(line.lstrip())
            out_lines.append(line[:prefix_len] + "PrivateKey = <redacted>")
        else:
            out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if config_text.endswith("\n") else "")


def _get_entry_or_raise(state_data: dict[str, Any], name: str) -> dict[str, Any]:
    """Internal helper — fetch the raw stored entry or raise KeyError.

    Callers must NOT invoke this directly. Use one of the two
    intent-typed accessors below so the redaction policy is encoded
    in the function name and cannot be forgotten by future maintainers.
    """
    configs = state_data.get("client_configs", {})
    if name not in configs:
        raise KeyError(f"Profile '{name}' not found")
    # Return a shallow copy so callers can mutate without touching the vault.
    return dict(configs[name])


def get_config_redacted(
    state_data: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    """Public-facing read — ``config_text`` has PrivateKey replaced by
    ``<redacted>``.

    SEC-020 baseline. Use this for:
      * HTTP GET response bodies the dashboard consumes (list views,
        Edit pre-fill, profile metadata).
      * Anywhere the config text might end up in browser memory, HTTP
        history, proxy logs, or screenshots.

    The original PrivateKey stays in the vault on disk — only the copy
    handed to the caller is sanitised. Use :func:`get_config_revealed`
    when the consumer is the OS WireGuard daemon (wg-quick) or the
    user's own QR re-export and audit-log the access at the call site.

    Raises:
        KeyError: profile not found.
    """
    entry = _get_entry_or_raise(state_data, name)
    if "config_text" in entry:
        entry["config_text"] = _redact_private_key(entry["config_text"])
    return entry


def get_config_revealed(
    state_data: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    """Authoritative read — returns the full config including PrivateKey.

    Use this ONLY when:
      * Bringing the WireGuard tunnel up via ``wg-quick`` (daemon needs
        the real key to derive the public key + sign handshakes).
      * The user explicitly requested a reveal via a confirmed UI action
        (``?reveal=1`` query, "Show key" button) and the call site
        audit-logs the reveal event with actor + reason.
      * Re-exporting the user's own client config to QR / .conf for
        another device they control.

    The caller is responsible for audit-logging via
    ``AuditLog.log("client-config-revealed", ...)``. This module does
    not log the access itself because the appropriate context (actor,
    HTTP path, reason) lives at the API handler.

    Raises:
        KeyError: profile not found.
    """
    return _get_entry_or_raise(state_data, name)


def delete_config(state_data: dict[str, Any], name: str) -> None:
    """Delete a config by name. Raises KeyError if not found."""
    configs = state_data.get("client_configs", {})
    if name not in configs:
        raise KeyError(f"Profile '{name}' not found")
    del configs[name]


def update_config(
    state_data: dict[str, Any],
    name: str,
    config_text: str,
) -> dict[str, str]:
    """Replace the stored config_text for an existing profile.

    Use case: server admin changed the WireGuard port or rotated the
    server keypair. Client receives a new .conf and pastes it here.
    Preserves the ``imported_at`` timestamp; refreshes endpoint + ip
    metadata from the new text. Adds ``updated_at``.

    Args:
        state_data:  Vault state ``_data`` dict (mutated in place).
        name:        Existing profile name.
        config_text: New raw .conf content.

    Raises:
        KeyError:   If ``name`` does not exist.
        ValueError: If ``config_text`` is missing required sections.
    """
    configs = state_data.get("client_configs", {})
    if name not in configs:
        raise KeyError(f"Profile '{name}' not found")

    errors = validate_conf(config_text)
    if errors:
        raise ValueError(f"Invalid config: {'; '.join(errors)}")

    meta = _parse_conf_metadata(config_text)
    now = datetime.now(timezone.utc).isoformat()
    entry = configs[name]
    entry["config_text"] = config_text
    entry["updated_at"] = now
    entry.update(meta)
    return {"updated_at": now, **meta}
