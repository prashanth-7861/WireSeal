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


def get_config(state_data: dict[str, Any], name: str) -> dict[str, Any]:
    """Get a single config by name. Raises KeyError if not found."""
    configs = state_data.get("client_configs", {})
    if name not in configs:
        raise KeyError(f"Profile '{name}' not found")
    return dict(configs[name])


def delete_config(state_data: dict[str, Any], name: str) -> None:
    """Delete a config by name. Raises KeyError if not found."""
    configs = state_data.get("client_configs", {})
    if name not in configs:
        raise KeyError(f"Profile '{name}' not found")
    del configs[name]
