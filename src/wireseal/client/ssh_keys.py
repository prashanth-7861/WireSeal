"""SSH key management — generate, import, export, delete keys in vault."""

from __future__ import annotations

import datetime
from typing import Any

import asyncssh

KEY_TYPES = {
    "ed25519": {"algorithm": "ssh-ed25519"},
    "rsa-2048": {"algorithm": "ssh-rsa", "key_size": 2048},
    "rsa-4096": {"algorithm": "ssh-rsa", "key_size": 4096},
}


def generate_keypair(
    state_data: dict[str, Any],
    name: str,
    key_type: str = "ed25519",
    comment: str = "",
) -> dict[str, Any]:
    """Generate a new SSH keypair and store it in the vault.

    Args:
        state_data:  Vault state._data dict.
        name:        Key identifier.
        key_type:    One of "ed25519", "rsa-2048", "rsa-4096".
        comment:     Optional comment appended to the public key.

    Returns:
        The stored key entry dict.

    Raises:
        ValueError: On unsupported key_type.
    """
    if key_type not in KEY_TYPES:
        raise ValueError(
            f"Unsupported key type '{key_type}'. "
            f"Choose from: {', '.join(sorted(KEY_TYPES))}"
        )

    params = dict(KEY_TYPES[key_type])
    algorithm = params.pop("algorithm")

    key = asyncssh.generate_private_key(algorithm, **params)

    private_key_pem = key.export_private_key().decode("utf-8")
    public_key_openssh = key.export_public_key().decode("utf-8").strip()
    fingerprint = key.get_fingerprint()

    if comment:
        public_key_openssh += f" {comment}"

    entry: dict[str, Any] = {
        "type": key_type,
        "private_key_pem": private_key_pem,
        "public_key_openssh": public_key_openssh,
        "fingerprint": fingerprint,
        "created_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }

    if "ssh_keys" not in state_data:
        state_data["ssh_keys"] = {}
    state_data["ssh_keys"][name] = entry

    return dict(entry)


def import_key(
    state_data: dict[str, Any],
    name: str,
    pem_text: str,
) -> dict[str, Any]:
    """Import an existing private key (PEM) into the vault.

    Args:
        state_data: Vault state._data dict.
        name:       Key identifier.
        pem_text:   PEM-encoded private key as a string.

    Returns:
        The stored key entry dict.

    Raises:
        ValueError: If the PEM is not a valid private key.
    """
    try:
        key = asyncssh.import_private_key(pem_text.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Invalid private key: {exc}") from exc

    private_key_pem = key.export_private_key().decode("utf-8")
    public_key_openssh = key.export_public_key().decode("utf-8").strip()
    fingerprint = key.get_fingerprint()

    entry: dict[str, Any] = {
        "type": "imported",
        "private_key_pem": private_key_pem,
        "public_key_openssh": public_key_openssh,
        "fingerprint": fingerprint,
        "created_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }

    if "ssh_keys" not in state_data:
        state_data["ssh_keys"] = {}
    state_data["ssh_keys"][name] = entry

    return dict(entry)


def export_public_key(state_data: dict[str, Any], name: str) -> str:
    """Return the OpenSSH public-key line for a stored key.

    Returns:
        ``"<key-type> <base64>"`` optionally with a comment suffix.

    Raises:
        KeyError: If *name* is not found.
    """
    keys = state_data.get("ssh_keys", {})
    if name not in keys:
        raise KeyError(f"SSH key '{name}' not found")
    return keys[name]["public_key_openssh"]


def get_private_key(
    state_data: dict[str, Any], name: str
) -> asyncssh.SSHKey:
    """Deserialize and return the private key as an ``asyncssh.SSHKey``.

    The returned key can be passed directly to ``asyncssh.connect()`` via
    the ``client_keys`` parameter.

    Raises:
        KeyError: If *name* is not found.
    """
    keys = state_data.get("ssh_keys", {})
    if name not in keys:
        raise KeyError(f"SSH key '{name}' not found")
    pem = keys[name]["private_key_pem"]
    return asyncssh.import_private_key(pem.encode("utf-8"))


def list_keys(state_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return metadata for every stored SSH key, sorted by name.

    Each entry contains ``name``, ``type``, ``fingerprint``, and
    ``created_at``.
    """
    keys = state_data.get("ssh_keys", {})
    result = []
    for name, entry in keys.items():
        result.append(
            {
                "name": name,
                "type": entry.get("type", "?"),
                "fingerprint": entry.get("fingerprint", "?"),
                "created_at": entry.get("created_at", "?"),
            }
        )
    result.sort(key=lambda k: k["name"])
    return result


def delete_key(state_data: dict[str, Any], name: str) -> None:
    """Remove a stored SSH key from the vault.

    Raises:
        KeyError: If *name* is not found.
    """
    keys = state_data.get("ssh_keys", {})
    if name not in keys:
        raise KeyError(f"SSH key '{name}' not found")
    del keys[name]
