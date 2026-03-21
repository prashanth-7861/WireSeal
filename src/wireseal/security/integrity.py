"""SHA-256 config integrity tracking for WireSeal.

Tracks deployed WireGuard config files to detect post-deployment tampering.
Tampering detection is a hard stop: the CALLER (CLI layer) is responsible
for printing the security alert and exiting -- this module only computes
and compares hashes.

CONFIG-04: SHA-256 hash of deployed config computed and stored for integrity.
"""

import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path


def compute_config_hash(config_path: Path) -> str:
    """Compute the SHA-256 hash of a deployed config file.

    Args:
        config_path: Path to the deployed WireGuard config file.

    Returns:
        Lowercase hex-encoded SHA-256 digest of the file contents.

    Raises:
        FileNotFoundError: If the config file does not exist.
        OSError: If the file cannot be read.
    """
    return hashlib.sha256(config_path.read_bytes()).hexdigest()


def verify_config_integrity(config_path: Path, stored_hash: str) -> bool:
    """Compare the current file hash against a stored hash.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing-based side-channel attacks.

    Note: The CALLER is responsible for the security response when this
    returns False. The expected response is:
        print("SECURITY ALERT: Config file tampered -- aborting. Do not reload WireGuard.")
        sys.exit(1)

    Args:
        config_path:  Path to the deployed WireGuard config file.
        stored_hash:  Previously stored hex SHA-256 digest.

    Returns:
        True if the file matches the stored hash, False if tampered.

    Raises:
        FileNotFoundError: If the config file does not exist.
        OSError: If the file cannot be read.
    """
    actual = compute_config_hash(config_path)
    return hmac.compare_digest(actual, stored_hash)


def store_hash_in_state(state_dict: dict, config_name: str, hash_value: str) -> None:
    """Store a config hash and verification timestamp in the vault state dict.

    Mutates state_dict in place under the 'integrity' key.

    Args:
        state_dict:  Vault state dict (will be mutated).
        config_name: Logical name for the config (e.g., "server", "client-alice").
        hash_value:  Hex SHA-256 digest to store.
    """
    state_dict.setdefault("integrity", {})[config_name] = hash_value
    # Store verification timestamp alongside the hash for audit trail
    state_dict["integrity"][f"{config_name}_verified"] = (
        datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
