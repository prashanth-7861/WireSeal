from .exceptions import VaultError, VaultUnlockError, VaultTamperedError
from .integrity import compute_config_hash, store_hash_in_state, verify_config_integrity
from .permissions import check_file_permissions, set_dir_permissions, set_file_permissions
from .secret_types import SecretBytes
from .secrets_wipe import wipe_bytes, wipe_string
from .validator import (
    validate_allowed_ips,
    validate_client_config,
    validate_client_name,
    validate_ip,
    validate_no_injection,
    validate_port,
    validate_server_config,
    validate_subnet,
    validate_wg_key,
)

__all__ = [
    # Exceptions
    "VaultError",
    "VaultUnlockError",
    "VaultTamperedError",
    # Integrity
    "compute_config_hash",
    "verify_config_integrity",
    "store_hash_in_state",
    # Permissions
    "set_file_permissions",
    "set_dir_permissions",
    "check_file_permissions",
    # Secret types
    "SecretBytes",
    "wipe_bytes",
    "wipe_string",
    # Validator
    "validate_client_name",
    "validate_wg_key",
    "validate_port",
    "validate_subnet",
    "validate_ip",
    "validate_no_injection",
    "validate_allowed_ips",
    "validate_server_config",
    "validate_client_config",
]
