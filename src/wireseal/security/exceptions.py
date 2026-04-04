"""Custom exceptions for vault operations."""


class VaultError(Exception):
    """Base exception for vault operations."""


class VaultUnlockError(VaultError):
    """Raised when vault cannot be unlocked (wrong passphrase or tampered).

    The error message is ALWAYS "Vault unlock failed" -- never discloses
    whether the failure was a wrong passphrase or ciphertext tampering.
    Attacker must not be able to distinguish the two failure modes.
    """


class VaultTamperedError(VaultError):
    """Raised when vault file integrity check fails (e.g., bad magic bytes).

    This is a subclass for cases where tampering is detected at the
    structural level (before attempting decryption), such as a missing
    or corrupted MAGIC header. GCM tag failures are reported as
    VaultUnlockError to avoid leaking distinguishing information.
    """


class KeyslotNotFoundError(VaultError):
    """Raised when admin_id not found in any keyslot, or when AES-256-GCM
    authentication fails during keyslot unwrap (wrong passphrase)."""


class KeyslotExistsError(VaultError):
    """Raised when add_keyslot is called with an admin_id that is already
    present in the keyslot store."""


class AdminRoleError(VaultError):
    """Raised when an operation violates role constraints.

    Examples:
    - Attempting to remove the last owner keyslot
    - A non-owner attempting an owner-only operation
    """
