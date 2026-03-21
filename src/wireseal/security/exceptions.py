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
