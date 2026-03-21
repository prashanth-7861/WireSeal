"""Encrypted vault for WireGuard Automate secret state.

Stores all secret state (keys, PSKs, IPs, server config) using AES-256-GCM
with Argon2id key derivation. The vault is the single point of trust for the
entire project -- every secret passes through it.

Security properties:
  - AES-256-GCM encryption with GCM authentication tag (tamper-evident)
  - Argon2id KDF: 256 MiB memory / 4 iterations / 4 parallelism
  - Fresh os.urandom(12) nonce per encryption (SEC-06: no nonce reuse)
  - Atomic writes: tmp + fsync + os.replace (never partially written)
  - Strict file permissions: vault dir 700, vault file 600 (Unix)
  - Context manager on VaultState: wipes all secrets in finally on exit
  - Generic error message for unlock failures (passphrase/tampering indistinct)
"""

import json
import os
import struct
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .atomic import atomic_write
from .exceptions import VaultTamperedError, VaultUnlockError
from .secret_types import SecretBytes
from .secrets_wipe import wipe_bytes

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

MAGIC = b"WGAV"  # WireGuard Automate Vault

FORMAT_VERSION = 1

# CRITICAL: memory_cost is in KiB. 256 MiB = 262144 KiB. Passing 256 = catastrophically weak.
ARGON2_MEMORY_COST_KIB = 262144  # 256 MiB
ARGON2_TIME_COST = 6
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32  # 256-bit AES key
ARGON2_SALT_LEN = 16

GCM_NONCE_LEN = 12

DEFAULT_VAULT_DIR = Path.home() / ".wireseal"
DEFAULT_VAULT_PATH = DEFAULT_VAULT_DIR / "vault.enc"

# Binary header layout (47 bytes total):
#   4  bytes: MAGIC (b'WGAV')
#   1  byte:  FORMAT_VERSION
#   4  bytes: ARGON2_MEMORY_COST_KIB (uint32 big-endian)
#   4  bytes: ARGON2_TIME_COST (uint32 big-endian)
#   4  bytes: ARGON2_PARALLELISM (uint32 big-endian)
#   1  byte:  salt length (always 16)
#   16 bytes: salt
#   1  byte:  nonce length (always 12)
#   12 bytes: nonce
#   ----
#   47 bytes total
_HEADER_STRUCT = struct.Struct(">4sBIII B16sB12s")
_HEADER_SIZE = 47  # bytes
assert _HEADER_STRUCT.size == _HEADER_SIZE, "Header struct size mismatch"


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def _derive_key(passphrase: bytearray, salt: bytes, *, memory_cost: int = ARGON2_MEMORY_COST_KIB,
                time_cost: int = ARGON2_TIME_COST, parallelism: int = ARGON2_PARALLELISM) -> bytearray:
    """Derive a 256-bit AES key from passphrase and salt using Argon2id.

    Args:
        passphrase: Mutable bytearray holding the passphrase (not copied here).
        salt:       16-byte random salt.
        memory_cost: Argon2 memory parameter in KiB (default: 262144 = 256 MiB).
        time_cost:  Argon2 iteration count (default: 4).
        parallelism: Argon2 parallelism (default: 4).

    Returns:
        32-byte derived key as mutable bytearray (caller must wipe after use).
    """
    raw = hash_secret_raw(
        secret=bytes(passphrase),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    # Convert immutable bytes to mutable bytearray so callers can wipe in-place
    result = bytearray(raw)
    # Best-effort: zero the immutable bytes copy (CPython only)
    import ctypes
    try:
        ctypes.memset(id(raw) + (len(raw).__sizeof__() - len(raw)), 0, len(raw))
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Directory permissions
# ---------------------------------------------------------------------------


def _ensure_vault_dir(dir_path: Path) -> None:
    """Create the vault directory with restrictive permissions.

    Unix: 700 (owner only).
    Windows: best-effort icacls to restrict to SYSTEM + Administrators.
             Full Windows ACL support is deferred to Phase 2.
    """
    dir_path.mkdir(parents=True, exist_ok=True)

    if sys.platform != "win32":
        os.chmod(dir_path, 0o700)
    else:
        try:
            dir_str = str(dir_path)
            # Remove inherited permissions, then grant SYSTEM and Administrators full control
            subprocess.run(
                ["icacls", dir_str, "/inheritance:r",
                 "/grant:r", "SYSTEM:(OI)(CI)F",
                 "/grant:r", "Administrators:(OI)(CI)F"],
                check=True,
                capture_output=True,
            )
        except Exception as exc:
            warnings.warn(
                f"Could not set restrictive permissions on vault directory {dir_path}: {exc}. "
                "The directory may be accessible to other users on this system. "
                "Full Windows ACL support will be added in Phase 2.",
                stacklevel=3,
            )


# ---------------------------------------------------------------------------
# Low-level encrypt / decrypt
# ---------------------------------------------------------------------------


def _encrypt_vault(plaintext_dict: dict[str, Any], passphrase: bytearray) -> bytes:
    """Serialize and encrypt a vault state dict.

    Binary layout:
      [47-byte header][4-byte ct_len][ct_len bytes ciphertext+GCM_tag]

    The 47-byte header is used as AAD (additional authenticated data) for
    AES-GCM, so any modification to the header also invalidates the tag.

    SEC-06: Fresh nonce (os.urandom(12)) generated per call -- never reused.

    Args:
        plaintext_dict: Vault state dict to encrypt.
        passphrase:     Mutable bytearray holding the passphrase.

    Returns:
        Encrypted binary blob.
    """
    salt = os.urandom(ARGON2_SALT_LEN)
    nonce = os.urandom(GCM_NONCE_LEN)  # SEC-06: fresh nonce per encryption

    key = _derive_key(passphrase, salt)
    try:
        header = _HEADER_STRUCT.pack(
            MAGIC,
            FORMAT_VERSION,
            ARGON2_MEMORY_COST_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            ARGON2_SALT_LEN,
            salt,
            GCM_NONCE_LEN,
            nonce,
        )

        plaintext_json = json.dumps(plaintext_dict, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext_json, header)
    finally:
        # Wipe derived key in-place (key is a mutable bytearray)
        wipe_bytes(key)

    ct_len_field = struct.pack(">I", len(ciphertext))
    return header + ct_len_field + ciphertext


def _decrypt_vault(blob: bytes, passphrase: bytearray) -> dict[str, Any]:
    """Decrypt and deserialize a vault binary blob.

    Parses Argon2 parameters from the header (not module constants) for
    forward compatibility: future vaults may have different parameters.

    Raises:
        VaultTamperedError: Magic bytes are wrong (structural tampering).
        VaultUnlockError:   GCM tag verification failed (wrong passphrase or
                            ciphertext tampering). Generic message only --
                            never distinguish the two failure modes.
    """
    min_size = _HEADER_SIZE + 4  # header + ct_len field
    if len(blob) < min_size:
        raise VaultTamperedError("Vault file is too small to be valid")

    # Validate magic bytes before attempting expensive Argon2 derivation
    if blob[:4] != MAGIC:
        raise VaultTamperedError("Vault file has invalid magic bytes")

    (
        _magic,
        _version,
        memory_cost,
        time_cost,
        parallelism,
        salt_len,
        salt,
        nonce_len,
        nonce,
    ) = _HEADER_STRUCT.unpack(blob[:_HEADER_SIZE])

    header = blob[:_HEADER_SIZE]

    # Extract ciphertext length and validate it against the actual blob size.
    # Python slice notation silently truncates on out-of-bounds, so we must
    # explicitly check that the declared length is consistent with the blob.
    # A corrupted ct_len field prevents decryption -> VaultUnlockError (generic).
    ct_len = struct.unpack(">I", blob[_HEADER_SIZE:_HEADER_SIZE + 4])[0]
    expected_total = _HEADER_SIZE + 4 + ct_len
    if len(blob) < expected_total:
        raise VaultUnlockError("Vault unlock failed") from None
    ciphertext = blob[_HEADER_SIZE + 4: expected_total]

    key = _derive_key(passphrase, salt, memory_cost=memory_cost,
                      time_cost=time_cost, parallelism=parallelism)
    try:
        plaintext = AESGCM(bytes(key)).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise VaultUnlockError("Vault unlock failed") from None
    finally:
        # Wipe derived key in-place (key is a mutable bytearray)
        wipe_bytes(key)

    return json.loads(plaintext.decode("utf-8"))


# ---------------------------------------------------------------------------
# VaultState
# ---------------------------------------------------------------------------


class VaultState:
    """Holds decrypted vault state in memory with SecretBytes wrapping for key material.

    Key fields (anything named *_key or psk) are wrapped in SecretBytes to
    prevent accidental exposure. All other fields are held as plain Python
    objects.

    Use as a context manager to ensure automatic wiping:

        with vault.open(passphrase) as state:
            key = state.server["private_key"]
            ...
        # state wiped here, even if an exception occurred
    """

    def __init__(self, data: dict[str, Any]) -> None:
        # Deep-copy the dict and wrap secret fields in SecretBytes
        self._data: dict[str, Any] = {}
        self._data["schema_version"] = data.get("schema_version", 1)
        self._data["server"] = self._wrap_secrets(dict(data.get("server", {})))
        self._data["clients"] = {
            name: self._wrap_secrets(dict(client))
            for name, client in data.get("clients", {}).items()
        }
        self._data["ip_pool"] = dict(data.get("ip_pool", {}))
        self._data["integrity"] = dict(data.get("integrity", {}))
        self._wiped = False

    @staticmethod
    def _wrap_secrets(d: dict[str, Any]) -> dict[str, Any]:
        """Wrap values whose key ends in '_key' or equals 'psk' in SecretBytes."""
        result = {}
        for k, v in d.items():
            if isinstance(v, str) and (k.endswith("_key") or k == "psk"):
                result[k] = SecretBytes(bytearray(v.encode("utf-8")))
            else:
                result[k] = v
        return result

    @staticmethod
    def _unwrap_secrets(d: dict[str, Any]) -> dict[str, Any]:
        """Convert SecretBytes back to strings for JSON serialization."""
        result = {}
        for k, v in d.items():
            if isinstance(v, SecretBytes):
                result[k] = bytes(v.expose_secret()).decode("utf-8")
            else:
                result[k] = v
        return result

    @property
    def server(self) -> dict[str, Any]:
        """Server configuration dict (private_key wrapped in SecretBytes)."""
        return self._data["server"]

    @property
    def clients(self) -> dict[str, dict[str, Any]]:
        """Clients dict: name -> config dict (key material wrapped in SecretBytes)."""
        return self._data["clients"]

    @property
    def ip_pool(self) -> dict[str, Any]:
        """IP pool state dict."""
        return self._data["ip_pool"]

    @property
    def integrity(self) -> dict[str, Any]:
        """Integrity tracking dict."""
        return self._data["integrity"]

    def to_dict(self) -> dict[str, Any]:
        """Serialize vault state back to a plain dict (SecretBytes -> strings).

        Used internally before re-encryption. The returned dict contains
        plaintext key material as strings -- wipe promptly after use.
        """
        return {
            "schema_version": self._data["schema_version"],
            "server": self._unwrap_secrets(self._data["server"]),
            "clients": {
                name: self._unwrap_secrets(client)
                for name, client in self._data["clients"].items()
            },
            "ip_pool": self._data["ip_pool"],
            "integrity": self._data["integrity"],
        }

    def wipe(self) -> None:
        """Zero all SecretBytes held in this state."""
        if self._wiped:
            return
        for v in self._data.get("server", {}).values():
            if isinstance(v, SecretBytes):
                v.wipe()
        for client in self._data.get("clients", {}).values():
            for v in client.values():
                if isinstance(v, SecretBytes):
                    v.wipe()
        self._wiped = True

    # Context manager: wipe in finally so secrets never linger
    def __enter__(self) -> "VaultState":
        return self

    def __exit__(self, *args: object) -> None:
        self.wipe()


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


class Vault:
    """Encrypted vault backed by a binary file on disk.

    Usage pattern (read):

        vault = Vault(path)
        with vault.open(passphrase) as state:
            process(state)
        # state auto-wiped here

    Usage pattern (write):

        vault = Vault(path)
        with vault.open(passphrase) as state:
            state.clients["alice"] = ...
            vault.save(state, passphrase)
        # state auto-wiped here
    """

    def __init__(self, vault_path: Path = DEFAULT_VAULT_PATH) -> None:
        self._path = vault_path

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        vault_path: Path,
        passphrase: SecretBytes,
        initial_state: dict[str, Any],
        hint: str | None = None,
    ) -> "Vault":
        """Create a new vault file at vault_path encrypted with passphrase.

        Passphrase length enforcement (VAULT-03): minimum 12 characters.
        Directory permissions (VAULT-02): 700 on Unix, best-effort icacls on Windows.
        Atomic write (VAULT-05): tmp + fsync + os.replace, never world-readable.
        Hint (VAULT-06): stored as plaintext .hint file with a clear warning.

        Args:
            vault_path:    Absolute path where vault.enc will be written.
            passphrase:    SecretBytes holding the passphrase (minimum 12 chars).
            initial_state: Dict matching the vault JSON schema.
            hint:          Optional plaintext passphrase hint.

        Returns:
            A Vault instance pointing at vault_path.

        Raises:
            ValueError: If passphrase is shorter than 12 characters.
        """
        # VAULT-03: enforce minimum passphrase length BEFORE any file I/O
        raw = passphrase.expose_secret()
        if len(raw) < 12:
            raise ValueError("Passphrase must be at least 12 characters")

        _ensure_vault_dir(vault_path.parent)

        blob = _encrypt_vault(initial_state, raw)
        atomic_write(vault_path, blob, mode=0o600)

        if hint is not None:
            hint_path = vault_path.with_suffix(".hint")
            print(
                "WARNING: The passphrase hint is stored as plain text and is not protected."
            )
            atomic_write(hint_path, hint.encode("utf-8"), mode=0o600)

        return cls(vault_path)

    # ------------------------------------------------------------------
    # Open / save
    # ------------------------------------------------------------------

    def open(self, passphrase: SecretBytes) -> VaultState:
        """Decrypt vault and return a VaultState instance.

        The caller is responsible for wiping the VaultState when done.
        Prefer using it as a context manager:

            with vault.open(passphrase) as state:
                ...

        Raises:
            VaultTamperedError: Structural tampering detected (bad magic bytes).
            VaultUnlockError:   Decryption failed (wrong passphrase or GCM failure).
        """
        blob = self._path.read_bytes()
        data = _decrypt_vault(blob, passphrase.expose_secret())
        return VaultState(data)

    def save(self, state: VaultState, passphrase: SecretBytes) -> None:
        """Re-encrypt and atomically write updated vault state.

        Args:
            state:      Current VaultState (must not be wiped).
            passphrase: SecretBytes holding the current passphrase.
        """
        plaintext = state.to_dict()
        raw = passphrase.expose_secret()
        blob = _encrypt_vault(plaintext, raw)
        atomic_write(self._path, blob, mode=0o600)

    # ------------------------------------------------------------------
    # Passphrase change (VAULT-07)
    # ------------------------------------------------------------------

    def change_passphrase(
        self,
        old_passphrase: SecretBytes,
        new_passphrase: SecretBytes,
    ) -> None:
        """Decrypt with old passphrase, re-encrypt with new passphrase, write atomically.

        New salt and new nonce are generated during re-encryption (os.urandom).
        Intermediate plaintext is wiped after use.

        Raises:
            VaultUnlockError: Old passphrase is wrong.
            ValueError:       New passphrase is shorter than 12 characters.
        """
        new_raw = new_passphrase.expose_secret()
        if len(new_raw) < 12:
            raise ValueError("Passphrase must be at least 12 characters")

        blob = self._path.read_bytes()
        plaintext = _decrypt_vault(blob, old_passphrase.expose_secret())
        try:
            new_blob = _encrypt_vault(plaintext, new_raw)
            atomic_write(self._path, new_blob, mode=0o600)
        finally:
            # Wipe the intermediate plaintext dict (best-effort for string values)
            plaintext.clear()

    # ------------------------------------------------------------------
    # Integrity verification (VAULT-08)
    # ------------------------------------------------------------------

    def verify_integrity(self, passphrase: SecretBytes) -> bool:
        """Verify that the vault can be decrypted (GCM tag + Argon2 salt integrity).

        Attempts decryption; if successful, wipes the decrypted state and
        returns True. Returns False if the GCM tag check fails.

        Raises:
            VaultTamperedError: Structural tampering detected (bad magic bytes).
        """
        blob = self._path.read_bytes()
        try:
            data = _decrypt_vault(blob, passphrase.expose_secret())
            # Wipe plaintext immediately -- we only care that decryption succeeded
            VaultState(data).wipe()
            return True
        except VaultUnlockError:
            return False

    # ------------------------------------------------------------------
    # Hint (VAULT-06)
    # ------------------------------------------------------------------

    @staticmethod
    def get_hint(vault_path: Path) -> str | None:
        """Read and return the plaintext hint beside the vault file, or None.

        The hint file is vault_path with extension replaced by .hint.
        """
        hint_path = vault_path.with_suffix(".hint")
        if hint_path.exists():
            return hint_path.read_text(encoding="utf-8").strip()
        return None
