"""Encrypted vault for WireSeal secret state.

Stores all secret state (keys, PSKs, IPs, server config) using a dual-layer
AEAD encryption scheme with Argon2id key derivation. The vault is the single
point of trust -- every secret passes through it.

Encryption engine (FORMAT_VERSION 2):
  - Argon2id KDF: 256 MiB memory / time_cost=10 / parallelism=4
    Produces a 32-byte master key from the passphrase + 32-byte random salt.
  - HKDF-SHA512 key separation: the master key is expanded into two
    independent 256-bit subkeys with distinct domain labels, so neither
    subkey leaks information about the other.
  - Layer 1 — ChaCha20-Poly1305 (inner):
      Stream cipher; no block-size alignment leakage; widely considered
      quantum-resistant compared to AES-based ciphers; 96-bit nonce.
  - Layer 2 — AES-256-GCM-SIV (outer, nonce-misuse resistant):
      If os.urandom() ever produces a repeated nonce (negligible probability
      with 96-bit nonces) AES-GCM-SIV only reveals that two ciphertexts have
      identical plaintexts — it does NOT reveal the plaintext itself. This is
      a strictly stronger security guarantee than standard AES-GCM.
  - Both layers use the full 76-byte header as AEAD additional data (AAD),
    so any modification to the header (KDF params, nonces, salt) invalidates
    both authentication tags simultaneously.
  - Atomic writes: tmp + fsync + os.replace (never partially written)
  - Strict file permissions: vault dir 700, vault file 600 (Unix)
  - All derived keys wiped in-place immediately after use (mutable bytearray)
  - Generic error message for unlock failures (passphrase/tampering indistinct)

FORMAT_VERSION 1 vaults (AES-256-GCM only) are detected and rejected with a
clear upgrade message — run fresh-start + init to create a v2 vault.
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .atomic import atomic_write
from .exceptions import VaultTamperedError, VaultUnlockError
from .secret_types import SecretBytes
from .secrets_wipe import wipe_bytes

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

MAGIC = b"WGAV"  # WireGuard Automate Vault

FORMAT_VERSION = 2  # v1: AES-256-GCM; v2: ChaCha20-Poly1305 + AES-256-GCM-SIV + HKDF

# CRITICAL: memory_cost is in KiB. 256 MiB = 262144 KiB. Passing 256 = catastrophically weak.
ARGON2_MEMORY_COST_KIB = 262144  # 256 MiB
ARGON2_TIME_COST = 10
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32   # Argon2id master key length (HKDF input)
ARGON2_SALT_LEN = 32   # v2: 256-bit salt (was 16 bytes in v1)

NONCE_LEN = 12         # 96-bit nonce for both ChaCha20 and AES-GCM-SIV

# HKDF domain separation labels — different info strings guarantee the two
# subkeys are cryptographically independent even if master_key is known.
_HKDF_INFO_CHACHA = b"wireseal-v2-chacha20-poly1305"
_HKDF_INFO_AES    = b"wireseal-v2-aes-256-gcm-siv"

DEFAULT_VAULT_DIR = Path.home() / ".wireseal"
DEFAULT_VAULT_PATH = DEFAULT_VAULT_DIR / "vault.enc"

# Binary header layout v2 (76 bytes total):
#   4  bytes: MAGIC (b'WGAV')
#   1  byte:  FORMAT_VERSION (2)
#   4  bytes: ARGON2_MEMORY_COST_KIB (uint32 big-endian)
#   4  bytes: ARGON2_TIME_COST       (uint32 big-endian)
#   4  bytes: ARGON2_PARALLELISM     (uint32 big-endian)
#   1  byte:  salt length (always 32)
#   32 bytes: Argon2id salt
#   1  byte:  nonce1 length (always 12) — ChaCha20-Poly1305
#   12 bytes: nonce1
#   1  byte:  nonce2 length (always 12) — AES-256-GCM-SIV
#   12 bytes: nonce2
#   ----
#   76 bytes total
_HEADER_STRUCT = struct.Struct(">4sBIII B32s B12s B12s")
_HEADER_SIZE = 76  # bytes
assert _HEADER_STRUCT.size == _HEADER_SIZE, "Header struct size mismatch"

# v1 header struct kept for format detection only (read-only, never written)
_HEADER_STRUCT_V1 = struct.Struct(">4sBIII B16sB12s")
_HEADER_SIZE_V1 = 47


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def _derive_master_key(passphrase: bytearray, salt: bytes, *,
                       memory_cost: int = ARGON2_MEMORY_COST_KIB,
                       time_cost: int = ARGON2_TIME_COST,
                       parallelism: int = ARGON2_PARALLELISM) -> bytearray:
    """Derive a 256-bit master key from passphrase + salt using Argon2id.

    The returned bytearray is the input to HKDF — it is never used directly
    as a cipher key. Caller must wipe after use.
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
    return bytearray(raw)


def _derive_subkeys(master_key: bytearray, salt: bytes) -> tuple[bytearray, bytearray]:
    """Derive two independent 256-bit cipher keys via HKDF-SHA512.

    Uses different info labels so the two keys are cryptographically
    independent: knowing one key reveals nothing about the other.

    Returns:
        (key_chacha, key_aes) — both mutable bytearrays, caller must wipe.
    """
    key_chacha = bytearray(
        HKDF(algorithm=hashes.SHA512(), length=32, salt=salt, info=_HKDF_INFO_CHACHA)
        .derive(bytes(master_key))
    )
    key_aes = bytearray(
        HKDF(algorithm=hashes.SHA512(), length=32, salt=salt, info=_HKDF_INFO_AES)
        .derive(bytes(master_key))
    )
    return key_chacha, key_aes


# Backward-compat alias used by tests that call _derive_key directly
def _derive_key(passphrase: bytearray, salt: bytes, **kwargs) -> bytearray:
    return _derive_master_key(passphrase, salt, **kwargs)


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
            # Get the current user's name for ACL grant
            current_user = os.environ.get("USERNAME", "")
            # Remove inherited permissions, then grant SYSTEM, Administrators,
            # and the current user full control (so the app works without admin).
            acl_cmd = [
                "icacls", dir_str, "/inheritance:r",
                "/grant:r", "SYSTEM:(OI)(CI)F",
                "/grant:r", "Administrators:(OI)(CI)F",
            ]
            if current_user:
                acl_cmd.extend(["/grant:r", f"{current_user}:(OI)(CI)F"])
            subprocess.run(
                acl_cmd,
                check=True,
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
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
    """Serialize and double-encrypt a vault state dict (FORMAT_VERSION 2).

    Encryption pipeline:
      plaintext JSON
        → ChaCha20-Poly1305  (inner, key_chacha, nonce1)
        → AES-256-GCM-SIV    (outer, key_aes,    nonce2)
        → stored ciphertext

    Both layers use the full 76-byte header as AEAD additional data (AAD),
    so any header modification invalidates both authentication tags.

    Binary layout:
      [76-byte header][4-byte ct_len][ct_len bytes double-ciphertext]

    SEC-06: Two independent fresh nonces per call (os.urandom(12) each).
    """
    salt    = os.urandom(ARGON2_SALT_LEN)   # 32 bytes
    nonce1  = os.urandom(NONCE_LEN)          # ChaCha20-Poly1305
    nonce2  = os.urandom(NONCE_LEN)          # AES-256-GCM-SIV

    master_key = _derive_master_key(passphrase, salt)
    key_chacha, key_aes = _derive_subkeys(master_key, salt)

    try:
        header = _HEADER_STRUCT.pack(
            MAGIC,
            FORMAT_VERSION,
            ARGON2_MEMORY_COST_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            ARGON2_SALT_LEN, salt,
            NONCE_LEN, nonce1,
            NONCE_LEN, nonce2,
        )

        plaintext_json = json.dumps(plaintext_dict, separators=(",", ":")).encode("utf-8")

        # Layer 1: ChaCha20-Poly1305 — stream cipher inner layer
        layer1 = ChaCha20Poly1305(bytes(key_chacha)).encrypt(nonce1, plaintext_json, header)

        # Layer 2: AES-256-GCM-SIV — nonce-misuse-resistant outer layer
        layer2 = AESGCMSIV(bytes(key_aes)).encrypt(nonce2, layer1, header)

    finally:
        wipe_bytes(master_key)
        wipe_bytes(key_chacha)
        wipe_bytes(key_aes)

    ct_len_field = struct.pack(">I", len(layer2))
    return header + ct_len_field + layer2


def _decrypt_vault(blob: bytes, passphrase: bytearray) -> dict[str, Any]:
    """Decrypt and deserialize a vault binary blob.

    Supports FORMAT_VERSION 2 (double AEAD).
    FORMAT_VERSION 1 vaults are detected and rejected with an upgrade notice.

    Raises:
        VaultTamperedError: Magic bytes wrong or format unrecognised.
        VaultUnlockError:   Authentication tag failed (wrong passphrase or
                            ciphertext tampering). Generic — never reveals
                            which layer failed or which condition triggered.
    """
    if len(blob) < 5:
        raise VaultTamperedError("Vault file is too small to be valid")

    if blob[:4] != MAGIC:
        raise VaultTamperedError("Vault file has invalid magic bytes")

    version = blob[4]
    if version == 1:
        raise VaultTamperedError(
            "Vault was created with FORMAT_VERSION 1 (AES-256-GCM only). "
            "Run 'sudo wireseal fresh-start' then 'sudo wireseal init' to "
            "upgrade to the v2 dual-layer encryption engine."
        )
    if version != FORMAT_VERSION:
        raise VaultTamperedError(
            f"Unsupported vault FORMAT_VERSION {version} "
            f"(this build supports version {FORMAT_VERSION})."
        )

    min_size = _HEADER_SIZE + 4
    if len(blob) < min_size:
        raise VaultTamperedError("Vault file is too small to be valid")

    (
        _magic,
        _version,
        memory_cost,
        time_cost,
        parallelism,
        _salt_len,
        salt,
        _nonce1_len,
        nonce1,
        _nonce2_len,
        nonce2,
    ) = _HEADER_STRUCT.unpack(blob[:_HEADER_SIZE])

    header = blob[:_HEADER_SIZE]

    ct_len = struct.unpack(">I", blob[_HEADER_SIZE:_HEADER_SIZE + 4])[0]
    expected_total = _HEADER_SIZE + 4 + ct_len
    if len(blob) < expected_total:
        raise VaultUnlockError("Vault unlock failed") from None
    ciphertext = blob[_HEADER_SIZE + 4: expected_total]

    master_key = _derive_master_key(passphrase, salt,
                                    memory_cost=memory_cost,
                                    time_cost=time_cost,
                                    parallelism=parallelism)
    key_chacha, key_aes = _derive_subkeys(master_key, salt)

    try:
        # Peel outer layer: AES-256-GCM-SIV
        try:
            layer1 = AESGCMSIV(bytes(key_aes)).decrypt(nonce2, ciphertext, header)
        except InvalidTag:
            raise VaultUnlockError("Vault unlock failed") from None

        # Peel inner layer: ChaCha20-Poly1305
        try:
            plaintext = ChaCha20Poly1305(bytes(key_chacha)).decrypt(nonce1, layer1, header)
        except InvalidTag:
            raise VaultUnlockError("Vault unlock failed") from None

    finally:
        wipe_bytes(master_key)
        wipe_bytes(key_chacha)
        wipe_bytes(key_aes)

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
