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
  - Layer 1 -- ChaCha20-Poly1305 (inner):
      Stream cipher; no block-size alignment leakage; widely considered
      quantum-resistant compared to AES-based ciphers; 96-bit nonce.
  - Layer 2 -- AES-256-GCM-SIV (outer, nonce-misuse resistant):
      If os.urandom() ever produces a repeated nonce (negligible probability
      with 96-bit nonces) AES-GCM-SIV only reveals that two ciphertexts have
      identical plaintexts -- it does NOT reveal the plaintext itself. This is
      a strictly stronger security guarantee than standard AES-GCM.
  - Both layers use the full 76-byte header as AEAD additional data (AAD),
    so any modification to the header (KDF params, nonces, salt) invalidates
    both authentication tags simultaneously.
  - Atomic writes: tmp + fsync + os.replace (never partially written)
  - Strict file permissions: vault dir 700, vault file 600 (Unix)
  - All derived keys wiped in-place immediately after use (mutable bytearray)
  - Generic error message for unlock failures (passphrase/tampering indistinct)

FORMAT_VERSION 1 vaults (AES-256-GCM only) are detected and rejected with a
clear upgrade message -- run fresh-start + init to create a v2 vault.

FORMAT_VERSION 3 adds LUKS-style keyslots: multiple admins can independently
unlock the same vault using their own passphrase. Each keyslot wraps the shared
32-byte master key under an Argon2id-derived AES-256-GCM key.
"""

import json
import os
import struct
import subprocess
import sys
import threading
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .atomic import atomic_write
from .exceptions import AdminRoleError, KeyslotExistsError, VaultTamperedError, VaultUnlockError
from .keyslot import (
    KeyslotStore,
    create_keyslot,
    deserialize_store,
    find_and_unlock,
    serialize_store,
)
from .secret_types import SecretBytes
from .secrets_wipe import wipe_bytes

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

MAGIC = b"WGAV"  # WireGuard Automate Vault

FORMAT_VERSION = 2  # v1: AES-256-GCM; v2: ChaCha20-Poly1305 + AES-256-GCM-SIV + HKDF
FORMAT_VERSION_3 = 3  # v3: v2 payload + LUKS-style keyslots

# CRITICAL: memory_cost is in KiB. 256 MiB = 262144 KiB. Passing 256 = catastrophically weak.
ARGON2_MEMORY_COST_KIB = 262144  # 256 MiB
ARGON2_TIME_COST = 13            # Calibrated: ≥500ms minimum (512ms measured, time_cost=13)
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32   # Argon2id master key length (HKDF input)
ARGON2_SALT_LEN = 32   # v2: 256-bit salt (was 16 bytes in v1)

NONCE_LEN = 12         # 96-bit nonce for both ChaCha20 and AES-GCM-SIV

# HKDF domain separation labels -- different info strings guarantee the two
# subkeys are cryptographically independent even if master_key is known.
_HKDF_INFO_CHACHA = b"wireseal-v2-chacha20-poly1305"
_HKDF_INFO_AES    = b"wireseal-v2-aes-256-gcm-siv"

DEFAULT_VAULT_DIR = Path.home() / ".wireseal"
DEFAULT_VAULT_PATH = DEFAULT_VAULT_DIR / "vault.enc"

# Serialise Argon2id calls so multiple threads don't compete for memory.
_ARGON2_SEMAPHORE = threading.Semaphore(1)

# Binary header layout v2 (76 bytes total):
#   4  bytes: MAGIC (b'WGAV')
#   1  byte:  FORMAT_VERSION (2)
#   4  bytes: ARGON2_MEMORY_COST_KIB (uint32 big-endian)
#   4  bytes: ARGON2_TIME_COST       (uint32 big-endian)
#   4  bytes: ARGON2_PARALLELISM     (uint32 big-endian)
#   1  byte:  salt length (always 32)
#   32 bytes: Argon2id salt
#   1  byte:  nonce1 length (always 12) -- ChaCha20-Poly1305
#   12 bytes: nonce1
#   1  byte:  nonce2 length (always 12) -- AES-256-GCM-SIV
#   12 bytes: nonce2
#   ----
#   76 bytes total
_HEADER_STRUCT = struct.Struct(">4sBIII B32s B12s B12s")
_HEADER_SIZE = 76  # bytes
assert _HEADER_STRUCT.size == _HEADER_SIZE, "Header struct size mismatch"

# v1 header struct kept for format detection only (read-only, never written)
_HEADER_STRUCT_V1 = struct.Struct(">4sBIII B16sB12s")
_HEADER_SIZE_V1 = 47

# v3 prefix: MAGIC(4) + FORMAT_VERSION(1) + keyslot_count(1) = 6 bytes
_HEADER_STRUCT_V3_PREFIX = struct.Struct(">4sBB")
_V3_PREFIX_SIZE = 6
assert _HEADER_STRUCT_V3_PREFIX.size == _V3_PREFIX_SIZE

# In v3, after the keyslot block we re-use the v2 payload header layout BUT
# strip off the leading MAGIC+VERSION that were already consumed.  The remaining
# v2 body fields occupy bytes [5..75] of the 76-byte v2 header, i.e. 71 bytes.
# We parse them with the same _HEADER_STRUCT and use offsets into the slice.
_KEYSLOT_ITEM_SIZE = 144


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------


def _migrate_v1_to_v2(data: dict) -> dict:
    """Migrate schema_version 1 vault JSON to schema_version 2.

    Adds admins, dns_mappings, backup_config and TTL fields introduced in
    schema v2.  Mutates and returns the dict.
    """
    data["admins"] = {
        "owner": {
            "role": "owner",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "totp_secret_b32": None,
            "totp_enrolled_at": None,
            "backup_codes": [],
            "last_unlock": None,
        }
    }
    data["dns_mappings"] = {}
    data["backup_config"] = {
        "enabled": False,
        "destination": "local",
        "local_path": None,
        "ssh_host": None,
        "ssh_user": None,
        "ssh_path": None,
        "webdav_url": None,
        "webdav_user": None,
        "keep_n": 10,
        "last_backup_at": None,
    }
    for _client_name, client_data in data.get("clients", {}).items():
        client_data.setdefault("ttl_seconds", None)
        client_data.setdefault("ttl_expires_at", None)
        client_data.setdefault("permanent", True)
    data["schema_version"] = 2
    return data


def _canonical_v2_initial_state() -> dict[str, Any]:
    """Return the canonical schema_version 2 initial vault state."""
    return {
        "schema_version": 2,
        "server": {},
        "clients": {},
        "ip_pool": {},
        "integrity": {},
        "admins": {
            "owner": {
                "role": "owner",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "totp_secret_b32": None,
                "totp_enrolled_at": None,
                "backup_codes": [],
                "last_unlock": None,
            }
        },
        "dns_mappings": {},
        "backup_config": {
            "enabled": False,
            "destination": "local",
            "local_path": None,
            "ssh_host": None,
            "ssh_user": None,
            "ssh_path": None,
            "webdav_url": None,
            "webdav_user": None,
            "keep_n": 10,
            "last_backup_at": None,
        },
    }


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def _derive_master_key(passphrase: bytearray, salt: bytes, *,
                       memory_cost: int = ARGON2_MEMORY_COST_KIB,
                       time_cost: int = ARGON2_TIME_COST,
                       parallelism: int = ARGON2_PARALLELISM) -> bytearray:
    """Derive a 256-bit master key from passphrase + salt using Argon2id.

    The returned bytearray is the input to HKDF -- it is never used directly
    as a cipher key. Caller must wipe after use.

    Acquires _ARGON2_SEMAPHORE to serialise concurrent KDF calls (prevents
    multiple threads from each allocating 256 MiB simultaneously).
    """
    with _ARGON2_SEMAPHORE:
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
        (key_chacha, key_aes) -- both mutable bytearrays, caller must wipe.
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
# Low-level encrypt / decrypt -- FORMAT_VERSION 2
# ---------------------------------------------------------------------------


def _encrypt_payload(plaintext_dict: dict[str, Any], master_key: bytearray,
                     salt: bytes, nonce1: bytes, nonce2: bytes,
                     header: bytes) -> bytes:
    """Inner payload encryption: ChaCha20-Poly1305 + AES-256-GCM-SIV.

    Derives subkeys from master_key via HKDF. Wipes subkeys in finally.
    Returns just the double-ciphertext (without header prefix).
    """
    key_chacha, key_aes = _derive_subkeys(master_key, salt)
    try:
        plaintext_json = json.dumps(plaintext_dict, separators=(",", ":")).encode("utf-8")
        layer1 = ChaCha20Poly1305(bytes(key_chacha)).encrypt(nonce1, plaintext_json, header)
        layer2 = AESGCMSIV(bytes(key_aes)).encrypt(nonce2, layer1, header)
    finally:
        wipe_bytes(key_chacha)
        wipe_bytes(key_aes)
    return layer2


def _decrypt_payload(ciphertext: bytes, master_key: bytearray,
                     salt: bytes, nonce1: bytes, nonce2: bytes,
                     header: bytes) -> dict[str, Any]:
    """Inner payload decryption: AES-256-GCM-SIV (outer) then ChaCha20-Poly1305 (inner).

    Wipes subkeys in finally. Raises VaultUnlockError on GCM tag failure.
    """
    key_chacha, key_aes = _derive_subkeys(master_key, salt)
    try:
        try:
            layer1 = AESGCMSIV(bytes(key_aes)).decrypt(nonce2, ciphertext, header)
        except InvalidTag:
            raise VaultUnlockError("Vault unlock failed") from None
        try:
            plaintext = ChaCha20Poly1305(bytes(key_chacha)).decrypt(nonce1, layer1, header)
        except InvalidTag:
            raise VaultUnlockError("Vault unlock failed") from None
    finally:
        wipe_bytes(key_chacha)
        wipe_bytes(key_aes)
    return json.loads(plaintext.decode("utf-8"))


def _encrypt_vault(plaintext_dict: dict[str, Any], passphrase: bytearray) -> bytes:
    """Serialize and double-encrypt a vault state dict (FORMAT_VERSION 2).

    Encryption pipeline:
      plaintext JSON
        -> ChaCha20-Poly1305  (inner, key_chacha, nonce1)
        -> AES-256-GCM-SIV    (outer, key_aes,    nonce2)
        -> stored ciphertext

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

        layer2 = _encrypt_payload(plaintext_dict, master_key, salt, nonce1, nonce2, header)
    finally:
        wipe_bytes(master_key)

    ct_len_field = struct.pack(">I", len(layer2))
    return header + ct_len_field + layer2


def _encrypt_vault_v3(plaintext_dict: dict[str, Any], master_key: bytearray,
                      store: KeyslotStore) -> bytes:
    """Serialize and double-encrypt a vault state dict (FORMAT_VERSION 3).

    FORMAT_VERSION 3 binary layout:
      [4]   MAGIC
      [1]   FORMAT_VERSION = 3
      [1]   keyslot_count (uint8)
      [N*144] keyslots
      [76]  v2-style payload header (Argon2 params vestigial, salt/nonces active)
      [4]   ct_len
      [ct_len] double-ciphertext

    The v2-style payload header's Argon2 params are written but not used for
    v3 unlock (keyslots store their own params).  The salt/nonce fields ARE
    used as HKDF salt and cipher nonces.
    """
    salt   = os.urandom(ARGON2_SALT_LEN)
    nonce1 = os.urandom(NONCE_LEN)
    nonce2 = os.urandom(NONCE_LEN)

    keyslot_count = len(store.keyslots)
    assert keyslot_count <= 255, "keyslot_count exceeds uint8 max"

    # Build v3 prefix (6 bytes)
    v3_prefix = _HEADER_STRUCT_V3_PREFIX.pack(MAGIC, FORMAT_VERSION_3, keyslot_count)

    # Serialise keyslots
    keyslots_bytes = serialize_store(store)

    # Build v2-style payload header (76 bytes) -- Argon2 params vestigial
    payload_header = _HEADER_STRUCT.pack(
        MAGIC,
        FORMAT_VERSION_3,
        ARGON2_MEMORY_COST_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        ARGON2_SALT_LEN, salt,
        NONCE_LEN, nonce1,
        NONCE_LEN, nonce2,
    )

    # AAD = full v3 prefix + keyslots + payload header (everything before ciphertext)
    aad = v3_prefix + keyslots_bytes + payload_header

    layer2 = _encrypt_payload(plaintext_dict, master_key, salt, nonce1, nonce2, aad)

    ct_len_field = struct.pack(">I", len(layer2))
    return aad + ct_len_field + layer2


def _decrypt_vault(blob: bytes, passphrase: bytearray) -> tuple[dict[str, Any], bytearray]:
    """Decrypt and deserialize a v2 vault binary blob.

    Returns (data_dict, master_key).  Caller MUST wipe master_key after use.

    Supports FORMAT_VERSION 2 only. FORMAT_VERSION 1 and 3 are handled
    by their own paths before this function is called.

    Raises:
        VaultTamperedError: Magic bytes wrong or format unrecognised.
        VaultUnlockError:   Authentication tag failed (wrong passphrase or
                            ciphertext tampering). Generic -- never reveals
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
    try:
        data = _decrypt_payload(ciphertext, master_key, salt, nonce1, nonce2, header)
    except VaultUnlockError:
        wipe_bytes(master_key)
        raise

    return data, master_key


def _decrypt_vault_v3(blob: bytes, admin_id: str,
                      passphrase: bytearray) -> tuple[dict[str, Any], bytearray, KeyslotStore]:
    """Decrypt and deserialize a FORMAT_VERSION 3 vault binary blob.

    Returns (data_dict, master_key, store).  Caller MUST wipe master_key after use.

    Raises:
        VaultTamperedError: Magic bytes wrong or structural corruption.
        VaultUnlockError:   Keyslot unlock failed or payload GCM tag failed.
    """
    if len(blob) < _V3_PREFIX_SIZE:
        raise VaultTamperedError("Vault file is too small to be valid")

    magic, version, keyslot_count = _HEADER_STRUCT_V3_PREFIX.unpack(blob[:_V3_PREFIX_SIZE])
    if magic != MAGIC:
        raise VaultTamperedError("Vault file has invalid magic bytes")
    if version != FORMAT_VERSION_3:
        raise VaultTamperedError(
            f"Unsupported vault FORMAT_VERSION {version} in v3 path"
        )

    keyslots_end = _V3_PREFIX_SIZE + keyslot_count * _KEYSLOT_ITEM_SIZE
    if len(blob) < keyslots_end + _HEADER_SIZE + 4:
        raise VaultTamperedError("Vault file is truncated (keyslot region)")

    keyslots_bytes = blob[_V3_PREFIX_SIZE:keyslots_end]
    store = deserialize_store(keyslots_bytes)

    # Unlock the keyslot for this admin_id
    from .exceptions import KeyslotNotFoundError
    try:
        master_key = find_and_unlock(store, admin_id, passphrase)
    except KeyslotNotFoundError:
        raise VaultUnlockError("Vault unlock failed") from None

    # Parse the v2-style payload header that follows the keyslot block
    payload_hdr_start = keyslots_end
    payload_hdr_end = payload_hdr_start + _HEADER_SIZE
    if len(blob) < payload_hdr_end + 4:
        wipe_bytes(master_key)
        raise VaultTamperedError("Vault file is truncated (payload header)")

    (
        _magic2,
        _version2,
        _memory_cost,
        _time_cost,
        _parallelism,
        _salt_len,
        salt,
        _nonce1_len,
        nonce1,
        _nonce2_len,
        nonce2,
    ) = _HEADER_STRUCT.unpack(blob[payload_hdr_start:payload_hdr_end])

    # AAD = everything before the ciphertext length field
    aad = blob[:payload_hdr_end]

    ct_len = struct.unpack(">I", blob[payload_hdr_end:payload_hdr_end + 4])[0]
    ciphertext_start = payload_hdr_end + 4
    expected_total = ciphertext_start + ct_len
    if len(blob) < expected_total:
        wipe_bytes(master_key)
        raise VaultUnlockError("Vault unlock failed") from None
    ciphertext = blob[ciphertext_start:expected_total]

    try:
        data = _decrypt_payload(ciphertext, master_key, salt, nonce1, nonce2, aad)
    except VaultUnlockError:
        wipe_bytes(master_key)
        raise

    return data, master_key, store


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

    def __init__(self, data: dict[str, Any], vault: "Vault | None" = None) -> None:
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
        # v2 schema fields -- preserved as-is (no secret wrapping needed)
        if "admins" in data:
            self._data["admins"] = data["admins"]
        if "dns_mappings" in data:
            self._data["dns_mappings"] = data["dns_mappings"]
        if "backup_config" in data:
            self._data["backup_config"] = data["backup_config"]
        if "client_configs" in data:
            self._data["client_configs"] = data["client_configs"]
        self._wiped = False
        # Reference back to the owning Vault instance (for keyslot management)
        self.vault: Vault | None = vault

    @property
    def data(self) -> dict[str, Any]:
        """Public alias for _data (used by v3 API callers)."""
        return self._data

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
        d: dict[str, Any] = {
            "schema_version": self._data["schema_version"],
            "server": self._unwrap_secrets(self._data["server"]),
            "clients": {
                name: self._unwrap_secrets(client)
                for name, client in self._data["clients"].items()
            },
            "ip_pool": self._data["ip_pool"],
            "integrity": self._data["integrity"],
        }
        # Include v2 schema fields when present
        if "admins" in self._data:
            d["admins"] = self._data["admins"]
        if "dns_mappings" in self._data:
            d["dns_mappings"] = self._data["dns_mappings"]
        if "backup_config" in self._data:
            d["backup_config"] = self._data["backup_config"]
        if "client_configs" in self._data:
            d["client_configs"] = self._data["client_configs"]
        return d

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
        # For FORMAT_VERSION 3 sessions: auto-save before wiping so keyslot
        # mutations (add/remove/change) are persisted without requiring an
        # explicit vault.save() call.
        exc_type = args[0] if args else None
        if exc_type is None and self.vault is not None:
            if self.vault._session_format == FORMAT_VERSION_3 and self.vault._session_store is not None:
                try:
                    self.vault._save_v3(self)
                except Exception:
                    # Do not suppress original exception; wipe and re-raise save error
                    self.wipe()
                    if self.vault is not None:
                        self.vault._wipe_session()
                    raise
        self.wipe()
        if self.vault is not None:
            self.vault._wipe_session()


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

    Usage pattern (v3, multi-admin):

        with vault.open(passphrase, admin_id="alice") as state:
            state.data["server"]
            state.vault.add_keyslot("bob", bob_pass)
    """

    def __init__(self, vault_path: Path = DEFAULT_VAULT_PATH) -> None:
        self._path = vault_path
        # Session state: set during open(), wiped on context-manager exit.
        self._session_master_key: bytearray | None = None
        self._session_passphrase: bytearray | None = None  # v2 only
        self._session_store: KeyslotStore | None = None     # v3 only
        self._session_format: int = 0
        self._session_state: "VaultState | None" = None    # weak ref to active VaultState

    def _wipe_session(self) -> None:
        """Wipe all session key material stored on this Vault instance."""
        if self._session_master_key is not None:
            wipe_bytes(self._session_master_key)
            self._session_master_key = None
        if self._session_passphrase is not None:
            wipe_bytes(self._session_passphrase)
            self._session_passphrase = None
        self._session_store = None
        self._session_format = 0
        self._session_state = None

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        vault_path: Path,
        passphrase: SecretBytes | bytearray,
        initial_state: dict[str, Any] | None = None,
        hint: str | None = None,
        keyslot_params: dict | None = None,
    ) -> "Vault":
        """Create a new vault file at vault_path encrypted with passphrase.

        Passphrase length enforcement (VAULT-03): minimum 12 characters.
        Directory permissions (VAULT-02): 700 on Unix, best-effort icacls on Windows.
        Atomic write (VAULT-05): tmp + fsync + os.replace, never world-readable.
        Hint (VAULT-06): stored as plaintext .hint file with a clear warning.

        Args:
            vault_path:    Absolute path where vault.enc will be written.
            passphrase:    SecretBytes or bytearray holding the passphrase (min 12 chars).
            initial_state: Dict matching the vault JSON schema.  If None, a canonical
                           schema_version 2 state is created.
            hint:          Optional plaintext passphrase hint.

        Returns:
            A Vault instance pointing at vault_path.

        Raises:
            ValueError: If passphrase is shorter than 12 characters.
        """
        # Normalise passphrase to bytearray
        if isinstance(passphrase, SecretBytes):
            raw = passphrase.expose_secret()
        else:
            raw = passphrase

        # VAULT-03: enforce minimum passphrase length BEFORE any file I/O
        if len(raw) < 12:
            raise ValueError("Passphrase must be at least 12 characters")

        _ensure_vault_dir(vault_path.parent)

        state_to_write = initial_state if initial_state is not None else _canonical_v2_initial_state()
        blob = _encrypt_vault(state_to_write, bytearray(raw) if not isinstance(raw, bytearray) else raw)
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

    def open(self, passphrase: SecretBytes | bytearray,
             admin_id: str = "owner") -> "VaultState":
        """Decrypt vault and return a VaultState instance.

        Supports FORMAT_VERSION 2 (passphrase -> Argon2id -> master key) and
        FORMAT_VERSION 3 (keyslot lookup -> master key).

        The caller is responsible for wiping the VaultState when done.
        Prefer using it as a context manager:

            with vault.open(passphrase) as state:
                ...

        Args:
            passphrase: SecretBytes or bytearray holding the passphrase.
            admin_id:   For FORMAT_VERSION 3, the admin whose keyslot to unlock.
                        Ignored for FORMAT_VERSION 2 vaults.

        Raises:
            VaultTamperedError: Structural tampering detected (bad magic bytes).
            VaultUnlockError:   Decryption failed (wrong passphrase or GCM failure).
        """
        # Normalise passphrase
        if isinstance(passphrase, SecretBytes):
            raw = bytearray(passphrase.expose_secret())
        else:
            raw = bytearray(passphrase)

        blob = self._path.read_bytes()

        if len(blob) < 5:
            raise VaultTamperedError("Vault file is too small to be valid")

        if blob[:4] != MAGIC:
            raise VaultTamperedError("Vault file has invalid magic bytes")

        version = blob[4]

        self._wipe_session()  # clear any previous session

        if version == FORMAT_VERSION_3:
            data, master_key, store = _decrypt_vault_v3(blob, admin_id, raw)
            # Apply roles from the decrypted JSON payload to the keyslot store.
            # The binary keyslot format does not encode role; roles live in data["admins"].
            admins_cfg: dict = data.get("admins", {})
            for slot in store.keyslots:
                slot_role = admins_cfg.get(slot.admin_id, {}).get("role", "admin")
                slot.role = slot_role
            self._session_master_key = master_key
            self._session_store = store
            self._session_format = FORMAT_VERSION_3
        elif version == FORMAT_VERSION:
            data, master_key = _decrypt_vault(blob, raw)
            self._session_master_key = master_key
            self._session_passphrase = bytearray(raw)
            self._session_format = FORMAT_VERSION
        else:
            # Let the existing error-path in _decrypt_vault handle v1 and unknowns
            _decrypt_vault(blob, raw)
            raise VaultTamperedError(
                f"Unsupported vault FORMAT_VERSION {version}"
            )

        state = VaultState(data, vault=self)
        self._session_state = state
        return state

    def save(self, state: VaultState, passphrase: SecretBytes | bytearray) -> None:
        """Re-encrypt and atomically write updated vault state (FORMAT_VERSION 2).

        For FORMAT_VERSION 3 vaults, use _save_v3() instead (called internally).

        Args:
            state:      Current VaultState (must not be wiped).
            passphrase: SecretBytes or bytearray holding the current passphrase.
        """
        if isinstance(passphrase, SecretBytes):
            raw = bytearray(passphrase.expose_secret())
        else:
            raw = bytearray(passphrase)

        plaintext = state.to_dict()
        blob = _encrypt_vault(plaintext, raw)
        atomic_write(self._path, blob, mode=0o600)

    def _save_v3(self, state: VaultState) -> None:
        """Re-encrypt and atomically write vault state as FORMAT_VERSION 3.

        Requires that session master_key and keyslot store are available.
        """
        if self._session_master_key is None or self._session_store is None:
            raise RuntimeError("_save_v3 called without active v3 session")
        plaintext = state.to_dict()
        blob = _encrypt_vault_v3(plaintext, self._session_master_key, self._session_store)
        atomic_write(self._path, blob, mode=0o600)

    # ------------------------------------------------------------------
    # Keyslot management (FORMAT_VERSION 3)
    # ------------------------------------------------------------------

    def add_keyslot(self, admin_id: str, passphrase: bytearray | bytes,
                    role: str = "admin",
                    keyslot_params: dict | None = None) -> None:
        """Add a new keyslot for admin_id wrapping the current master key.

        Must be called within an active open() context (so master key is available).

        If the vault is currently FORMAT_VERSION 2, this upgrades it to
        FORMAT_VERSION 3 by wrapping the existing master key in an owner keyslot
        (using the session passphrase) and the new admin's keyslot.

        Args:
            admin_id:       Unique identifier for the new admin.
            passphrase:     Passphrase to protect this admin's keyslot.
            role:           "owner" | "admin" | "readonly".
            keyslot_params: Optional dict with Argon2id override params
                            (time_cost, memory_cost, parallelism).  Used by
                            tests to pass _DEV_FAST_PARAMS and avoid slow KDF.

        Raises:
            KeyslotExistsError: admin_id already has a keyslot.
            RuntimeError:       Called outside an open() context.
        """
        if self._session_master_key is None:
            raise RuntimeError("add_keyslot requires an active open() context")

        # Determine current store (upgrade v2 -> v3 if needed)
        if self._session_format == FORMAT_VERSION:
            # Upgrade: create owner keyslot from session passphrase
            if self._session_passphrase is None:
                raise RuntimeError("Cannot upgrade v2 vault: session passphrase not available")
            store = KeyslotStore()
            kp = keyslot_params or {}
            owner_slot = create_keyslot(
                "owner", self._session_passphrase, self._session_master_key, role="owner", **kp
            )
            store.keyslots.append(owner_slot)
            self._session_store = store
            self._session_format = FORMAT_VERSION_3
            # Ensure admins dict reflects the owner keyslot
            if self._session_state is not None:
                if "admins" not in self._session_state.data:
                    self._session_state.data["admins"] = {}
                if "owner" not in self._session_state.data["admins"]:
                    self._session_state.data["admins"]["owner"] = {
                        "role": "owner",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "totp_secret_b32": None,
                        "totp_enrolled_at": None,
                        "backup_codes": [],
                        "last_unlock": None,
                    }
                else:
                    # Ensure role is set correctly
                    self._session_state.data["admins"]["owner"]["role"] = "owner"

        store = self._session_store
        assert store is not None

        # Check for duplicate
        if store.find(admin_id) is not None:
            raise KeyslotExistsError(f"Keyslot for admin_id '{admin_id}' already exists")

        kp = keyslot_params or {}
        new_slot = create_keyslot(admin_id, passphrase, self._session_master_key, role=role, **kp)
        store.keyslots.append(new_slot)

        # Keep admins dict in the session state in sync
        if self._session_state is not None and "admins" in self._session_state.data:
            if admin_id not in self._session_state.data["admins"]:
                self._session_state.data["admins"][admin_id] = {
                    "role": role,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "totp_secret_b32": None,
                    "totp_enrolled_at": None,
                    "backup_codes": [],
                    "last_unlock": None,
                }

    def remove_keyslot(self, admin_id: str) -> None:
        """Remove the keyslot for admin_id.

        Raises:
            AdminRoleError:         Removing would leave no owner keyslot.
            KeyslotNotFoundError:   admin_id has no keyslot.
            RuntimeError:           Called outside an open() context.
        """
        from .exceptions import KeyslotNotFoundError

        if self._session_store is None:
            raise RuntimeError("remove_keyslot requires an active v3 open() context")

        store = self._session_store
        slot = store.find(admin_id)
        if slot is None:
            raise KeyslotNotFoundError(f"No keyslot found for admin_id '{admin_id}'")

        # Guard: do not remove the last owner
        if slot.role == "owner" and store.owner_count() <= 1:
            raise AdminRoleError(
                f"Cannot remove keyslot for '{admin_id}': it is the last owner keyslot"
            )

        store.keyslots = [s for s in store.keyslots if s.admin_id != admin_id]

        # Keep admins dict in the session state in sync
        if self._session_state is not None and "admins" in self._session_state.data:
            self._session_state.data["admins"].pop(admin_id, None)

    def list_keyslots(self) -> list[dict]:
        """Return a list of {admin_id, role} dicts for all keyslots.

        Raises:
            RuntimeError: Called outside an open() context.
        """
        if self._session_store is None:
            raise RuntimeError("list_keyslots requires an active v3 open() context")
        return [{"admin_id": s.admin_id, "role": s.role}
                for s in self._session_store.keyslots]

    def change_keyslot_passphrase(self, admin_id: str, old_passphrase: bytearray,
                                  new_passphrase: bytearray) -> None:
        """Change the passphrase protecting a keyslot.

        Unlocks the keyslot with old_passphrase (to verify correctness), then
        re-wraps the master key under new_passphrase.

        Raises:
            KeyslotNotFoundError: admin_id not found or old_passphrase wrong.
            RuntimeError:         Called outside an open() context.
        """
        if self._session_store is None:
            raise RuntimeError("change_keyslot_passphrase requires an active v3 open() context")

        store = self._session_store
        slot = store.find(admin_id)
        if slot is None:
            from .exceptions import KeyslotNotFoundError
            raise KeyslotNotFoundError(f"No keyslot found for admin_id '{admin_id}'")

        # Verify old passphrase is correct (unlock raises KeyslotNotFoundError if wrong)
        from .keyslot import unlock_keyslot
        recovered = unlock_keyslot(slot, old_passphrase)
        wipe_bytes(recovered)

        # Re-wrap master key under new passphrase
        new_slot = create_keyslot(admin_id, new_passphrase, self._session_master_key,
                                  role=slot.role)
        # Replace in store (preserve ordering)
        store.keyslots = [new_slot if s.admin_id == admin_id else s
                          for s in store.keyslots]

    # ------------------------------------------------------------------
    # Context-manager support for Vault itself (auto-save v3 on exit)
    # ------------------------------------------------------------------

    # Note: VaultState's __exit__ calls vault._wipe_session().
    # Keyslot mutations (add/remove/change) are held in _session_store in memory.
    # The caller must explicitly call vault._save_v3(state) or vault.save(state, pp)
    # to persist changes.  For simplicity in the context manager pattern, we
    # intercept VaultState.__exit__ to flush v3 stores automatically.

    # ------------------------------------------------------------------
    # Passphrase change (VAULT-07)
    # ------------------------------------------------------------------

    def change_passphrase(
        self,
        old_passphrase: SecretBytes | bytearray,
        new_passphrase: SecretBytes | bytearray,
    ) -> None:
        """Decrypt with old passphrase, re-encrypt with new passphrase, write atomically.

        New salt and new nonce are generated during re-encryption (os.urandom).
        Intermediate plaintext is wiped after use.

        Raises:
            VaultUnlockError: Old passphrase is wrong.
            ValueError:       New passphrase is shorter than 12 characters.
        """
        if isinstance(old_passphrase, SecretBytes):
            old_raw = bytearray(old_passphrase.expose_secret())
        else:
            old_raw = bytearray(old_passphrase)

        if isinstance(new_passphrase, SecretBytes):
            new_raw = bytearray(new_passphrase.expose_secret())
        else:
            new_raw = bytearray(new_passphrase)

        if len(new_raw) < 12:
            raise ValueError("Passphrase must be at least 12 characters")

        blob = self._path.read_bytes()
        data, master_key = _decrypt_vault(blob, old_raw)
        wipe_bytes(master_key)
        try:
            new_blob = _encrypt_vault(data, new_raw)
            atomic_write(self._path, new_blob, mode=0o600)
        finally:
            data.clear()

    # ------------------------------------------------------------------
    # Integrity verification (VAULT-08)
    # ------------------------------------------------------------------

    def verify_integrity(self, passphrase: SecretBytes | bytearray) -> bool:
        """Verify that the vault can be decrypted (GCM tag + Argon2 salt integrity).

        Attempts decryption; if successful, wipes the decrypted state and
        returns True. Returns False if the GCM tag check fails.

        Raises:
            VaultTamperedError: Structural tampering detected (bad magic bytes).
        """
        if isinstance(passphrase, SecretBytes):
            raw = bytearray(passphrase.expose_secret())
        else:
            raw = bytearray(passphrase)

        blob = self._path.read_bytes()
        try:
            data, master_key = _decrypt_vault(blob, raw)
            wipe_bytes(master_key)
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
