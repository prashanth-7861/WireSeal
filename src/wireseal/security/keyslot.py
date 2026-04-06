"""Keyslot module -- LUKS-style per-admin key wrapping for WireSeal vault.

Each keyslot stores a passphrase-derived wrapping key (Argon2id) used to
AES-256-GCM encrypt the vault master key. Multiple keyslots allow multiple
admins to unlock the same vault with independent passphrases.

Binary layout (144 bytes per keyslot):
  [32]  Argon2id salt
  [4]   memory_cost KiB (uint32 BE)
  [4]   time_cost (uint32 BE)
  [4]   parallelism (uint32 BE)
  [12]  AES-256-GCM nonce
  [48]  wrapped_master_key (32 ciphertext + 16 GCM tag)
  [40]  admin_id UTF-8, null-padded
  ----
  144 bytes total
"""

import hmac
import os
import struct
from dataclasses import dataclass, field

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import KeyslotNotFoundError
from .secret_types import SecretBytes

# ---------------------------------------------------------------------------
# Default Argon2id parameters for new keyslots (production values per SECURITY-SPEC §1.2)
# ---------------------------------------------------------------------------
KEYSLOT_TIME_COST = 13           # Calibrated: ≥500ms minimum (512ms measured, time_cost=13)
KEYSLOT_MEMORY_COST_KIB = 262144  # 256 MiB
KEYSLOT_PARALLELISM = 4
KEYSLOT_HASH_LEN = 32

# Development/test override — pass as **_DEV_FAST_PARAMS to create_keyslot / unlock_keyslot
_DEV_FAST_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}

_SLOT_STRUCT = struct.Struct(">III")  # memory_cost, time_cost, parallelism (3 x uint32 BE)
_SLOT_SIZE = 144
_ADMIN_ID_FIELD_LEN = 40

assert _SLOT_STRUCT.size == 12
assert 32 + 12 + 12 + 48 + 40 == _SLOT_SIZE, "Keyslot binary layout size mismatch"


@dataclass
class Keyslot:
    admin_id: str
    role: str             # "owner" | "admin" | "readonly"
    salt: bytes           # 32 bytes, Argon2id salt
    memory_cost: int      # KiB
    time_cost: int
    parallelism: int
    nonce: bytes          # 12 bytes, AES-GCM nonce
    wrapped_key: bytes    # 48 bytes = 32 ciphertext + 16 GCM tag


@dataclass
class KeyslotStore:
    keyslots: list[Keyslot] = field(default_factory=list)

    def find(self, admin_id: str) -> Keyslot | None:
        for slot in self.keyslots:
            if hmac.compare_digest(slot.admin_id.encode(), admin_id.encode()):
                return slot
        return None

    def admin_ids(self) -> list[str]:
        return [s.admin_id for s in self.keyslots]

    def owner_count(self) -> int:
        return sum(1 for s in self.keyslots if s.role == "owner")


def _derive_wrapping_key(passphrase: bytearray | bytes, salt: bytes, *,
                         time_cost: int, memory_cost: int, parallelism: int) -> bytearray:
    """Derive a 32-byte AES wrapping key from passphrase via Argon2id.

    Acquires the shared _ARGON2_SEMAPHORE from vault to serialise concurrent
    KDF calls and prevent simultaneous 256 MiB allocations on low-RAM hardware.
    """
    from .vault import _ARGON2_SEMAPHORE
    with _ARGON2_SEMAPHORE:
        raw = hash_secret_raw(
            secret=bytes(passphrase),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=KEYSLOT_HASH_LEN,
            type=Type.ID,
        )
    return bytearray(raw)


def create_keyslot(admin_id: str, passphrase: bytearray | bytes,
                   master_key: bytes | bytearray, *, role: str = "admin",
                   time_cost: int = KEYSLOT_TIME_COST,
                   memory_cost: int = KEYSLOT_MEMORY_COST_KIB,
                   parallelism: int = KEYSLOT_PARALLELISM) -> Keyslot:
    """Create a new keyslot wrapping master_key under passphrase.

    Uses Argon2id to derive a wrapping key, then AES-256-GCM to encrypt
    the 32-byte master key. The admin_id is used as AEAD additional data
    to bind the ciphertext to this admin's identity.

    Pass time_cost/memory_cost/parallelism (or **_DEV_FAST_PARAMS) to override
    production Argon2id parameters for testing.
    """
    salt = os.urandom(32)
    nonce = os.urandom(12)
    wrapping_key = _derive_wrapping_key(
        passphrase, salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )
    try:
        aesgcm = AESGCM(bytes(wrapping_key))
        wrapped = aesgcm.encrypt(nonce, bytes(master_key), admin_id.encode("utf-8"))
    finally:
        for i in range(len(wrapping_key)):
            wrapping_key[i] = 0

    assert len(wrapped) == 48, f"Expected 48 bytes wrapped key, got {len(wrapped)}"

    return Keyslot(
        admin_id=admin_id,
        role=role,
        salt=salt,
        memory_cost=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism,
        nonce=nonce,
        wrapped_key=wrapped,
    )


def unlock_keyslot(slot: Keyslot, passphrase: bytearray | bytes,
                   **_ignored_kdf_params) -> bytearray:
    """Decrypt the master key from a keyslot using passphrase.

    Raises KeyslotNotFoundError if the passphrase is wrong (GCM auth failure).

    KDF parameters are always read from the slot (they were serialised at
    creation time). Any extra keyword arguments (e.g. **_DEV_FAST_PARAMS)
    are accepted but ignored so that test code can pass fast params without
    special-casing unlock vs create.
    """
    wrapping_key = _derive_wrapping_key(
        passphrase, slot.salt,
        time_cost=slot.time_cost,
        memory_cost=slot.memory_cost,
        parallelism=slot.parallelism,
    )
    try:
        aesgcm = AESGCM(bytes(wrapping_key))
        try:
            plaintext = aesgcm.decrypt(slot.nonce, slot.wrapped_key, slot.admin_id.encode("utf-8"))
        except InvalidTag:
            raise KeyslotNotFoundError(
                "Keyslot unlock failed -- wrong passphrase or tampered keyslot"
            )
    finally:
        for i in range(len(wrapping_key)):
            wrapping_key[i] = 0

    return bytearray(plaintext)


def find_and_unlock(store: KeyslotStore, admin_id: str,
                    passphrase: bytearray | bytes, **kdf_params) -> bytearray:
    """Find the keyslot for admin_id and unlock it.

    Uses constant-time comparison to find the slot. Raises KeyslotNotFoundError
    if admin_id not found OR if passphrase is wrong.

    Extra keyword arguments are forwarded to unlock_keyslot (accepted but
    ignored — KDF params come from the stored slot).
    """
    slot = store.find(admin_id)
    if slot is None:
        raise KeyslotNotFoundError(f"No keyslot found for admin_id '{admin_id}'")
    return unlock_keyslot(slot, passphrase, **kdf_params)


def serialize_keyslot(slot: Keyslot) -> bytes:
    """Serialize a keyslot to exactly 144 bytes."""
    admin_id_bytes = slot.admin_id.encode("utf-8")
    if len(admin_id_bytes) > _ADMIN_ID_FIELD_LEN:
        raise ValueError(
            f"admin_id too long: {len(admin_id_bytes)} bytes (max {_ADMIN_ID_FIELD_LEN})"
        )
    admin_id_padded = admin_id_bytes.ljust(_ADMIN_ID_FIELD_LEN, b"\x00")

    header = _SLOT_STRUCT.pack(slot.memory_cost, slot.time_cost, slot.parallelism)
    result = slot.salt + header + slot.nonce + slot.wrapped_key + admin_id_padded
    assert len(result) == _SLOT_SIZE, (
        f"Serialized keyslot is {len(result)} bytes, expected {_SLOT_SIZE}"
    )
    return result


def deserialize_keyslot(data: bytes, *, role: str = "admin") -> Keyslot:
    """Deserialize a keyslot from exactly 144 bytes."""
    if len(data) != _SLOT_SIZE:
        raise ValueError(f"Expected {_SLOT_SIZE} bytes, got {len(data)}")

    salt = data[0:32]
    memory_cost, time_cost, parallelism = _SLOT_STRUCT.unpack(data[32:44])

    # Bounds-check KDF parameters to prevent absurdly weak keys on restore.
    _MIN_MEM_KIB = 65_536   # 64 MiB
    _MIN_TIME = 1
    if memory_cost < _MIN_MEM_KIB:
        raise ValueError(
            f"Keyslot memory_cost {memory_cost} KiB is below minimum {_MIN_MEM_KIB}"
        )
    if time_cost < _MIN_TIME:
        raise ValueError(f"Keyslot time_cost {time_cost} is below minimum {_MIN_TIME}")
    if parallelism < 1 or parallelism > 255:
        raise ValueError(f"Keyslot parallelism {parallelism} out of range [1, 255]")

    nonce = data[44:56]
    wrapped_key = data[56:104]
    admin_id_raw = data[104:144]
    admin_id = admin_id_raw.rstrip(b"\x00").decode("utf-8")

    return Keyslot(
        admin_id=admin_id,
        role=role,
        salt=salt,
        memory_cost=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism,
        nonce=nonce,
        wrapped_key=wrapped_key,
    )


def serialize_store(store: KeyslotStore) -> bytes:
    """Serialize all keyslots to N*144 bytes."""
    return b"".join(serialize_keyslot(s) for s in store.keyslots)


def deserialize_store(data: bytes, roles: dict[str, str] | None = None) -> KeyslotStore:
    """Deserialize N keyslots from N*144 bytes.

    roles: optional dict mapping admin_id -> role. If not provided, all slots get role="admin".
    """
    if len(data) % _SLOT_SIZE != 0:
        raise ValueError(
            f"Keyslot data length {len(data)} is not a multiple of {_SLOT_SIZE}"
        )

    store = KeyslotStore()
    roles = roles or {}
    for i in range(0, len(data), _SLOT_SIZE):
        slot = deserialize_keyslot(data[i:i + _SLOT_SIZE])
        slot.role = roles.get(slot.admin_id, "admin")
        store.keyslots.append(slot)
    return store
