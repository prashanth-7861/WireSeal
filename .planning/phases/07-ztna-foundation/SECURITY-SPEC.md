---
phase: "07"
document: SECURITY-SPEC
status: draft
author: Senior Cryptography/Security Engineer
date: 2026-04-02
---

# WireSeal Phase 7 — Cryptographic Security Specification

This document is the authoritative cryptographic specification for three Phase 7
features. It is written for the implementation engineer. Every algorithm choice,
parameter, data structure, and operation is specified precisely enough to
implement correctly without further design decisions.

Read the entire document before writing any code. Specs 1, 2, and 3 are
interdependent: Spec 2 stores data defined by Spec 1, and Spec 3 uses fields
defined by Spec 1.

---

## Table of Contents

1. [Spec 1 — Multi-Admin Vault (LUKS-style Keyslots)](#spec-1)
2. [Spec 2 — TOTP 2FA (RFC 6238, stdlib-only)](#spec-2)
3. [Spec 3 — Ephemeral Key TTL Security Model](#spec-3)
4. [Cross-Cutting Security Risks](#cross-cutting-risks)

---

<a name="spec-1"></a>
## Spec 1: Multi-Admin Vault (LUKS-style Keyslots)

### 1.1 Current Vault Schema (FORMAT_VERSION 2 — before this spec)

The current vault stores its JSON payload encrypted under two AES layers. The
passphrase is the *only* secret input: Argon2id(passphrase, salt) directly
produces the material fed into HKDF, which produces the two cipher keys. There
is no independent vault master key. The inner JSON currently has this structure:

```json
{
  "schema_version": 1,
  "server": {
    "private_key": "<base64>",
    "public_key":  "<base64>",
    "endpoint":    "<ip:port>",
    "listen_port": 51820
  },
  "clients": {
    "<name>": {
      "private_key":  "<base64>",
      "public_key":   "<base64>",
      "psk":          "<base64>",
      "allowed_ips":  "<cidr>",
      "assigned_ip":  "<ip>"
    }
  },
  "ip_pool": { ... },
  "integrity": { ... }
}
```

**The binary envelope (FORMAT_VERSION 2) is unchanged by this spec.** Only the
inner JSON payload schema changes.

---

### 1.2 New Vault Schema (schema_version 2)

```json
{
  "schema_version": 2,

  "vault_header": {
    "created_at":    "<ISO8601-UTC>",
    "upgraded_at":   "<ISO8601-UTC> | null",
    "owner_slot_id": "<slot_id string>"
  },

  "keyslots": {
    "<slot_id>": {
      "slot_id":      "<uuid4 string>",
      "admin_name":   "<string>",
      "role":         "owner | admin | readonly",
      "argon2_salt":  "<base64url — 32 bytes>",
      "argon2_time":  10,
      "argon2_mem":   262144,
      "argon2_par":   4,
      "wrapping_iv":  "<base64url — 12 bytes>",
      "wrapped_key":  "<base64url — 48 bytes (32 ciphertext + 16 GCM tag)>",
      "created_at":   "<ISO8601-UTC>",
      "totp": null
    }
  },

  "master_key_check": "<base64url — 32 bytes>",

  "server": { ... },
  "clients": {
    "<name>": { ... }
  },
  "ip_pool":     { ... },
  "integrity":   { ... }
}
```

Field-by-field types and constraints:

| Field | Type | Constraints |
|---|---|---|
| `schema_version` | integer | Must equal `2` |
| `vault_header.created_at` | string | ISO 8601 UTC, set once at creation/migration |
| `vault_header.upgraded_at` | string or null | null for new vaults; set during migration |
| `vault_header.owner_slot_id` | string | Must reference a key in `keyslots` with `role == "owner"` |
| `keyslots` | object | Minimum 1 entry (the owner). Maximum 16 entries (practical limit). |
| `keyslots[id].slot_id` | string | UUID4 format. Matches the object key. |
| `keyslots[id].admin_name` | string | Non-empty, unique across all slots. |
| `keyslots[id].role` | string | Exactly one of: `"owner"`, `"admin"`, `"readonly"` |
| `keyslots[id].argon2_salt` | string | base64url, decodes to exactly 32 bytes |
| `keyslots[id].argon2_time` | integer | >= 3 (MUST NOT be reduced below this floor) |
| `keyslots[id].argon2_mem` | integer | >= 65536 KiB (MUST NOT be reduced below this floor) |
| `keyslots[id].argon2_par` | integer | 1–16 |
| `keyslots[id].wrapping_iv` | string | base64url, decodes to exactly 12 bytes |
| `keyslots[id].wrapped_key` | string | base64url, decodes to exactly 48 bytes (32 plaintext master key + 16 AEAD tag) |
| `keyslots[id].created_at` | string | ISO 8601 UTC |
| `keyslots[id].totp` | object or null | See Spec 2 for the TOTP sub-schema |
| `master_key_check` | string | base64url, decodes to exactly 32 bytes. HKDF-derived check value (see §1.4). |

**Role semantics:**
- `owner`: can do everything an `admin` can, plus: add/remove/promote/demote
  other admins, reset another admin's TOTP. There must always be exactly one
  `owner` slot (enforcement described in §1.7).
- `admin`: can read and write all server/client data.
- `readonly`: can read server/client data but cannot modify vault contents.
  Cannot unlock via the API endpoints that require write access.

---

### 1.3 Master Key

**Algorithm:** 256-bit random key drawn from `os.urandom(32)`.

This key never appears outside the vault. It lives only in memory during an
unlock session and on disk only as a wrapped (encrypted) form inside each
keyslot.

**Why random, not passphrase-derived?**
With a passphrase-derived key, changing or revoking one admin requires
re-encrypting the entire vault under a new key. With a random master key,
adding/removing an admin only touches their keyslot entry — the vault body is
unchanged. This is structurally identical to LUKS keyslots.

**Entropy requirement:** `os.urandom(32)` is the only acceptable source.
`secrets.token_bytes(32)` is equivalent (wraps `os.urandom`) and also
acceptable. No PRNG seeded from time, PID, or any deterministic input.

---

### 1.4 Keyslot Wrapping Scheme

Each keyslot protects the 32-byte vault master key using AES-256-GCM with a
key derived from that admin's passphrase.

**Wrapping key derivation (per keyslot):**

```python
import os
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SLOT_ARGON2_TIME    = 10
SLOT_ARGON2_MEM_KIB = 262144  # 256 MiB
SLOT_ARGON2_PAR     = 4
SLOT_ARGON2_LEN     = 32

SLOT_HKDF_INFO = b"wireseal-v2-keyslot-wrapping-key"

def derive_slot_wrapping_key(passphrase: bytes, salt: bytes) -> bytearray:
    """
    Derives the 256-bit AES-GCM wrapping key for a keyslot.
    passphrase: raw UTF-8 bytes of the admin's passphrase
    salt:       32 bytes from os.urandom(32), unique per slot
    Returns:    32-byte bytearray; caller must wipe after use
    """
    argon2_output = hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=SLOT_ARGON2_TIME,
        memory_cost=SLOT_ARGON2_MEM_KIB,
        parallelism=SLOT_ARGON2_PAR,
        hash_len=SLOT_ARGON2_LEN,
        type=Type.ID,
    )
    # Pass through HKDF for domain separation. The HKDF salt is the same
    # Argon2 salt to avoid introducing a second independent salt.
    wrapping_key = bytearray(
        HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            info=SLOT_HKDF_INFO,
        ).derive(argon2_output)
    )
    # Wipe intermediate Argon2 output
    argon2_ba = bytearray(argon2_output)
    for i in range(len(argon2_ba)):
        argon2_ba[i] = 0
    return wrapping_key
```

**Wrapping (encrypting the master key into a slot):**

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD_PREFIX = b"wireseal-keyslot-v1:"

def wrap_master_key(
    master_key: bytes,      # 32-byte vault master key
    wrapping_key: bytes,    # 32-byte key from derive_slot_wrapping_key
    slot_id: str,           # UUID4 string — used as AAD to bind ciphertext to this slot
) -> tuple[bytes, bytes]:
    """
    Returns (iv, ciphertext) where:
      iv          = 12 bytes (os.urandom(12))
      ciphertext  = 48 bytes (32 encrypted + 16 GCM tag)
    """
    iv = os.urandom(12)
    aad = AAD_PREFIX + slot_id.encode("utf-8")
    ct = AESGCM(wrapping_key).encrypt(iv, master_key, aad)
    assert len(ct) == 48  # 32 plaintext + 16 GCM tag
    return iv, ct
```

**Unwrapping (decrypting the master key from a slot):**

```python
from cryptography.exceptions import InvalidTag

def unwrap_master_key(
    wrapped_key: bytes,     # 48-byte ciphertext+tag
    wrapping_key: bytes,    # 32-byte key from derive_slot_wrapping_key
    iv: bytes,              # 12-byte IV from the slot record
    slot_id: str,
) -> bytes:
    """
    Returns the 32-byte vault master key, or raises InvalidTag on failure.
    Caller must never catch InvalidTag silently — always raise VaultUnlockError.
    """
    aad = AAD_PREFIX + slot_id.encode("utf-8")
    return AESGCM(wrapping_key).decrypt(iv, wrapped_key, aad)
```

**Why AES-256-GCM here instead of AES-256-GCM-SIV?**

AES-GCM-SIV's nonce-misuse resistance is valuable when nonces are reused across
many encryptions with the same key. A keyslot key is derived fresh per unlock
and used for exactly one wrap operation, so nonce reuse is impossible in
practice. Standard AES-256-GCM is sufficient. The HKDF domain-separation label
(`SLOT_HKDF_INFO`) ensures that the wrapping key cannot be confused with the
vault body keys even if both use the same Argon2 output as input material.

**AAD binding:**

The `AAD_PREFIX + slot_id` additional data binds the wrapped ciphertext to its
slot. If an attacker copies a wrapped key from slot A into slot B, GCM
decryption will fail because the AAD used during decryption (slot B's ID) will
not match the AAD used during encryption (slot A's ID). This prevents keyslot
transplant attacks.

**Master key check value:**

`master_key_check` is stored at the vault JSON top level. It allows the unlock
flow to verify that the unwrapped master key is correct before attempting to
use it to decrypt the vault body. This avoids wasted computation and provides
an early-exit before the expensive outer decryption.

```python
def compute_master_key_check(master_key: bytes) -> bytes:
    """
    Returns a 32-byte check value derived from the master key.
    Stored in vault JSON as master_key_check (base64url).
    This value is not secret (it is inside the encrypted vault body),
    so no key material is exposed.
    """
    return HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=None,
        info=b"wireseal-master-key-check-v1",
    ).derive(master_key)
```

The check value lives *inside* the encrypted vault payload, not in plaintext.
It cannot be used by an attacker to verify guesses at the master key without
first decrypting the vault — which already requires either the passphrase or
the master key itself.

---

### 1.5 Migration Path (schema_version 1 to 2)

Migration is triggered automatically when an existing vault is opened with a
passphrase and `schema_version == 1` is detected. The process is:

```
Step 1: Decrypt existing vault body using current passphrase
        (uses existing _decrypt_vault — FORMAT_VERSION 2 binary envelope unchanged)

Step 2: Check schema_version in decrypted JSON
        If schema_version == 2: migration already done, return

Step 3: Generate vault master key
        master_key = os.urandom(32)

Step 4: Generate owner keyslot ID
        slot_id = str(uuid.uuid4())

Step 5: Generate slot salt
        slot_salt = os.urandom(32)

Step 6: Derive wrapping key from existing passphrase + slot_salt
        wrapping_key = derive_slot_wrapping_key(passphrase_bytes, slot_salt)

Step 7: Wrap master key
        iv, wrapped_key = wrap_master_key(master_key, wrapping_key, slot_id)
        wipe(wrapping_key)

Step 8: Compute check value
        check = compute_master_key_check(master_key)

Step 9: Build new vault JSON
        - Set schema_version = 2
        - Preserve all existing server, clients, ip_pool, integrity fields
        - Add vault_header with created_at (existing), upgraded_at (now), owner_slot_id
        - Add keyslots dict with one entry for the owner
        - Add master_key_check = base64url(check)

Step 10: Re-encrypt vault using existing _encrypt_vault(new_json, passphrase)
         This generates new nonces/salt for the binary envelope.

Step 11: Atomic write to disk

Step 12: Wipe master_key from memory
```

**CRITICAL: The migration MUST be idempotent.** If power fails between steps
10 and 11, the old vault is still intact on disk. If power fails during step 11,
the atomic write (tmp + fsync + os.replace) guarantees the old file survives.
There is no window where both old and new vaults are absent.

**Passphrase continuity:** The admin's passphrase does not change during
migration. The same passphrase that unlocked the old vault now unlocks the new
vault via the owner keyslot.

---

### 1.6 Unlock Flow (schema_version 2)

```
Input: passphrase (bytearray, UTF-8 bytes of the admin's passphrase)

Step 1: Read vault file from disk
        blob = vault_path.read_bytes()

Step 2: Decrypt binary envelope (FORMAT_VERSION 2 unchanged)
        vault_json = _decrypt_vault(blob, passphrase)
        -- This validates the Argon2id-derived outer envelope.
        -- If this fails, raise VaultUnlockError (wrong passphrase or tampered file).
        -- IMPORTANT: the passphrase used here is the admin's passphrase,
           which is ALSO used to derive the keyslot wrapping key. The binary
           envelope is re-keyed from the same passphrase on every vault save,
           so the outer layer always matches the most-recently-saved admin
           passphrase. (See §1.9 for why this is true.)

Step 3: Check schema_version
        If schema_version == 1: trigger migration (§1.5), re-run from Step 1
        If schema_version == 2: continue

Step 4: Try each keyslot
        For each slot_id, slot in vault_json["keyslots"].items():
            a. Decode slot_salt = base64url_decode(slot["argon2_salt"])
            b. Derive wrapping_key = derive_slot_wrapping_key(passphrase, slot_salt)
               (using slot's argon2_time, argon2_mem, argon2_par parameters)
            c. Attempt: master_key = unwrap_master_key(
                   base64url_decode(slot["wrapped_key"]),
                   wrapping_key,
                   base64url_decode(slot["wrapping_iv"]),
                   slot["slot_id"]
               )
               wipe(wrapping_key)
            d. If InvalidTag: wipe wrapping_key, continue to next slot
            e. If success: break

        If no slot succeeded: raise VaultUnlockError("Vault unlock failed")
        (Generic message — never reveal which slot was tried or which failed.)

Step 5: Verify master key check
        expected_check = base64url_decode(vault_json["master_key_check"])
        actual_check   = compute_master_key_check(master_key)
        If not hmac.compare_digest(expected_check, actual_check):
            wipe(master_key)
            raise VaultUnlockError("Vault unlock failed")
        -- This catches the unlikely case of a corrupt wrapped_key that
           happens to pass GCM authentication (should be impossible, but
           provides defense-in-depth).

Step 6: Return (VaultState, slot_id, role)
        -- VaultState is the decrypted vault payload as usual
        -- slot_id identifies which admin unlocked the vault
        -- role is used for authorization checks
        -- master_key must be wiped after the session ends
```

**Performance note:** Step 4 tries each keyslot sequentially. With a 256 MiB
Argon2id budget, each attempt takes approximately 1–5 seconds depending on
hardware. A vault with 8 keyslots could take up to 40 seconds in the worst case
(wrong passphrase tested against all slots). In practice, the unlock is fast
when the correct passphrase matches the first slot tried. The implementation
MAY cache the last-used `slot_id` (e.g., by admin username entered at login)
to try that slot first, avoiding the trial-and-error cost for the common case.

**RISK-01 — Timing side-channel across slots:** If the implementation exits
immediately on the first successful slot and takes longer for wrong passwords
(because it tries all slots), an attacker who can measure unlock time may infer
how many admins exist. Mitigate by continuing to iterate all remaining slots
even after a match (with dummy computations), or by accepting this as a
low-severity information leak (number of slots is not sensitive).

---

### 1.7 Add-Admin Flow

Required authorization: caller's role must be `owner` or `admin`.
Adding an admin with role `owner` requires caller's role to be `owner`.

```
Input: caller's authenticated session (includes master_key in memory),
       new_admin_name (string),
       new_admin_passphrase (bytearray),
       new_admin_role ("owner" | "admin" | "readonly")

Step 1: Validate inputs
        - new_admin_name must be non-empty and not already present in any slot's admin_name
        - new_admin_passphrase must be >= 12 characters
        - If new_admin_role == "owner": caller's role must be "owner"
        - len(vault_json["keyslots"]) < 16 (reject if already at max)

Step 2: Generate slot credentials
        slot_id   = str(uuid.uuid4())
        slot_salt = os.urandom(32)

Step 3: Derive wrapping key for new admin
        wrapping_key = derive_slot_wrapping_key(new_admin_passphrase, slot_salt)

Step 4: Wrap master key with new admin's wrapping key
        iv, wrapped_key = wrap_master_key(master_key, wrapping_key, slot_id)
        wipe(wrapping_key)
        wipe(new_admin_passphrase)

Step 5: Build keyslot entry
        new_slot = {
            "slot_id":      slot_id,
            "admin_name":   new_admin_name,
            "role":         new_admin_role,
            "argon2_salt":  base64url(slot_salt),
            "argon2_time":  SLOT_ARGON2_TIME,
            "argon2_mem":   SLOT_ARGON2_MEM_KIB,
            "argon2_par":   SLOT_ARGON2_PAR,
            "wrapping_iv":  base64url(iv),
            "wrapped_key":  base64url(wrapped_key),
            "created_at":   now_utc_iso(),
            "totp":         null,
        }

Step 6: Insert into vault state
        vault_json["keyslots"][slot_id] = new_slot

Step 7: Save vault
        -- vault.save(state, caller_passphrase)
        -- This re-encrypts the entire vault body under the caller's passphrase
           (the binary envelope's Argon2 KDF uses the caller's passphrase).
        -- New nonces and salt generated automatically.

Step 8: Audit log
        audit.log("add_admin", {
            "added_by_slot_id": caller_slot_id,
            "added_by_name":    caller_name,
            "new_slot_id":      slot_id,
            "new_admin_name":   new_admin_name,
            "role":             new_admin_role,
        })
```

**NOTE on binary envelope re-keying (§1.9):** After `vault.save()`, the binary
envelope is re-encrypted using the *caller's* passphrase. This means the outer
layer can only be unlocked with the *caller's* passphrase. The unlock flow in
§1.6 accounts for this: the binary envelope decryption (Step 2) uses whatever
passphrase is presented, and if it succeeds, the keyslot search (Step 4) finds
the matching slot. Any admin presenting the correct passphrase will succeed at
both steps, because the save operation always uses the currently-authenticated
admin's passphrase for the outer layer.

**RISK-02 — Outer envelope key mismatch:** After admin A adds admin B and saves
the vault with admin A's passphrase, the outer layer is keyed to admin A. If
admin B tries to unlock, the outer layer decryption (Step 2) will fail with
admin B's passphrase. This is a design flaw in the current architecture.

**Resolution for RISK-02:** The outer binary envelope must either:
  (a) Use the vault master key directly (not a per-admin passphrase) to derive
      the outer envelope keys, OR
  (b) Be re-keyed on every unlock to the unlocking admin's passphrase.

**RECOMMENDED DESIGN (resolving RISK-02):**

Option (a) is cleaner. Modify `_encrypt_vault` and `_decrypt_vault` to accept
a `master_key: bytes` parameter instead of `passphrase: bytearray`. The binary
envelope outer layer is always keyed from the vault master key through HKDF.
Each admin's passphrase is used *only* for their keyslot unwrapping. The unlock
flow then becomes:

```
1. Read binary envelope headers (salt, nonces, KDF params) WITHOUT decrypting
2. Try each keyslot:
   a. Derive slot wrapping key from passphrase + slot_salt
   b. Unwrap master_key
   c. Verify master_key_check
3. Decrypt binary envelope using master_key-derived subkeys
```

This requires refactoring `_encrypt_vault`/`_decrypt_vault` to use a 32-byte
key as input rather than a passphrase. The HKDF step inside those functions
continues to apply domain separation. The binary envelope format (76-byte
header) does not change structurally, but the Argon2 parameters in the header
become irrelevant for the outer layer (they are replaced by the keyslot's
Argon2 parameters). The header field can be repurposed or set to zeros.

**Implementation decision required:** The implementation engineer must choose
Option (a) and refactor the vault I/O layer accordingly. This is not optional —
the current passphrase-keyed outer envelope is incompatible with multi-admin
access.

---

### 1.8 Remove-Admin Flow

Required authorization: caller's role must be `owner`.
A non-owner admin cannot remove any admin (including themselves).

```
Input: caller's authenticated session, target_slot_id or target_admin_name

Step 1: Resolve target slot
        Find the keyslot by slot_id or admin_name.
        If not found: raise ValueError("Admin not found")

Step 2: Owner protection check (CRITICAL)
        If target_slot_id == vault_json["vault_header"]["owner_slot_id"]:
            raise ValueError("Cannot remove the owner slot. Promote another admin to owner first.")

        Count remaining slots after removal:
        If len(vault_json["keyslots"]) == 1:
            raise ValueError("Cannot remove the only keyslot. Vault would become inaccessible.")

Step 3: TOTP cleanup
        If target_slot["totp"] is not None:
            -- No cryptographic cleanup needed; the keyslot entry is simply deleted.
            -- The TOTP secret disappears with the slot.

Step 4: Delete keyslot
        del vault_json["keyslots"][target_slot_id]

Step 5: Save vault
        vault.save(state, caller_passphrase)

Step 6: Audit log
        audit.log("remove_admin", {
            "removed_by_slot_id": caller_slot_id,
            "removed_by_name":    caller_name,
            "removed_slot_id":    target_slot_id,
            "removed_admin_name": target_admin_name,
            "removed_role":       target_role,
        })
```

**Note:** No vault re-encryption is needed. The removed admin's passphrase can
no longer unwrap any keyslot. The master key itself is unchanged. This is the
core benefit of the keyslot model.

---

### 1.9 Change-Admin-Passphrase Flow

Required authorization: any admin can change their own passphrase; owner can
change any admin's passphrase.

```
Input: caller's session, target_slot_id, old_passphrase (if target == self),
       new_passphrase

Step 1: Validate new_passphrase >= 12 characters

Step 2: Generate new slot credentials
        new_slot_salt = os.urandom(32)
        new_slot_id   = target_slot_id  -- keep same slot_id

Step 3: Derive new wrapping key
        new_wrapping_key = derive_slot_wrapping_key(new_passphrase, new_slot_salt)

Step 4: Wrap master key with new wrapping key
        new_iv, new_wrapped_key = wrap_master_key(master_key, new_wrapping_key, target_slot_id)
        wipe(new_wrapping_key)

Step 5: Update keyslot entry (in-place)
        slot["argon2_salt"] = base64url(new_slot_salt)
        slot["wrapping_iv"] = base64url(new_iv)
        slot["wrapped_key"] = base64url(new_wrapped_key)
        -- argon2_time, argon2_mem, argon2_par remain at current defaults
        -- totp field is NOT touched

Step 6: Save vault
        vault.save(state, caller_passphrase)

Step 7: Audit log
        audit.log("change_passphrase", {
            "changed_by_slot_id": caller_slot_id,
            "target_slot_id":     target_slot_id,
            "target_admin_name":  target_admin_name,
        })
```

---

### 1.10 Owner Cannot Be Removed — Enforcement Summary

Enforcement happens at three layers:

1. **Remove-Admin Step 2** (above): Rejects removal of the slot referenced by
   `vault_header.owner_slot_id`.

2. **Demote check:** If an `owner` is being demoted to `admin` or `readonly`,
   the code must verify that at least one other `owner` slot exists (or
   simultaneously designate a new owner). Atomic: do both in the same vault
   save operation.

3. **Vault save validation:** Before writing, validate that
   `vault_header.owner_slot_id` exists in `keyslots` and that the referenced
   slot has `role == "owner"`. Reject the save if this invariant is violated.

---

<a name="spec-2"></a>
## Spec 2: TOTP 2FA (RFC 6238, stdlib-only)

No third-party libraries. Uses only: `hmac`, `struct`, `time`, `base64`,
`hashlib`, `secrets`, `os`.

---

### 2.1 TOTP Secret Generation

```python
import secrets
import base64

TOTP_SECRET_BYTES = 20  # 160 bits — RFC 4226 minimum; matches Google Authenticator default

def generate_totp_secret() -> bytes:
    """
    Returns 20 raw bytes of TOTP secret from os.urandom.
    Store as base32 in the vault (no padding).
    """
    return secrets.token_bytes(TOTP_SECRET_BYTES)

def encode_totp_secret(raw: bytes) -> str:
    """
    Returns the base32-encoded secret string (no padding, uppercase).
    This is what the admin sees as their enrollment key, and what is
    stored in the vault.
    """
    return base64.b32encode(raw).decode("ascii").rstrip("=")

def decode_totp_secret(encoded: str) -> bytes:
    """
    Decodes a base32 secret string back to bytes.
    Adds padding before decoding (base32 requires padding to multiple of 8).
    """
    padding_needed = (8 - len(encoded) % 8) % 8
    padded = encoded + "=" * padding_needed
    return base64.b32decode(padded.upper())
```

**Secret length rationale:** RFC 4226 §4 specifies a minimum of 128 bits.
160 bits (20 bytes) is the standard choice and is compatible with all TOTP
apps.

---

### 2.2 TOTP Computation (RFC 6238 / RFC 4226)

```python
import hmac
import hashlib
import struct
import time

TOTP_PERIOD     = 30    # seconds per time step (RFC 6238 default)
TOTP_DIGITS     = 6     # output digits
TOTP_ALGORITHM  = "sha1"  # RFC 6238 default; SHA-1 is correct here per spec
                           # Google Authenticator, Aegis, and Authy all default to SHA-1

def _hotp(secret_bytes: bytes, counter: int) -> str:
    """
    RFC 4226 HOTP: HMAC-SHA1 of counter, truncated to TOTP_DIGITS digits.

    counter: 64-bit big-endian unsigned integer (the time step)
    Returns: zero-padded decimal string of TOTP_DIGITS digits
    """
    # Step 1: Generate HMAC-SHA1
    msg = struct.pack(">Q", counter)   # 8-byte big-endian counter
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()  # 20 bytes

    # Step 2: Dynamic truncation (RFC 4226 §5.3)
    offset = h[-1] & 0x0F              # low 4 bits of last byte
    code = (
        (h[offset]     & 0x7F) << 24 |
        (h[offset + 1] & 0xFF) << 16 |
        (h[offset + 2] & 0xFF) <<  8 |
        (h[offset + 3] & 0xFF)
    )

    # Step 3: Reduce to TOTP_DIGITS digits
    otp = code % (10 ** TOTP_DIGITS)
    return str(otp).zfill(TOTP_DIGITS)

def compute_totp(secret_bytes: bytes, at_time: float | None = None) -> str:
    """
    RFC 6238 TOTP for the current (or given) UNIX timestamp.
    Returns a zero-padded 6-digit string.
    """
    t = at_time if at_time is not None else time.time()
    counter = int(t) // TOTP_PERIOD
    return _hotp(secret_bytes, counter)
```

**Note on TOTP_ALGORITHM:** RFC 6238 defines SHA-1 as the default. SHA-256
and SHA-512 variants exist but are not universally supported by authenticator
apps. Use SHA-1 to ensure interoperability. The short HMAC output (20 bytes)
is reduced to 6 digits; there is no known practical attack on HOTP using
SHA-1 in this construction.

---

### 2.3 Verification with Clock Drift Tolerance

```python
TOTP_WINDOW = 1  # Accept codes from (current - WINDOW) to (current + WINDOW) time steps
                 # Window = 1 means: previous step, current step, next step = 3 codes valid
                 # Each step = 30 seconds, so total tolerance = ±30 seconds

def verify_totp(
    secret_bytes: bytes,
    code: str,
    at_time: float | None = None,
    used_codes: set[str] | None = None,  # See §2.8 anti-replay
) -> tuple[bool, int | None]:
    """
    Verifies a TOTP code against a window of valid steps.

    Returns (valid: bool, step_offset: int | None)
      step_offset is 0 for current step, -1 for previous, +1 for next.
      Returns None if invalid.

    used_codes: set of recently-used (step_counter, code) tuples for anti-replay.
    """
    t = at_time if at_time is not None else time.time()
    current_step = int(t) // TOTP_PERIOD

    # Normalize: strip whitespace, must be exactly TOTP_DIGITS characters
    code = code.strip()
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return False, None

    for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        step = current_step + offset
        expected = _hotp(secret_bytes, step)
        if hmac.compare_digest(expected, code):
            # Anti-replay check (§2.8)
            if used_codes is not None:
                replay_key = f"{step}:{code}"
                if replay_key in used_codes:
                    return False, None   # Replayed code
                used_codes.add(replay_key)
            return True, offset

    return False, None
```

**Window rationale:** A window of ±1 step (±30 seconds) is the standard
practice recommended by RFC 6238 §5.2. A larger window would increase the
exposure window for a stolen code. A window of 0 would reject codes generated
at the beginning or end of a 30-second step on slow systems.

---

### 2.4 QR Code URI Format (otpauth://)

The enrollment URI follows the Key URI Format specification (Google
Authenticator protocol). This URI is rendered as a QR code in the dashboard.

```python
import urllib.parse

APP_ISSUER = "WireSeal"

def build_totp_uri(
    secret_encoded: str,  # base32-encoded (no padding)
    admin_name: str,
    issuer: str = APP_ISSUER,
) -> str:
    """
    Returns an otpauth:// URI suitable for QR code generation.

    Format:
      otpauth://totp/<issuer>:<account>?secret=<secret>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30

    The issuer appears twice: once in the path and once as a query parameter.
    Both are required by the spec for maximum app compatibility.
    """
    account = f"{issuer}:{admin_name}"
    params = urllib.parse.urlencode({
        "secret":    secret_encoded,
        "issuer":    issuer,
        "algorithm": "SHA1",
        "digits":    str(TOTP_DIGITS),
        "period":    str(TOTP_PERIOD),
    })
    encoded_account = urllib.parse.quote(account, safe="")
    return f"otpauth://totp/{encoded_account}?{params}"
```

**Example output:**
```
otpauth://totp/WireSeal%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=WireSeal&algorithm=SHA1&digits=6&period=30
```

**QR code rendering:** Use the existing dashboard mechanism or a pure-Python
QR generator. The URI is the content of the QR code. No library changes are
needed for the URI itself.

---

### 2.5 Verification Flow Integrated with Vault Unlock

The TOTP check is interleaved with the vault unlock flow (Spec 1 §1.6). It
occurs after the keyslot is found (passphrase correct) but before the session
is granted.

```
Modified Step 4e (in Spec 1 §1.6):

  If keyslot unwrap succeeded:
    slot = vault_json["keyslots"][matched_slot_id]

    If slot["totp"] is not None:
      -- TOTP is enrolled for this admin
      -- Prompt for TOTP code (separate from passphrase prompt)
      totp_code = <read from caller>

      -- Get the in-memory used_codes set for this slot
      -- (Lives in the session, not persisted to vault)
      used_codes = _get_session_used_codes(matched_slot_id)

      totp_secret_bytes = decode_totp_secret(slot["totp"]["secret"])
      valid, _ = verify_totp(totp_secret_bytes, totp_code, used_codes=used_codes)
      wipe(totp_secret_bytes)

      If not valid:
        -- Check if it's a backup code (§2.6)
        backup_valid = verify_backup_code(totp_code, slot["totp"], vault_state)
        If not backup_valid:
          wipe(master_key)
          raise VaultUnlockError("Vault unlock failed")

    -- TOTP passed (or not enrolled): continue to Step 5
```

**RISK-03 — TOTP code prompt timing:** The unlock flow reveals that a valid
passphrase was entered (by prompting for a TOTP code). An attacker who can
observe whether a TOTP prompt appears has confirmed a correct passphrase. This
is generally acceptable — the TOTP is a second factor precisely because the
passphrase alone may be compromised. Document this as a known behavior.

---

### 2.6 Backup Codes

**Count:** 8 backup codes per admin.
**Format:** `XXXX-XXXX-XXXX` (three groups of 4 alphanumeric characters,
uppercase, hyphen-separated). Total entropy: 12 characters from alphabet of
size 32 (base32 without padding chars) = log2(32^12) ≈ 60 bits. Sufficient
for single-use codes.

```python
import secrets

BACKUP_CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # base32 alphabet
BACKUP_CODE_COUNT    = 8
BACKUP_CODE_GROUPS   = 3
BACKUP_CODE_LEN      = 4  # characters per group

def generate_backup_codes() -> list[str]:
    """
    Returns a list of 8 backup codes in the format XXXX-XXXX-XXXX.
    Each code is unique within the list.
    """
    codes = set()
    while len(codes) < BACKUP_CODE_COUNT:
        groups = [
            "".join(secrets.choice(BACKUP_CODE_ALPHABET) for _ in range(BACKUP_CODE_LEN))
            for _ in range(BACKUP_CODE_GROUPS)
        ]
        codes.add("-".join(groups))
    return list(codes)
```

**Storage in vault:** Backup codes are stored as HMAC-SHA256 digests (not
plaintext) in the keyslot's `totp` sub-object. A used backup code is
represented by replacing its hash with the string `"used"`.

```python
import hashlib
import hmac

BACKUP_CODE_HMAC_KEY = b"wireseal-backup-code-v1"

def hash_backup_code(code: str) -> str:
    """
    Returns a hex-encoded HMAC-SHA256 of the normalized backup code.
    Normalization: uppercase, strip hyphens and whitespace.
    The HMAC key is a static domain-separation constant (not secret).
    """
    normalized = code.upper().replace("-", "").strip()
    digest = hmac.new(BACKUP_CODE_HMAC_KEY, normalized.encode("ascii"), hashlib.sha256).hexdigest()
    return digest

def verify_backup_code(
    code: str,
    totp_data: dict,
    vault_state,    # VaultState — needed to persist "used" marking
) -> bool:
    """
    Verifies a backup code against the stored hashes.
    Marks the code as used (single-use enforcement).
    Returns True if a valid unused code was found.
    """
    normalized = code.upper().replace("-", "").strip()
    code_hash = hash_backup_code(normalized)

    backup_hashes = totp_data.get("backup_codes", [])
    for i, stored in enumerate(backup_hashes):
        if stored == "used":
            continue
        if hmac.compare_digest(stored, code_hash):
            # Mark used
            totp_data["backup_codes"][i] = "used"
            # vault_state is dirty — caller must vault.save() after unlock
            return True

    return False
```

**Why HMAC instead of plain SHA256?**
A static HMAC key provides domain separation and prevents the hash from being
usable outside this context. Since backup codes are high-entropy (60 bits),
even plain SHA256 would be computationally infeasible to reverse. The HMAC adds
defense-in-depth at negligible cost.

**Backup code lifecycle:**
1. Generated on TOTP enrollment (`totp_enroll`).
2. Shown to the admin exactly once (in the enrollment UI). Not retrievable later.
3. Stored as HMAC-SHA256 digests in `keyslot["totp"]["backup_codes"]` (8 entries).
4. On use: the matching entry is replaced with `"used"` and the vault is saved.
5. Admin can regenerate all backup codes (generates 8 new codes, invalidating old).
   Regeneration requires TOTP verification or owner authorization.

---

### 2.7 Vault Schema — TOTP Sub-Object

This is the structure of `keyslots[id]["totp"]` when TOTP is enrolled:

```json
{
  "secret":       "<base32 string, 20 bytes encoded, no padding>",
  "enrolled_at":  "<ISO8601-UTC>",
  "backup_codes": [
    "<hex HMAC-SHA256>",
    "<hex HMAC-SHA256>",
    "<hex HMAC-SHA256>",
    "<hex HMAC-SHA256>",
    "<hex HMAC-SHA256>",
    "<hex HMAC-SHA256>",
    "<hex HMAC-SHA256>",
    "<hex HMAC-SHA256>"
  ]
}
```

When TOTP is not enrolled: `"totp": null`.

When backup codes are exhausted: the entries in `backup_codes` are all `"used"`.
The admin must regenerate via the dashboard or use a regular TOTP code.

**RISK-04 — TOTP secret in vault plaintext:** The TOTP secret is stored
unencrypted within the vault JSON, which is itself encrypted by the vault body.
An attacker who decrypts the vault (by obtaining any admin's passphrase) gains
the TOTP secret. This is unavoidable in a software-only implementation without
a separate TOTP secret store. The TOTP provides protection against an attacker
who intercepts the passphrase in transit but does not have the vault file. An
attacker with the vault file AND a passphrase has full access regardless of
TOTP — both factors are then compromised.

---

### 2.8 Anti-Replay: Preventing TOTP Code Reuse

A valid TOTP code used within its 30-second window must not be accepted a
second time. This prevents replay of a legitimately-obtained code.

**Storage:** `_session_used_codes: dict[str, set[str]]`
- Maps `slot_id` -> `set` of `"<step>:<code>"` strings
- Held in memory only (not persisted to vault)
- Stored in the API server's `_session` dict alongside the vault state

```python
def _get_session_used_codes(slot_id: str) -> set[str]:
    with _lock:
        if "used_totp_codes" not in _session:
            _session["used_totp_codes"] = {}
        if slot_id not in _session["used_totp_codes"]:
            _session["used_totp_codes"][slot_id] = set()
        return _session["used_totp_codes"][slot_id]

def _prune_old_used_codes(slot_id: str, current_step: int) -> None:
    """
    Remove entries for steps older than current_step - TOTP_WINDOW - 1.
    Prevents unbounded memory growth.
    """
    used_codes = _get_session_used_codes(slot_id)
    cutoff_step = current_step - TOTP_WINDOW - 1
    to_remove = {entry for entry in used_codes
                 if int(entry.split(":")[0]) < cutoff_step}
    used_codes -= to_remove
```

**On vault lock / session expiry:** Call `_session["used_totp_codes"].clear()`.
This is safe because the vault is locked and no further TOTP codes can be
accepted until a new unlock occurs.

**Limitation:** Anti-replay only works within a single API server process.
If two API server instances run concurrently (not a supported configuration),
replay across instances is theoretically possible. This is an acceptable
limitation given WireSeal's single-server deployment model.

---

<a name="spec-3"></a>
## Spec 3: Ephemeral Key TTL Security Model

### 3.1 Client Metadata per Vault Entry

The `clients` dict in the vault JSON is extended with TTL-related fields:

```json
{
  "clients": {
    "<name>": {
      "private_key":       "<base64>",
      "public_key":        "<base64>",
      "psk":               "<base64>",
      "allowed_ips":       "<cidr>",
      "assigned_ip":       "<ip>",

      "ttl_seconds":       86400,
      "created_at":        "<ISO8601-UTC>",
      "last_heartbeat":    "<ISO8601-UTC> | null",
      "expires_at":        "<ISO8601-UTC> | null",
      "permanent":         false,
      "heartbeat_token":   "<hex string — 32 bytes>"
    }
  }
}
```

Field definitions:

| Field | Type | Default | Description |
|---|---|---|---|
| `ttl_seconds` | integer | 86400 | Seconds after last heartbeat (or creation if no heartbeat) before expiry. 0 = no TTL (equivalent to permanent). |
| `created_at` | string | set at creation | ISO 8601 UTC. Used as expiry baseline if `last_heartbeat` is null. |
| `last_heartbeat` | string or null | null | ISO 8601 UTC timestamp of the most recent accepted heartbeat. |
| `expires_at` | string or null | computed | Pre-computed expiry time = max(created_at, last_heartbeat) + ttl_seconds. Updated on creation and on heartbeat. Null only if `permanent == true`. |
| `permanent` | boolean | false | If true, client is never expired by TTL. Heartbeat calls are accepted but have no effect on expiry. |
| `heartbeat_token` | string | generated at creation | 32-byte random hex string. The client uses this token to authenticate heartbeat requests. Stored in the vault (encrypted). Also distributed in the client config file. |

**`expires_at` computation:**

```python
import datetime

def compute_expires_at(
    created_at: str,
    last_heartbeat: str | None,
    ttl_seconds: int,
) -> str | None:
    if ttl_seconds == 0:
        return None  # Treat ttl_seconds=0 as permanent
    baseline_str = last_heartbeat if last_heartbeat is not None else created_at
    baseline = datetime.datetime.fromisoformat(baseline_str)
    expires = baseline + datetime.timedelta(seconds=ttl_seconds)
    return expires.isoformat()
```

---

### 3.2 Heartbeat Endpoint Authentication

The heartbeat endpoint allows a client to prove its continued activity and
reset its TTL timer. The client must NOT have access to the vault or any admin
credential.

**Authentication model: Bearer token (per-client pre-shared secret)**

Each client receives a `heartbeat_token` (32-byte random hex string) at
provisioning time, embedded in their WireGuard config file as a comment or
as a separate `.token` file delivered alongside the config.

**Endpoint:** `POST /api/heartbeat/<client_name>`

**Request:**
```
POST /api/heartbeat/alice HTTP/1.1
Authorization: Bearer <heartbeat_token_hex>
Content-Type: application/json

{}
```

**Server verification:**

```python
import hmac

def verify_heartbeat_token(
    client_name: str,
    token_from_request: str,
    vault_state: VaultState,
) -> bool:
    """
    Verifies the heartbeat token from the Authorization header.
    Returns True if valid, False otherwise.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    client = vault_state.clients.get(client_name)
    if client is None:
        return False

    stored_token = client.get("heartbeat_token", "")
    if not stored_token:
        return False

    # Both values are hex strings — compare directly
    return hmac.compare_digest(
        stored_token.lower(),
        token_from_request.strip().lower()
    )
```

**Token generation at client provisioning:**

```python
import secrets

def generate_heartbeat_token() -> str:
    """Returns a 32-byte random token as a 64-character lowercase hex string."""
    return secrets.token_hex(32)
```

**Token delivery:** Include the token in the client config bundle. Options:
1. As a comment in the `.conf` file: `# HEARTBEAT_TOKEN=<hex>`
2. As a separate `<name>.token` file alongside `<name>.conf`
3. Displayed once in the dashboard QR code alongside the WireGuard config

Option 2 is recommended — it keeps the token accessible without modifying
the WireGuard config syntax.

**RISK-05 — Token interception:** The heartbeat token is a long-term secret.
If an attacker intercepts it, they can keep a client alive indefinitely without
having the client's WireGuard private key. However:
- The heartbeat endpoint only resets the TTL timer. It does not grant VPN access.
- WireGuard access requires the client's private key (separate secret).
- The token is transmitted over HTTPS (local network, self-signed certificate)
  or over localhost only (API bound to 127.0.0.1 — see api.py).

**RISK-06 — Localhost binding:** The API is currently bound to 127.0.0.1:8080.
If the heartbeat endpoint must be reachable by remote VPN clients, the binding
must change (e.g., to the WireGuard interface IP). The heartbeat endpoint MUST
require HTTPS or be accessible only over the WireGuard tunnel. This
architectural decision must be made before implementation.

**Recommendation for RISK-06:** Bind the heartbeat endpoint to the WireGuard
interface IP (e.g., 10.0.0.1) and require the client to call it over the VPN
tunnel. This means: client is alive (has established a WireGuard session) AND
presents the correct heartbeat token. This is a stronger liveness check than
a token alone.

---

### 3.3 Expiry Enforcement

Expiry enforcement runs in a background thread within the `wireseal serve`
process. It checks every 60 seconds.

**Background thread loop:**

```python
import threading
import datetime
import subprocess

EXPIRY_CHECK_INTERVAL = 60  # seconds

def _expiry_check_loop(vault: Vault, get_passphrase, audit_log, wg_iface: str):
    """
    Background thread function. Runs indefinitely until the shutdown event is set.
    Checks for expired clients and evicts them.
    """
    while not _shutdown_event.is_set():
        try:
            _run_expiry_check(vault, get_passphrase, audit_log, wg_iface)
        except Exception as e:
            audit_log.log("expiry_check_error", {"error": str(e)}, success=False)
        _shutdown_event.wait(timeout=EXPIRY_CHECK_INTERVAL)
```

**Per-check logic:**

```python
def _run_expiry_check(vault, get_passphrase, audit_log, wg_iface):
    now = datetime.datetime.now(datetime.timezone.utc)

    with vault.open(get_passphrase()) as state:
        expired_clients = []

        for name, client in state.clients.items():
            if client.get("permanent", False):
                continue
            expires_at_str = client.get("expires_at")
            if expires_at_str is None:
                continue
            expires_at = datetime.datetime.fromisoformat(expires_at_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
            if now >= expires_at:
                expired_clients.append(name)

        if not expired_clients:
            return

        for name in expired_clients:
            client = state.clients[name]
            public_key = client["public_key"]
            if isinstance(public_key, SecretBytes):
                public_key = public_key.expose_secret().decode("utf-8")

            # Step 1: Remove from WireGuard
            try:
                subprocess.run(
                    ["wg", "set", wg_iface, "peer", public_key, "remove"],
                    check=True, capture_output=True
                )
            except subprocess.CalledProcessError as e:
                audit_log.log("expiry_wg_remove_failed", {
                    "client": name,
                    "error": e.stderr.decode(errors="replace")
                }, success=False)
                # Continue — still remove from vault even if wg command fails

            # Step 2: Remove from vault state
            del state.clients[name]

            # Step 3: Release IP back to pool (implementation-specific)
            # ip_pool handling omitted here — follows existing remove-client logic

            # Step 4: Audit
            audit_log.log("client_expired", {
                "client_name":   name,
                "expired_at":    now.isoformat(),
                "expires_at":    expires_at_str,
                "public_key":    "<redacted>",
            })

        # Step 5: Save vault with expired clients removed
        vault.save(state, get_passphrase())
```

**Eviction steps in order:**

1. Compute expired set (clients where `expires_at <= now` and `permanent == false`)
2. For each expired client: `wg set <iface> peer <pubkey> remove`
3. Delete client from vault state
4. Release assigned IP back to ip_pool
5. Audit log `client_expired` event
6. `vault.save()` atomically — all evictions in one save

---

### 3.4 Race Conditions

**Race: Concurrent heartbeat + expiry check**

Scenario:
- T=0: Expiry check thread reads vault. Client X has `expires_at = T-1` (expired).
- T=1: Heartbeat request arrives for client X. Heartbeat thread reads vault and
  updates `last_heartbeat` and `expires_at`. Vault saved.
- T=2: Expiry check thread, using its stale read from T=0, deletes client X.

Result: The heartbeat arrived in time but the client was evicted due to a stale
read.

**Resolution: Lock-then-recheck pattern**

The expiry check and the heartbeat endpoint must share a single mutex. Before
performing eviction, re-read the client's current `expires_at` and verify it
is still expired:

```python
# Pseudo-code for eviction with recheck:
with _vault_write_lock:
    with vault.open(get_passphrase()) as fresh_state:
        client = fresh_state.clients.get(name)
        if client is None:
            return  # Already removed
        if client.get("permanent", False):
            return  # Marked permanent since we last checked
        expires_at = datetime.datetime.fromisoformat(client["expires_at"])
        if now < expires_at:
            return  # Heartbeat arrived between our check and now
        # Safe to evict
        _do_evict(fresh_state, name, ...)
        vault.save(fresh_state, get_passphrase())
```

The `_vault_write_lock` is a module-level `threading.Lock()` held for the
duration of all vault write operations (heartbeat updates, expiry evictions,
client additions/removals). The existing `_lock = threading.RLock()` in api.py
may be used for this purpose, or a dedicated lock may be added.

**Race: Two simultaneous heartbeats for the same client**

Both heartbeats arrive at T=0. Both read the vault. Both compute a new
`expires_at`. Both try to save. The second save overwrites the first.

This is benign: both saves set `expires_at` to approximately the same value
(current_time + ttl_seconds). The outcome is correct.

**Race: Expiry check while vault is locked**

If the vault is locked (no in-memory passphrase), the expiry check cannot run.
This is acceptable — if an admin locks the vault, the server is in a degraded
state and no client management operations should be expected.

The background thread should check `_session["passphrase"] is not None` before
attempting to open the vault, and skip the check if locked.

---

### 3.5 Permanent Clients

**Flag:** `permanent: bool` in the client vault entry.

**Semantics:**
- `permanent == true`: The client is never expired by the background TTL thread.
  Heartbeat requests are accepted (200 OK) but do not update `expires_at`.
  The `expires_at` field is set to `null` when `permanent` is set.
- `permanent == false` (default): Normal TTL enforcement applies.

**Who can set the permanent flag:**
- `owner` role: can set/unset `permanent` for any client
- `admin` role: can set/unset `permanent` for any client
- `readonly` role: cannot modify the permanent flag
- Clients themselves: cannot set the permanent flag (they only have the
  heartbeat token, not an admin session)

**Setting the flag (via API):**

```
PATCH /api/clients/<name>
Authorization: (admin session)

{"permanent": true}
```

**Implementation:**

```python
def set_client_permanent(
    client_name: str,
    permanent: bool,
    vault_state: VaultState,
) -> None:
    client = vault_state.clients.get(client_name)
    if client is None:
        raise ValueError(f"Client {client_name!r} not found")
    client["permanent"] = permanent
    if permanent:
        client["expires_at"] = None
    else:
        # Recompute expires_at from current last_heartbeat (or created_at)
        client["expires_at"] = compute_expires_at(
            client["created_at"],
            client.get("last_heartbeat"),
            client["ttl_seconds"],
        )
    # Caller must vault.save() after this
```

---

### 3.6 Heartbeat Flow (Complete)

```
POST /api/heartbeat/<client_name>
Authorization: Bearer <heartbeat_token>

Step 1: Rate limit check
        Clients are not admin sessions, but the heartbeat endpoint should
        still be rate-limited. Use a per-source-IP rate limit: max 10
        requests per minute per IP. Reject with 429 if exceeded.

Step 2: Vault must be unlocked
        If vault is locked: return 503 Service Unavailable
        (Do not return 401 — heartbeat does not use admin credentials)

Step 3: Read vault state (under _vault_write_lock)
        client = vault_state.clients.get(client_name)
        If client is None: return 404 (client unknown or already expired)

Step 4: Verify heartbeat token
        If not verify_heartbeat_token(client_name, token, vault_state):
            audit_log.log("heartbeat_auth_failed", {"client": client_name, "ip": request_ip})
            return 401

Step 5: Check permanent flag
        If client["permanent"] == True:
            -- Accept the heartbeat but don't update expires_at
            audit_log.log("heartbeat_received", {
                "client": client_name, "permanent": True
            })
            return 200

Step 6: Update heartbeat fields
        now = datetime.datetime.now(datetime.timezone.utc)
        client["last_heartbeat"] = now.isoformat()
        client["expires_at"] = compute_expires_at(
            client["created_at"],
            client["last_heartbeat"],
            client["ttl_seconds"],
        )

Step 7: Save vault (under _vault_write_lock)
        vault.save(vault_state, _session["passphrase"])

Step 8: Audit
        audit_log.log("heartbeat_received", {
            "client":      client_name,
            "new_expires": client["expires_at"],
        })
        return 200
```

---

### 3.7 Audit Events

All audit events use the existing `AuditLog.log()` interface (no schema changes
needed). Secret fields are automatically scrubbed by `_scrub_secrets()`.

| Event | `action` string | Key metadata fields | Trigger |
|---|---|---|---|
| Client created | `add_client` | `client_name`, `assigned_ip`, `ttl_seconds`, `permanent` | New client provisioned |
| Client removed (manual) | `remove_client` | `client_name`, `removed_by` | Admin removes client |
| Client expired (TTL) | `client_expired` | `client_name`, `expired_at`, `ttl_seconds` | Background expiry thread |
| Heartbeat received | `heartbeat_received` | `client_name`, `new_expires_at`, `permanent` | Valid heartbeat POST |
| Heartbeat auth failed | `heartbeat_auth_failed` | `client_name`, `source_ip` | Invalid/missing token |
| Client made permanent | `client_set_permanent` | `client_name`, `set_by`, `permanent` (true/false) | Admin changes flag |
| Admin added | `add_admin` | `added_by_name`, `new_admin_name`, `role` | add-admin command |
| Admin removed | `remove_admin` | `removed_by_name`, `removed_admin_name`, `role` | remove-admin command |
| Admin passphrase changed | `change_passphrase` | `changed_by_name`, `target_admin_name` | change-passphrase |
| TOTP enrolled | `totp_enrolled` | `admin_name`, `enrolled_by` | TOTP setup |
| TOTP disabled | `totp_disabled` | `admin_name`, `disabled_by` | TOTP teardown |
| Backup code used | `backup_code_used` | `admin_name` | Successful backup code verification |
| Vault migrated | `vault_migrated` | `schema_from`, `schema_to`, `slot_count` | schema_version migration |
| Expiry check error | `expiry_check_error` | `error` | Background thread exception |

**Scrubbing note:** `client_name` and `admin_name` are not considered secrets
and appear in plaintext. WireGuard public keys (`public_key`) must be scrubbed
via `_scrub_secrets`. The heartbeat token is NEVER included in any audit entry.

---

<a name="cross-cutting-risks"></a>
## Cross-Cutting Security Risks

This section consolidates all flagged risks from the three specs.

| ID | Severity | Location | Description | Mitigation |
|---|---|---|---|---|
| RISK-01 | Low | Spec 1 §1.6 | Timing side-channel: unlock time reveals number of admin slots | Accept as known; optionally pad with dummy Argon2 computations |
| RISK-02 | CRITICAL | Spec 1 §1.7 | Outer binary envelope keyed to caller's passphrase, not master key. Multi-admin unlock will fail for non-saving admins. | MUST refactor _encrypt_vault/_decrypt_vault to accept master_key directly. This is blocking for multi-admin. |
| RISK-03 | Low | Spec 2 §2.5 | TOTP prompt reveals passphrase is correct | Acceptable by design; document as known behavior |
| RISK-04 | Medium | Spec 2 §2.7 | TOTP secret stored in vault — compromise of vault + one passphrase defeats both factors | Unavoidable without HSM; TOTP protects against passphrase-only leaks |
| RISK-05 | Medium | Spec 3 §3.2 | Heartbeat token interception allows indefinite TTL extension without WireGuard key | Token only controls TTL, not VPN access; bind heartbeat to WireGuard interface to require active tunnel |
| RISK-06 | High | Spec 3 §3.2 | Heartbeat endpoint must be reachable by VPN clients but API is bound to localhost | MUST bind heartbeat to WireGuard interface IP; document required firewall configuration |

**RISK-02 is a blocking architectural issue.** Multi-admin support cannot
function correctly without first resolving this. The fix is described in
Spec 1 §1.7. Implement this before any other Phase 7 feature.

---

## Implementation Order (Revised)

Given the dependencies identified above, implement in this order:

1. **Vault I/O refactor (prerequisite):** Modify `_encrypt_vault` and
   `_decrypt_vault` to accept a 32-byte `master_key` instead of a passphrase.
   The outer binary envelope is keyed from the master key, not from any admin's
   passphrase. The existing 76-byte FORMAT_VERSION 2 binary header can be
   reused with Argon2 parameters set to sentinel values (e.g., zeros) since
   the KDF is no longer used for the outer envelope. Alternatively, introduce
   FORMAT_VERSION 3 with a simplified binary header (magic, version, nonces,
   no Argon2 fields). This decision affects the migration path.

2. **Spec 1 full implementation:** New vault schema, keyslot operations,
   migration.

3. **Spec 2 full implementation:** TOTP enrollment, verification, backup codes.

4. **Spec 3 full implementation:** TTL metadata, heartbeat endpoint, background
   expiry thread.

---

*End of WireSeal Phase 7 Cryptographic Security Specification.*
