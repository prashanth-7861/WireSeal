"""Unit tests for the encrypted Vault.

Tests verify:
  - Round-trip: create then open with same passphrase returns correct schema_version
  - Wrong passphrase raises VaultUnlockError
  - Tampered ciphertext raises VaultUnlockError (GCM tag failure)
  - Bad magic bytes raises VaultTamperedError
  - atomic_write crash (os.fsync raises OSError) leaves no partial file
  - Passphrase change preserves state and old passphrase is rejected

Uses fixtures from conftest.py: vault_path, passphrase, wrong_passphrase,
initial_vault_state.

NOTE: Argon2id with ARGON2_MEMORY_COST_KIB=262144 requires ~256 MiB RAM and takes
several seconds per vault open. Each vault operation in this test suite invokes KDF.
Tests are functional correctness tests, not performance benchmarks.
"""

import os
import pytest

from wireseal.security.exceptions import VaultTamperedError, VaultUnlockError
from wireseal.security.secret_types import SecretBytes
from wireseal.security.vault import Vault, _HEADER_SIZE, _PAYLOAD_HASH_KEY


class TestVaultRoundTrip:
    """Basic create/open round-trip tests."""

    def test_vault_round_trip(self, vault_path, passphrase, initial_vault_state):
        """Create vault, reopen with same passphrase, assert schema_version == 1."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        with vault.open(passphrase) as state:
            assert state._data["schema_version"] == 1

    def test_vault_file_created_at_correct_path(self, vault_path, passphrase, initial_vault_state):
        """After Vault.create(), the vault file must exist at the given path."""
        assert not vault_path.exists()
        Vault.create(vault_path, passphrase, initial_vault_state)
        assert vault_path.exists()

    def test_vault_state_fields_preserved(self, vault_path, passphrase, initial_vault_state):
        """All top-level schema keys are present after round-trip."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        with vault.open(passphrase) as state:
            assert "server" in state._data
            assert "clients" in state._data
            assert "ip_pool" in state._data
            assert "integrity" in state._data


class TestVaultUnlockErrors:
    """Tests that wrong passphrase and tampered ciphertext raise correct exceptions."""

    def test_wrong_passphrase_raises_vault_unlock_error(
        self, vault_path, passphrase, wrong_passphrase, initial_vault_state
    ):
        """Opening with wrong passphrase must raise VaultUnlockError."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        with pytest.raises(VaultUnlockError):
            vault.open(wrong_passphrase)

    def test_tampered_ciphertext_raises_vault_unlock_error(
        self, vault_path, passphrase, initial_vault_state
    ):
        """Flipping a byte in the ciphertext region must raise VaultUnlockError."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        blob = vault_path.read_bytes()
        # Flip a byte past the header (index 51 = header + 4 bytes ct_len field)
        tampered = bytearray(blob)
        tampered[51] ^= 0xFF
        vault_path.write_bytes(bytes(tampered))

        vault = Vault(vault_path)
        with pytest.raises(VaultUnlockError):
            vault.open(passphrase)

    def test_bad_magic_bytes_raises_vault_tampered_error(
        self, vault_path, passphrase, initial_vault_state
    ):
        """Overwriting the magic bytes must raise VaultTamperedError (structural tampering)."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        blob = vault_path.read_bytes()
        tampered = bytearray(blob)
        tampered[:4] = b"XXXX"
        vault_path.write_bytes(bytes(tampered))

        vault = Vault(vault_path)
        with pytest.raises(VaultTamperedError):
            vault.open(passphrase)

    def test_truncated_file_raises(self, vault_path, passphrase, initial_vault_state):
        """A file shorter than the minimum header size raises VaultTamperedError."""
        vault_path.parent.mkdir(parents=True, exist_ok=True)
        vault_path.write_bytes(b"WGAV" + b"\x00" * 10)  # Too short to be valid

        vault = Vault(vault_path)
        with pytest.raises((VaultTamperedError, VaultUnlockError)):
            vault.open(passphrase)


class TestVaultAtomicWrite:
    """Tests that atomic write crash safety is enforced."""

    def test_atomic_write_leaves_no_partial_on_fsync_crash(
        self, tmp_path, passphrase, initial_vault_state, mocker
    ):
        """If os.fsync raises OSError during Vault.create, no file should remain."""
        vault_path = tmp_path / "vault.enc"
        mocker.patch("os.fsync", side_effect=OSError("disk full"))

        with pytest.raises(OSError):
            Vault.create(vault_path, passphrase, initial_vault_state)

        # Main vault file must not exist
        assert not vault_path.exists()

        # No leftover temp files
        leftover = list(tmp_path.glob(".tmp_wga_*"))
        assert leftover == [], f"Leftover temp files found: {leftover}"


class TestVaultPassphraseChange:
    """Tests for change_passphrase (VAULT-07)."""

    def test_passphrase_change_preserves_state(
        self, vault_path, passphrase, initial_vault_state
    ):
        """After change_passphrase, new passphrase opens vault and data is intact."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        new_passphrase = SecretBytes(bytearray(b"new-passphrase-xyz-abc"))
        vault.change_passphrase(passphrase, new_passphrase)

        with vault.open(new_passphrase) as state:
            assert state._data["schema_version"] == 1

    def test_old_passphrase_rejected_after_change(
        self, vault_path, passphrase, initial_vault_state
    ):
        """After change_passphrase, the old passphrase must raise VaultUnlockError."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        new_passphrase = SecretBytes(bytearray(b"new-passphrase-xyz-abc"))
        vault.change_passphrase(passphrase, new_passphrase)

        with pytest.raises(VaultUnlockError):
            vault.open(passphrase)

    def test_change_passphrase_wrong_old_passphrase_raises(
        self, vault_path, passphrase, wrong_passphrase, initial_vault_state
    ):
        """change_passphrase with wrong old_passphrase must raise VaultUnlockError."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        new_passphrase = SecretBytes(bytearray(b"new-passphrase-xyz"))
        with pytest.raises(VaultUnlockError):
            vault.change_passphrase(wrong_passphrase, new_passphrase)

    def test_change_passphrase_too_short_raises_value_error(
        self, vault_path, passphrase, initial_vault_state
    ):
        """change_passphrase with new passphrase < 12 chars raises ValueError."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        short_passphrase = SecretBytes(bytearray(b"short"))
        with pytest.raises(ValueError, match="12"):
            vault.change_passphrase(passphrase, short_passphrase)


class TestVaultPassphraseMinLength:
    """Tests for VAULT-03 minimum passphrase length enforcement."""

    def test_create_with_short_passphrase_raises_value_error(
        self, vault_path, initial_vault_state
    ):
        """Vault.create with passphrase shorter than 12 chars raises ValueError."""
        short = SecretBytes(bytearray(b"tooshort"))
        with pytest.raises(ValueError, match="12"):
            Vault.create(vault_path, short, initial_vault_state)


class TestVaultPayloadIntegrity:
    """Phase 5.2: SHA-256 payload integrity hash — verifies decrypted payload
    has not been silently corrupted (bit-rot, memory corruption, serialisation
    bugs that AEAD cannot catch because the ciphertext was never touched).
    """

    def test_payload_hash_round_trip(self, vault_path, passphrase, initial_vault_state):
        """Create then open — no error means the hash was added on first save
        and verified on decrypt. The hash is popped after verification so it
        does not appear in the public state."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        with vault.open(passphrase):
            pass  # No exception = hash was added and verified

    def test_payload_hash_verified_on_every_open(self, vault_path, passphrase, initial_vault_state):
        """Opening a vault multiple times must succeed each time — the hash
        is added on first save and verified on every subsequent open."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        for _ in range(3):
            with vault.open(passphrase):
                pass

    def test_payload_hash_survives_save(self, vault_path, passphrase, initial_vault_state):
        """After modifying state and saving, the hash must be updated and
        verified correctly on the next open."""
        Vault.create(vault_path, passphrase, initial_vault_state)
        vault = Vault(vault_path)
        with vault.open(passphrase) as state:
            state._data["server"]["test"] = "value"
            vault.save(state, passphrase)
        with vault.open(passphrase) as state:
            assert state._data["server"]["test"] == "value"

    def test_payload_hash_backward_compat(self, vault_path, passphrase, initial_vault_state, mocker):
        """A vault saved WITHOUT a payload_hash (pre-Phase 5.2) must still
        open successfully — the verification is skipped when the key is absent.
        We intercept _encrypt_payload with a wrapper that skips the hash step."""
        import json
        import os
        from cryptography.hazmat.primitives.ciphers.aead import (
            AESGCMSIV, ChaCha20Poly1305,
        )
        from wireseal.security import vault as vault_mod

        vault_mod.Vault.create(vault_path, passphrase, initial_vault_state)

        def _no_hash_encrypt(plaintext_dict, master_key, salt, nonce1, nonce2, header):
            """Encrypt WITHOUT adding payload_hash."""
            kc, ka = vault_mod._derive_subkeys(master_key, salt)
            pt_bytes = json.dumps(plaintext_dict, separators=(",", ":")).encode("utf-8")
            try:
                l1 = ChaCha20Poly1305(bytes(kc)).encrypt(nonce1, pt_bytes, header)
                l2 = AESGCMSIV(bytes(ka)).encrypt(nonce2, l1, header)
            finally:
                vault_mod.wipe_bytes(kc)
                vault_mod.wipe_bytes(ka)
            return l2

        # Open, save again with NO hash
        vault = vault_mod.Vault(vault_path)
        with vault.open(passphrase) as state:
            # Re-save using the no-hash encrypt
            mocker.patch.object(vault_mod, "_encrypt_payload", _no_hash_encrypt)
            vault.save(state, passphrase)

        mocker.stopall()

        # Now open — must succeed (backward compat skips verification when
        # payload_hash is absent).  We verify by checking the blob directly.
        vault2 = vault_mod.Vault(vault_path)
        with vault2.open(passphrase):
            pass  # No exception = backward compat works

    def test_payload_hash_mismatch_detected(self, vault_path, passphrase, mocker):
        """If the payload_hash does not match the decrypted JSON, open must
        raise VaultTamperedError with a clear corruption message.

        We bypass the normal hash computation by monkeypatching
        ``_encrypt_payload`` to use a wrapper that serialises the dict with a
        pre-set wrong hash and encrypts WITHOUT the hash-recomputation step.
        """
        import json
        import os
        from cryptography.hazmat.primitives.ciphers.aead import (
            AESGCMSIV, ChaCha20Poly1305,
        )
        from wireseal.security import vault as vault_mod

        # Create the vault normally first so the file exists
        vault_mod.Vault.create(vault_path, passphrase, {"schema_version":1,"server":{},"clients":{},"ip_pool":{},"integrity":{}})

        def _encrypt_with_wrong_hash(plaintext_dict, master_key, salt, nonce1, nonce2, header):
            """Encrypt without computing a payload_hash — uses whatever is in
            integrity.payload_hash (which we pre-set to a deliberately wrong value)."""
            kc, ka = vault_mod._derive_subkeys(master_key, salt)
            pt_bytes = json.dumps(plaintext_dict, separators=(",", ":")).encode("utf-8")
            try:
                l1 = ChaCha20Poly1305(bytes(kc)).encrypt(nonce1, pt_bytes, header)
                l2 = AESGCMSIV(bytes(ka)).encrypt(nonce2, l1, header)
            finally:
                vault_mod.wipe_bytes(kc)
                vault_mod.wipe_bytes(ka)
            return l2

        mocker.patch.object(vault_mod, "_encrypt_payload", _encrypt_with_wrong_hash)

        # Open vault, inject a wrong hash, then save
        vault = vault_mod.Vault(vault_path)
        with vault.open(passphrase) as state:
            state.integrity[_PAYLOAD_HASH_KEY] = "0" * 64
            vault.save(state, passphrase)

        mocker.stopall()

        # Now open — the hash '0'*64 won't match the actual payload
        vault2 = vault_mod.Vault(vault_path)
        with pytest.raises(VaultTamperedError, match="integrity check failed"):
            vault2.open(passphrase)
