"""Unit tests for WireGuard key pair generation and PSK generation.

Tests verify:
  - Private key is SecretBytes (never plain str or bytes)
  - Public key is base64-encoded 44-char string decoding to exactly 32 bytes
  - Two keypairs have different public keys
  - PSK is 44-char base64 decoding to 32 bytes
  - Two PSKs differ (statistical randomness check)
  - Private key wipe() completes without error (PyInstaller ctypes regression check)
"""

import base64

import pytest

from wireseal.core.keygen import generate_keypair
from wireseal.core.psk import generate_psk
from wireseal.security.secret_types import SecretBytes


class TestKeypairGeneration:
    """Tests for generate_keypair() function."""

    def test_private_key_is_secretbytes(self):
        """Private key must be a SecretBytes instance (KEYGEN-02)."""
        private_key, _ = generate_keypair()
        assert isinstance(private_key, SecretBytes), (
            f"Expected SecretBytes, got {type(private_key).__name__}"
        )

    def test_public_key_is_bytes(self):
        """Public key is plain bytes (not SecretBytes -- public keys are non-secret)."""
        _, public_key = generate_keypair()
        # Public key should be plain bytes (not SecretBytes) per design decision [01-03]
        assert isinstance(public_key, (bytes, str)), (
            f"Expected bytes or str, got {type(public_key).__name__}"
        )

    def test_public_key_is_valid_base64_44_chars(self):
        """Public key must be exactly 44 base64 characters decoding to 32 bytes."""
        _, public_key = generate_keypair()
        # Normalize to str for length check
        pub_str = public_key.decode("ascii") if isinstance(public_key, bytes) else public_key
        assert len(pub_str) == 44, f"Expected 44 chars, got {len(pub_str)}"

        decoded = base64.b64decode(pub_str)
        assert len(decoded) == 32, f"Expected 32 bytes, got {len(decoded)}"

    def test_two_keypairs_have_different_public_keys(self):
        """Two independently generated keypairs must have different public keys."""
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        assert pub1 != pub2, "Two keypairs have identical public keys -- randomness failure"

    def test_two_keypairs_have_different_private_keys(self):
        """Two independently generated private keys must differ."""
        priv1, _ = generate_keypair()
        priv2, _ = generate_keypair()
        # Use bytes() to extract raw content for comparison
        assert bytes(priv1.expose_secret()) != bytes(priv2.expose_secret()), (
            "Two private keys are identical -- randomness failure"
        )

    def test_key_wipe_does_not_raise(self):
        """Wiping the private key must not raise any exception.

        Catches PyInstaller ctypes regressions (Research open question 1).
        Do NOT assert mlock success.
        """
        private_key, _ = generate_keypair()
        private_key.wipe()  # Must not raise

    def test_private_key_repr_does_not_expose_key(self):
        """repr of private key must not contain the raw base64 key material."""
        private_key, public_key = generate_keypair()
        pub_str = public_key.decode("ascii") if isinstance(public_key, bytes) else public_key
        assert pub_str not in repr(private_key)


class TestPSKGeneration:
    """Tests for generate_psk() function."""

    def test_psk_is_secretbytes(self):
        """PSK must be wrapped in SecretBytes (KEYGEN-03)."""
        psk = generate_psk()
        assert isinstance(psk, SecretBytes), (
            f"Expected SecretBytes, got {type(psk).__name__}"
        )

    def test_psk_is_valid_base64_44_chars(self):
        """PSK must be exactly 44 base64 characters decoding to 32 bytes."""
        psk = generate_psk()
        psk_str = bytes(psk.expose_secret()).decode("ascii")
        assert len(psk_str) == 44, f"Expected 44 chars, got {len(psk_str)}"

        decoded = base64.b64decode(psk_str)
        assert len(decoded) == 32, f"Expected 32 bytes, got {len(decoded)}"

    def test_two_psks_differ(self):
        """Two independently generated PSKs must differ (KEYGEN-03: unique per peer)."""
        psk1 = generate_psk()
        psk2 = generate_psk()
        raw1 = bytes(psk1.expose_secret())
        raw2 = bytes(psk2.expose_secret())
        assert raw1 != raw2, "Two PSKs are identical -- randomness failure"

    def test_psk_wipe_does_not_raise(self):
        """Wiping the PSK must not raise any exception."""
        psk = generate_psk()
        psk.wipe()  # Must not raise

    def test_psk_repr_does_not_expose_key(self):
        """repr of PSK must not contain raw key material."""
        psk = generate_psk()
        assert "SecretBytes(***)" == repr(psk)

    def test_generate_many_psks_all_valid(self):
        """Generate 10 PSKs; all must be valid 44-char base64 decoding to 32 bytes."""
        for _ in range(10):
            psk = generate_psk()
            psk_str = bytes(psk.expose_secret()).decode("ascii")
            assert len(psk_str) == 44
            assert len(base64.b64decode(psk_str)) == 32
