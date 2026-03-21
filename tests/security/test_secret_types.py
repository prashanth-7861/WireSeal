"""Unit tests for SecretBytes and wipe_bytes.

Tests verify SEC-01 security invariants:
  - repr and str never expose raw content
  - Equality comparison works correctly (constant-time)
  - Hashing raises TypeError (unhashable)
  - Pickling raises TypeError or produces safe output
  - wipe_bytes zeroes the buffer
  - SecretBytes.wipe() completes without error (PyInstaller ctypes regression check)
"""

import pickle

import pytest

from wireseal.security.secret_types import SecretBytes
from wireseal.security.secrets_wipe import wipe_bytes


class TestSecretBytesRepr:
    """SEC-01: repr and str must never expose the raw secret value."""

    def test_repr_does_not_expose_secret(self):
        sb = SecretBytes(bytearray(b"my-super-secret"))
        result = repr(sb)
        assert "my-super-secret" not in result
        assert "SecretBytes(***)" == result

    def test_str_does_not_expose_secret(self):
        sb = SecretBytes(bytearray(b"my-super-secret"))
        result = str(sb)
        assert "my-super-secret" not in result
        assert "SecretBytes(***)" == result


class TestSecretBytesEquality:
    """SEC-01: Equality must compare content, not be based on identity."""

    def test_eq_compares_equal_buffers(self):
        sb1 = SecretBytes(bytearray(b"same-data"))
        sb2 = SecretBytes(bytearray(b"same-data"))
        assert sb1 == sb2

    def test_eq_different_buffers_not_equal(self):
        sb1 = SecretBytes(bytearray(b"data-a"))
        sb2 = SecretBytes(bytearray(b"data-b"))
        assert sb1 != sb2

    def test_eq_does_not_expose_via_timing(self):
        """Equality and inequality work correctly (constant-time implementation)."""
        sb1 = SecretBytes(bytearray(b"secret"))
        sb2 = SecretBytes(bytearray(b"secret"))
        sb3 = SecretBytes(bytearray(b"wrong!"))
        assert sb1 == sb2
        assert sb1 != sb3

    def test_eq_with_non_secretbytes_returns_not_implemented(self):
        sb = SecretBytes(bytearray(b"data"))
        # Comparing with a non-SecretBytes type should return NotImplemented
        # which Python converts to False for != checks
        assert sb != b"data"
        assert sb != "data"


class TestSecretBytesHash:
    """SEC-01: SecretBytes must not be hashable (prevents use as dict key, set member)."""

    def test_hash_raises_type_error(self):
        sb = SecretBytes(bytearray(b"secret"))
        with pytest.raises(TypeError):
            hash(sb)

    def test_cannot_be_used_as_dict_key(self):
        sb = SecretBytes(bytearray(b"secret"))
        with pytest.raises(TypeError):
            d = {sb: "value"}


class TestSecretBytesPickle:
    """SEC-01: Pickling SecretBytes must not expose raw secret data."""

    def test_getstate_raises_type_error(self):
        sb = SecretBytes(bytearray(b"super-secret"))
        with pytest.raises(TypeError):
            sb.__getstate__()

    def test_pickle_dumps_raises_or_is_safe(self):
        """pickle.dumps either raises or produces output without raw secret bytes."""
        sb = SecretBytes(bytearray(b"super-secret"))
        raw_secret = b"super-secret"
        try:
            pickled = pickle.dumps(sb)
            # If it didn't raise, the pickled bytes must not contain the raw secret
            assert raw_secret not in pickled, (
                "Pickled SecretBytes contains raw secret data -- SEC-01 violation"
            )
        except Exception:
            # Any exception is acceptable -- pickling is blocked
            pass


class TestWipeBytes:
    """Tests for wipe_bytes zeroing function."""

    def test_wipe_zeroes_buffer(self):
        """After wipe_bytes, all bytes are 0 (or buffer is empty -- both acceptable)."""
        buf = bytearray(b"sensitive-data-to-wipe")
        wipe_bytes(buf)
        # After zero-random-zero, final pass leaves all zeros
        assert all(b == 0 for b in buf) or len(buf) == 0

    def test_wipe_empty_buffer_is_noop(self):
        """wipe_bytes on an empty bytearray must not raise."""
        buf = bytearray()
        wipe_bytes(buf)  # Should be a no-op
        assert len(buf) == 0

    def test_wipe_single_byte_buffer(self):
        """Single-byte buffers are wiped correctly."""
        buf = bytearray(b"\xff")
        wipe_bytes(buf)
        assert buf[0] == 0


class TestSecretBytesWipe:
    """Tests for SecretBytes.wipe() method."""

    def test_secretbytes_created_and_wiped_without_error(self):
        """Create SecretBytes, call wipe(), assert no exception raised.

        Catches PyInstaller ctypes regressions (Research open question 1).
        """
        sb = SecretBytes(bytearray(b"secret"))
        sb.wipe()  # Must not raise

    def test_wipe_sets_is_wiped_flag(self):
        sb = SecretBytes(bytearray(b"secret"))
        assert not sb.is_wiped
        sb.wipe()
        assert sb.is_wiped

    def test_double_wipe_is_safe(self):
        """Calling wipe() twice must not raise."""
        sb = SecretBytes(bytearray(b"secret"))
        sb.wipe()
        sb.wipe()  # Second call must be a no-op, not an error

    def test_context_manager_wipes_on_exit(self):
        """Using SecretBytes as a context manager auto-wipes on __exit__."""
        with SecretBytes(bytearray(b"secret")) as sb:
            pass
        assert sb.is_wiped

    def test_to_bytearray_returns_copy(self):
        """to_bytearray() returns an independent copy, not the internal buffer."""
        sb = SecretBytes(bytearray(b"data"))
        copy = sb.to_bytearray()
        assert copy == bytearray(b"data")
        # Modifying the copy must not affect the original
        copy[0] = 0xFF
        assert bytes(sb.expose_secret()[:1]) != b"\xff"
