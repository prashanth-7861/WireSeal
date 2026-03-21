"""Unit tests for config integrity tracking.

Tests verify:
  - compute_config_hash returns a 64-char lowercase hex SHA-256 digest
  - The digest matches hashlib.sha256(content).hexdigest()
  - verify_config_integrity returns True for unchanged file
  - verify_config_integrity returns False after file is modified
  - verify_config_integrity returns False for a wrong stored hash
"""

import hashlib

import pytest

from wireseal.security.integrity import compute_config_hash, verify_config_integrity


class TestComputeConfigHash:
    """Tests for compute_config_hash function."""

    def test_compute_hash_is_sha256_hex(self, tmp_path):
        """Hash must be a 64-character lowercase hex string."""
        config_file = tmp_path / "wg0.conf"
        config_file.write_bytes(b"[Interface]\nPrivateKey = abc\n")
        result = compute_config_hash(config_file)
        assert isinstance(result, str)
        assert len(result) == 64
        assert result == result.lower()
        assert all(c in "0123456789abcdef" for c in result)

    def test_compute_hash_matches_hashlib_sha256(self, tmp_path):
        """Hash must exactly match hashlib.sha256(content).hexdigest()."""
        content = b"[Interface]\nPrivateKey = secret\nListenPort = 51820\n"
        config_file = tmp_path / "wg0.conf"
        config_file.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        actual = compute_config_hash(config_file)
        assert actual == expected

    def test_compute_hash_is_deterministic(self, tmp_path):
        """Same file content produces the same hash on repeated calls."""
        content = b"deterministic content"
        config_file = tmp_path / "wg0.conf"
        config_file.write_bytes(content)

        hash1 = compute_config_hash(config_file)
        hash2 = compute_config_hash(config_file)
        assert hash1 == hash2

    def test_compute_hash_differs_for_different_content(self, tmp_path):
        """Different file contents produce different hashes."""
        file_a = tmp_path / "a.conf"
        file_b = tmp_path / "b.conf"
        file_a.write_bytes(b"content-a")
        file_b.write_bytes(b"content-b")

        assert compute_config_hash(file_a) != compute_config_hash(file_b)

    def test_compute_hash_missing_file_raises(self, tmp_path):
        """FileNotFoundError raised if config file does not exist."""
        missing = tmp_path / "nonexistent.conf"
        with pytest.raises(FileNotFoundError):
            compute_config_hash(missing)


class TestVerifyConfigIntegrity:
    """Tests for verify_config_integrity function."""

    def test_verify_returns_true_for_unchanged_file(self, tmp_path):
        """Verifying immediately after hashing must return True."""
        config_file = tmp_path / "wg0.conf"
        config_file.write_bytes(b"[Interface]\nListenPort = 51820\n")

        stored_hash = compute_config_hash(config_file)
        result = verify_config_integrity(config_file, stored_hash)
        assert result is True

    def test_verify_returns_false_after_tampering(self, tmp_path):
        """After appending content to the file, verify must return False."""
        config_file = tmp_path / "wg0.conf"
        config_file.write_bytes(b"[Interface]\nListenPort = 51820\n")

        stored_hash = compute_config_hash(config_file)

        # Tamper: append an extra line
        with config_file.open("ab") as f:
            f.write(b"\n# tampered\n")

        result = verify_config_integrity(config_file, stored_hash)
        assert result is False

    def test_verify_returns_false_for_wrong_hash(self, tmp_path):
        """Passing a known-wrong hash must return False."""
        config_file = tmp_path / "wg0.conf"
        config_file.write_bytes(b"correct content")

        wrong_hash = "a" * 64  # 64-char all-'a' hex string
        result = verify_config_integrity(config_file, wrong_hash)
        assert result is False

    def test_verify_returns_false_for_empty_wrong_hash(self, tmp_path):
        """Zero hash string returns False (not True) for any real file."""
        config_file = tmp_path / "wg0.conf"
        config_file.write_bytes(b"some content")

        zero_hash = "0" * 64
        result = verify_config_integrity(config_file, zero_hash)
        assert result is False

    def test_verify_empty_file(self, tmp_path):
        """Empty file has a valid SHA-256 hash that verifies correctly."""
        config_file = tmp_path / "empty.conf"
        config_file.write_bytes(b"")

        stored_hash = compute_config_hash(config_file)
        assert verify_config_integrity(config_file, stored_hash) is True

    def test_verify_missing_file_raises(self, tmp_path):
        """FileNotFoundError raised if config file does not exist during verify."""
        missing = tmp_path / "nonexistent.conf"
        fake_hash = "a" * 64
        with pytest.raises(FileNotFoundError):
            verify_config_integrity(missing, fake_hash)
