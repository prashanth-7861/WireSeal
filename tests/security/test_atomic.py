"""Unit tests for atomic_write.

Tests verify:
  - Successful write produces correct content at destination
  - No leftover .tmp_wga_* files after successful write
  - If os.fsync raises OSError during write, destination does not exist
  - No leftover temp files on fsync crash
  - Overwriting an existing file replaces it atomically
"""

import pytest

from wireseal.security.atomic import atomic_write


class TestAtomicWriteSuccess:
    """Tests for successful atomic write operations."""

    def test_atomic_write_success(self, tmp_path):
        """Write data to dest; dest contains the correct bytes, no temp files remain."""
        dest = tmp_path / "output.conf"
        atomic_write(dest, b"hello")
        assert dest.read_bytes() == b"hello"

        leftover = list(tmp_path.glob(".tmp_wga_*"))
        assert leftover == [], f"Leftover temp files: {leftover}"

    def test_atomic_write_binary_content(self, tmp_path):
        """Write arbitrary binary content (including null bytes)."""
        dest = tmp_path / "binary.bin"
        data = bytes(range(256))
        atomic_write(dest, data)
        assert dest.read_bytes() == data

    def test_atomic_write_empty_content(self, tmp_path):
        """Writing empty bytes creates an empty file at the destination."""
        dest = tmp_path / "empty.conf"
        atomic_write(dest, b"")
        assert dest.exists()
        assert dest.read_bytes() == b""

    def test_atomic_write_overwrites_existing(self, tmp_path):
        """Writing to an existing path replaces the content."""
        dest = tmp_path / "config.conf"
        atomic_write(dest, b"version-1")
        atomic_write(dest, b"version-2")
        assert dest.read_bytes() == b"version-2"

        leftover = list(tmp_path.glob(".tmp_wga_*"))
        assert leftover == [], f"Leftover temp files: {leftover}"

    def test_atomic_write_no_leftover_temp_files_on_success(self, tmp_path):
        """After a successful write, no .tmp_wga_* files remain anywhere."""
        for i in range(5):
            dest = tmp_path / f"file{i}.conf"
            atomic_write(dest, f"content-{i}".encode())

        leftover = list(tmp_path.glob(".tmp_wga_*"))
        assert leftover == [], f"Leftover temp files after multiple writes: {leftover}"


class TestAtomicWriteCrashSafety:
    """Tests that os.fsync crash leaves no partial or final file."""

    def test_atomic_write_no_partial_on_fsync_crash(self, tmp_path, mocker):
        """If os.fsync raises OSError, dest must not exist and no temp files remain."""
        dest = tmp_path / "safe.conf"
        mocker.patch("os.fsync", side_effect=OSError("disk full"))

        with pytest.raises(OSError):
            atomic_write(dest, b"hello")

        # Destination must not exist
        assert not dest.exists(), "Destination file exists after fsync crash"

        # No leftover temp files
        leftover = list(tmp_path.glob(".tmp_wga_*"))
        assert leftover == [], f"Leftover temp files after crash: {leftover}"

    def test_atomic_write_no_partial_on_write_error(self, tmp_path, mocker):
        """If os.write raises OSError, dest must not exist and no temp files remain."""
        dest = tmp_path / "safe2.conf"
        mocker.patch("os.write", side_effect=OSError("no space left on device"))

        with pytest.raises(OSError):
            atomic_write(dest, b"hello")

        assert not dest.exists()
        leftover = list(tmp_path.glob(".tmp_wga_*"))
        assert leftover == [], f"Leftover temp files: {leftover}"
