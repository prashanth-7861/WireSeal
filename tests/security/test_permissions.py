"""Unit tests for cross-platform file and directory permission enforcement.

Tests verify:
  - Unix: os.chmod called with 0o600 for files, 0o700 for directories
  - Windows: subprocess.run invoked with icacls command
  - Unix: subprocess.run NOT called on linux/darwin platforms

All tests mock os.chmod and subprocess.run -- never call real chmod or icacls.
"""

import sys
from pathlib import Path
from unittest.mock import call

import pytest

from wg_automate.security import permissions as perm_module
from wg_automate.security.permissions import (
    check_file_permissions,
    set_dir_permissions,
    set_file_permissions,
)


class TestUnixFilePermissions:
    """set_file_permissions on Unix (linux/darwin) calls os.chmod with mode 0o600."""

    def test_unix_permissions_calls_chmod_600(self, tmp_path, mocker):
        """On non-win32 platform, os.chmod is called with 0o600."""
        mocker.patch.object(perm_module.sys, "platform", "linux")
        mock_chmod = mocker.patch("wg_automate.security.permissions.os.chmod")

        test_file = tmp_path / "test.conf"
        test_file.write_bytes(b"config")
        set_file_permissions(test_file)

        mock_chmod.assert_called_once_with(test_file, 0o600)

    def test_unix_permissions_respects_custom_mode(self, tmp_path, mocker):
        """Custom mode is passed through to os.chmod."""
        mocker.patch.object(perm_module.sys, "platform", "linux")
        mock_chmod = mocker.patch("wg_automate.security.permissions.os.chmod")

        test_file = tmp_path / "test.conf"
        test_file.write_bytes(b"config")
        set_file_permissions(test_file, mode=0o400)

        mock_chmod.assert_called_once_with(test_file, 0o400)

    def test_unix_does_not_call_icacls_on_linux(self, tmp_path, mocker):
        """On linux, subprocess.run must NOT be called for set_file_permissions."""
        mocker.patch.object(perm_module.sys, "platform", "linux")
        mocker.patch("wg_automate.security.permissions.os.chmod")
        mock_subprocess = mocker.patch("wg_automate.security.permissions.subprocess.run")

        test_file = tmp_path / "test.conf"
        test_file.write_bytes(b"config")
        set_file_permissions(test_file)

        mock_subprocess.assert_not_called()

    def test_unix_does_not_call_icacls_on_darwin(self, tmp_path, mocker):
        """On darwin, subprocess.run must NOT be called for set_file_permissions."""
        mocker.patch.object(perm_module.sys, "platform", "darwin")
        mocker.patch("wg_automate.security.permissions.os.chmod")
        mock_subprocess = mocker.patch("wg_automate.security.permissions.subprocess.run")

        test_file = tmp_path / "test.conf"
        test_file.write_bytes(b"config")
        set_file_permissions(test_file)

        mock_subprocess.assert_not_called()


class TestUnixDirPermissions:
    """set_dir_permissions on Unix calls os.chmod with mode 0o700."""

    def test_unix_dir_permissions_calls_chmod_700(self, tmp_path, mocker):
        """On non-win32 platform, os.chmod is called with 0o700 for directories."""
        mocker.patch.object(perm_module.sys, "platform", "linux")
        mock_chmod = mocker.patch("wg_automate.security.permissions.os.chmod")

        set_dir_permissions(tmp_path)

        mock_chmod.assert_called_once_with(tmp_path, 0o700)


class TestWindowsFilePermissions:
    """set_file_permissions on Windows delegates to icacls via subprocess.run."""

    def test_windows_delegates_to_icacls(self, tmp_path, mocker):
        """On win32, subprocess.run is called with icacls arguments."""
        mocker.patch.object(perm_module.sys, "platform", "win32")
        mock_subprocess = mocker.patch("wg_automate.security.permissions.subprocess.run")

        test_file = tmp_path / "test.conf"
        test_file.write_bytes(b"config")
        set_file_permissions(test_file)

        # subprocess.run must be called with icacls
        assert mock_subprocess.called
        call_args = mock_subprocess.call_args
        cmd = call_args[0][0]  # First positional argument is the command list
        assert "icacls" in cmd

    def test_windows_icacls_includes_path(self, tmp_path, mocker):
        """On win32, icacls command includes the file path."""
        mocker.patch.object(perm_module.sys, "platform", "win32")
        mock_subprocess = mocker.patch("wg_automate.security.permissions.subprocess.run")

        test_file = tmp_path / "secret.conf"
        test_file.write_bytes(b"config")
        set_file_permissions(test_file)

        cmd = mock_subprocess.call_args[0][0]
        assert str(test_file) in cmd

    def test_windows_icacls_restricts_to_system_and_admins(self, tmp_path, mocker):
        """On win32, icacls grants SYSTEM and Administrators permissions."""
        mocker.patch.object(perm_module.sys, "platform", "win32")
        mock_subprocess = mocker.patch("wg_automate.security.permissions.subprocess.run")

        test_file = tmp_path / "secret.conf"
        test_file.write_bytes(b"config")
        set_file_permissions(test_file)

        cmd = mock_subprocess.call_args[0][0]
        cmd_str = " ".join(str(c) for c in cmd)
        assert "SYSTEM" in cmd_str
        assert "Administrators" in cmd_str

    def test_windows_does_not_call_chmod(self, tmp_path, mocker):
        """On win32, os.chmod must NOT be called."""
        mocker.patch.object(perm_module.sys, "platform", "win32")
        mocker.patch("wg_automate.security.permissions.subprocess.run")
        mock_chmod = mocker.patch("wg_automate.security.permissions.os.chmod")

        test_file = tmp_path / "test.conf"
        test_file.write_bytes(b"config")
        set_file_permissions(test_file)

        mock_chmod.assert_not_called()
