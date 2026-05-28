"""Tests for platform detection and adapter factory.

Verifies:
  - get_platform_info returns correct dict structure
  - get_adapter returns the correct platform adapter
  - UnsupportedPlatformError for unknown platforms
"""

import sys

import pytest

from wireseal.platform.detect import get_adapter, get_platform_info
from wireseal.platform.exceptions import UnsupportedPlatformError


class TestGetPlatformInfo:
    """get_platform_info returns a diagnostic dict."""

    def test_returns_dict_with_expected_keys(self):
        """The returned dict must contain os, version, and machine keys."""
        info = get_platform_info()
        assert isinstance(info, dict)
        assert "os" in info
        assert "version" in info
        assert "machine" in info

    def test_os_key_matches_sys_platform(self):
        """The os value must equal sys.platform."""
        info = get_platform_info()
        assert info["os"] == sys.platform


class TestGetAdapter:
    """get_adapter returns the correct platform adapter."""

    def test_linux_returns_linux_adapter(self, mocker):
        """On linux sys.platform, get_adapter must return LinuxAdapter."""
        mocker.patch.object(sys, "platform", "linux")
        adapter = get_adapter()
        from wireseal.platform.linux import LinuxAdapter
        assert isinstance(adapter, LinuxAdapter)

    def test_darwin_returns_macos_adapter(self, mocker):
        """On darwin sys.platform, get_adapter must return MacOSAdapter."""
        mocker.patch.object(sys, "platform", "darwin")
        adapter = get_adapter()
        from wireseal.platform.macos import MacOSAdapter
        assert isinstance(adapter, MacOSAdapter)

    def test_win32_returns_windows_adapter(self, mocker):
        """On win32 sys.platform, get_adapter must return WindowsAdapter."""
        mocker.patch.object(sys, "platform", "win32")
        adapter = get_adapter()
        from wireseal.platform.windows import WindowsAdapter
        assert isinstance(adapter, WindowsAdapter)

    def test_unsupported_platform_raises_error(self, mocker):
        """On an unknown platform, get_adapter must raise UnsupportedPlatformError."""
        mocker.patch.object(sys, "platform", "freebsd")
        with pytest.raises(UnsupportedPlatformError):
            get_adapter()

    def test_unsupported_platform_message_includes_platform_name(self, mocker):
        """The error message must include the unsupported platform name."""
        mocker.patch.object(sys, "platform", "solaris")
        with pytest.raises(UnsupportedPlatformError) as exc:
            get_adapter()
        assert "solaris" in str(exc.value)

    def test_adapter_implements_abstract_methods(self, mocker):
        """The returned adapter must be a proper AbstractPlatformAdapter subclass
        (all abstract methods implemented)."""
        mocker.patch.object(sys, "platform", "linux")
        adapter = get_adapter()
        from wireseal.platform.base import AbstractPlatformAdapter
        assert isinstance(adapter, AbstractPlatformAdapter)
        # geteuid may not exist on non-POSIX — create the attribute with create=True
        mocker.patch("wireseal.platform.linux.os.geteuid", return_value=0, create=True)
        adapter.check_privileges()
