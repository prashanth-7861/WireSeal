"""Platform detection factory for WireSeal.

Provides:
  get_platform_info()  -- Diagnostic dict with OS, version, and machine info.
  get_adapter()        -- Factory that auto-selects the correct platform adapter.

Platform adapters are imported lazily so that platform-specific stdlib modules
(e.g., winreg on Windows) are never imported on other operating systems.
"""

from __future__ import annotations

import platform
import sys

from .base import AbstractPlatformAdapter
from .exceptions import UnsupportedPlatformError


def get_platform_info() -> dict[str, str]:
    """Return a diagnostic dict describing the current OS environment.

    Used for logging and error reporting -- never used for branching logic
    (use get_adapter() for that).

    Returns:
        Dict with keys:
          ``os``       -- sys.platform value (e.g., ``"linux"``, ``"darwin"``, ``"win32"``)
          ``version``  -- platform.release() (e.g., ``"6.1.0"``, ``"23.1.0"``, ``"10"``)
          ``machine``  -- platform.machine() (e.g., ``"x86_64"``, ``"arm64"``, ``"AMD64"``)
    """
    return {
        "os": sys.platform,
        "version": platform.release(),
        "machine": platform.machine(),
    }


def get_adapter() -> AbstractPlatformAdapter:
    """Return the correct platform adapter for the current operating system.

    Adapter modules are imported lazily to prevent importing platform-specific
    stdlib (e.g., ``winreg``) on OSes where those modules don't exist.

    Returns:
        An instance of the appropriate AbstractPlatformAdapter subclass.

    Raises:
        UnsupportedPlatformError: If the current OS is not Linux, macOS, or Windows.
    """
    if sys.platform == "linux":
        from .linux import LinuxAdapter  # type: ignore[import]
        return LinuxAdapter()
    if sys.platform == "darwin":
        from .macos import MacOSAdapter  # type: ignore[import]
        return MacOSAdapter()
    if sys.platform == "win32":
        from .windows import WindowsAdapter  # type: ignore[import]
        return WindowsAdapter()
    raise UnsupportedPlatformError(
        f"Unsupported platform: {sys.platform}. "
        "wireseal supports Linux, macOS, and Windows only."
    )
