"""Platform adapter package for wg-automate.

Public API:
  get_adapter()          -- Factory: returns the correct AbstractPlatformAdapter subclass
  get_platform_info()    -- Returns dict with os/version/machine for diagnostics
  AbstractPlatformAdapter -- ABC that all platform implementations must subclass
  Progress               -- Step progress reporter with locked output format
  Exception classes      -- PlatformError, PrivilegeError, UnsupportedPlatformError,
                            PrerequisiteError, FirewallValidationError, SetupError
"""

from .exceptions import (
    PlatformError,
    PrivilegeError,
    UnsupportedPlatformError,
    PrerequisiteError,
    FirewallValidationError,
    SetupError,
)
from .progress import Progress


def __getattr__(name: str):  # type: ignore[return]
    """Lazy imports for symbols that depend on base.py and detect.py (added in Task 2)."""
    if name == "get_adapter":
        from .detect import get_adapter
        return get_adapter
    if name == "get_platform_info":
        from .detect import get_platform_info
        return get_platform_info
    if name == "AbstractPlatformAdapter":
        from .base import AbstractPlatformAdapter
        return AbstractPlatformAdapter
    raise AttributeError(f"module 'wg_automate.platform' has no attribute {name!r}")


__all__ = [
    "get_adapter",
    "get_platform_info",
    "AbstractPlatformAdapter",
    "Progress",
    "PlatformError",
    "PrivilegeError",
    "UnsupportedPlatformError",
    "PrerequisiteError",
    "FirewallValidationError",
    "SetupError",
]
