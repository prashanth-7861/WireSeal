"""Platform adapter package for wg-automate.

Public API:
  get_adapter()          -- Factory: returns the correct AbstractPlatformAdapter subclass
  get_platform_info()    -- Returns dict with os/version/machine for diagnostics
  AbstractPlatformAdapter -- ABC that all platform implementations must subclass
  Progress               -- Step progress reporter with locked output format
  Exception classes      -- PlatformError, PrivilegeError, UnsupportedPlatformError,
                            PrerequisiteError, FirewallValidationError, SetupError
"""

from .detect import get_adapter, get_platform_info
from .base import AbstractPlatformAdapter
from .progress import Progress
from .exceptions import (
    PlatformError,
    PrivilegeError,
    UnsupportedPlatformError,
    PrerequisiteError,
    FirewallValidationError,
    SetupError,
)

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
