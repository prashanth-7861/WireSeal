"""Platform-specific exception hierarchy for WireSeal.

All platform adapter errors subclass PlatformError so callers can catch
the broad category or a specific subclass as needed.
"""

import sys


class PlatformError(Exception):
    """Base exception for all platform adapter errors."""


class PrivilegeError(PlatformError):
    """Raised when wireseal is not running as root/Administrator.

    Per locked decision: called at startup, BEFORE vault interaction.
    Message format is locked -- do not alter without updating all callers.
    """

    def __init__(self, message: str | None = None) -> None:
        if message is None:
            if sys.platform == "win32":
                message = (
                    "wireseal requires root/Administrator privileges. "
                    "Re-run from an elevated command prompt (Run as Administrator)"
                )
            else:
                message = (
                    "wireseal requires root/Administrator privileges. "
                    "Re-run with: sudo wireseal"
                )
        super().__init__(message)


class UnsupportedPlatformError(PlatformError):
    """Raised when the current OS is not supported by WireSeal."""


class PrerequisiteError(PlatformError):
    """Raised when required tools (wireguard, nftables, etc.) are missing.

    Per locked decision: message must include exact install command, e.g.:
      "Run: apt install wireguard nftables"
    """


class FirewallValidationError(PlatformError):
    """Raised when generated firewall rules do not match the deny-by-default template.

    Satisfies FW-03: applied rules are validated against canonical template
    before they take effect.
    """


class SetupError(PlatformError):
    """Raised on a generic setup step failure not covered by a more specific exception."""
