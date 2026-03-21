"""Abstract platform adapter base class for WireSeal.

All platform-specific implementations (Linux, macOS, Windows) must subclass
AbstractPlatformAdapter and implement all 12 abstract methods. Missing method
implementations cause TypeError at instantiation time, not at the call site --
this is enforced by the ABC metaclass.

FW-03: validate_firewall_rules is exposed as a concrete method on the adapter
so all subclasses inherit it without reimplementing it.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from pathlib import Path

from .exceptions import FirewallValidationError


# ---------------------------------------------------------------------------
# Module-level helper (also exposed as a concrete adapter method via delegation)
# ---------------------------------------------------------------------------


def validate_firewall_rules(generated: str, template: str) -> None:
    """Validate that generated firewall rules match a deny-by-default template.

    Normalization applied before comparison:
      - Strip leading/trailing whitespace from each line
      - Remove blank lines
      - Remove comment lines (lines starting with ``#`` after stripping)

    Args:
        generated: The firewall rule string produced by the adapter.
        template:  The canonical deny-by-default template to compare against.

    Raises:
        FirewallValidationError: If the normalized strings differ.

    Satisfies FW-03.
    """

    def _normalize(text: str) -> str:
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
        return "\n".join(lines)

    norm_generated = _normalize(generated)
    norm_template = _normalize(template)

    if norm_generated != norm_template:
        raise FirewallValidationError(
            "Generated firewall rules do not match the deny-by-default template.\n"
            f"Expected:\n{norm_template}\n\nGot:\n{norm_generated}"
        )


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class AbstractPlatformAdapter(ABC):
    """Contract for all platform-specific wireseal adapters.

    Subclasses MUST implement all 12 abstract methods or Python's ABC
    metaclass will raise TypeError when the subclass is instantiated.

    Privilege check (check_privileges) is always called BEFORE any vault
    interaction, per the locked security decision.
    """

    # ------------------------------------------------------------------
    # 1. Privilege check
    # ------------------------------------------------------------------

    @abstractmethod
    def check_privileges(self) -> None:
        """Raise PrivilegeError if wireseal is not running as root/Administrator.

        Per locked decision: called at startup, BEFORE vault interaction.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 2. Prerequisite check
    # ------------------------------------------------------------------

    @abstractmethod
    def check_prerequisites(self) -> list[str]:
        """Return the list of missing required tools.

        Raises PrerequisiteError with exact install commands if any tool is
        missing (e.g., ``"Run: apt install wireguard nftables"``).

        Returns:
            List of missing tool names (empty list means all present).
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 3. WireGuard installation
    # ------------------------------------------------------------------

    @abstractmethod
    def install_wireguard(self) -> None:
        """Install WireGuard via the platform's package manager."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 4. Config deployment
    # ------------------------------------------------------------------

    @abstractmethod
    def deploy_config(self, config_content: str, interface: str = "wg0") -> Path:
        """Write a WireGuard config file to the platform-canonical path.

        Delegates permission setting to ``security.permissions.set_file_permissions``
        and uses ``security.atomic.atomic_write`` for safe write.

        Args:
            config_content: The WireGuard INI configuration as a string.
            interface:      Name of the WireGuard interface (default ``wg0``).

        Returns:
            The Path where the config was written.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 5 & 6. Firewall management
    # ------------------------------------------------------------------

    @abstractmethod
    def apply_firewall_rules(
        self, wg_port: int, wg_interface: str, subnet: str
    ) -> None:
        """Apply deny-by-default + rate-limited UDP + NAT masquerade rules.

        Per locked decision: applied separately, NOT via PostUp/PostDown in
        the WireGuard config.

        Args:
            wg_port:       UDP port WireGuard listens on.
            wg_interface:  WireGuard interface name (e.g., ``wg0``).
            subnet:        WireGuard subnet in CIDR notation (e.g., ``10.0.0.0/24``).
        """
        raise NotImplementedError

    @abstractmethod
    def remove_firewall_rules(self, wg_interface: str) -> None:
        """Remove all WireGuard-related firewall rules.

        Args:
            wg_interface: WireGuard interface name (e.g., ``wg0``).
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 7. IP forwarding
    # ------------------------------------------------------------------

    @abstractmethod
    def enable_ip_forwarding(self) -> None:
        """Enable IPv4 packet forwarding persistently across reboots."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 8 & 9. Tunnel service lifecycle
    # ------------------------------------------------------------------

    @abstractmethod
    def enable_tunnel_service(self, interface: str = "wg0") -> None:
        """Enable and start the WireGuard tunnel service.

        Args:
            interface: WireGuard interface name (default ``wg0``).
        """
        raise NotImplementedError

    @abstractmethod
    def disable_tunnel_service(self, interface: str = "wg0") -> None:
        """Disable and stop the WireGuard tunnel service.

        Args:
            interface: WireGuard interface name (default ``wg0``).
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 10. DNS updater scheduling
    # ------------------------------------------------------------------

    @abstractmethod
    def setup_dns_updater(
        self, script_path: Path, interval_minutes: int = 5
    ) -> None:
        """Schedule DuckDNS updates to run as a non-root user (satisfies HARD-04).

        Args:
            script_path:       Path to the DuckDNS update script.
            interval_minutes:  How often to run the update (default every 5 min).
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 11. Config path resolution
    # ------------------------------------------------------------------

    @abstractmethod
    def get_config_path(self, interface: str = "wg0") -> Path:
        """Return the platform-canonical path for the WireGuard config file.

        Args:
            interface: WireGuard interface name (default ``wg0``).

        Returns:
            Absolute path where the config should be written.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 12. Outbound interface detection
    # ------------------------------------------------------------------

    @abstractmethod
    def detect_outbound_interface(self) -> str:
        """Return the name of the default outbound network interface.

        Returns:
            Interface name string (e.g., ``"eth0"``, ``"ens3"``, ``"Ethernet"``).
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Concrete helper (inherited by all subclasses)
    # ------------------------------------------------------------------

    def validate_firewall_rules(self, generated: str, template: str) -> None:
        """Validate generated firewall rules against the deny-by-default template.

        Delegates to the module-level :func:`validate_firewall_rules` function.
        Concrete so subclasses inherit it without reimplementing it (FW-03).

        Args:
            generated: The rule string produced by the adapter.
            template:  The canonical deny-by-default template.

        Raises:
            FirewallValidationError: If the normalized strings differ.
        """
        validate_firewall_rules(generated, template)
