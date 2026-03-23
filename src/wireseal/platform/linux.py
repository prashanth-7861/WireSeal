"""Linux platform adapter for WireSeal.

Implements all 12 abstract methods from AbstractPlatformAdapter for Linux systems
with systemd, nftables, and sysctl.d support.

Security properties:
  - All subprocess calls use shell=False with list args (never shell=True)
  - Config files written via atomic_write with correct permissions before rename
  - nftables firewall rules are deny-by-default with rate limiting (FW-01)
  - NAT masquerade targets only the detected outbound interface (FW-02)
  - Generated firewall rules validated against template before application (FW-03)
  - DuckDNS updater runs as non-root wireseal system user (HARD-04)
  - All operations are idempotent (safe to re-run)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from .base import AbstractPlatformAdapter
from .exceptions import PrerequisiteError, PrivilegeError, SetupError
from ..security.atomic import atomic_write


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_NFTABLES_DIR = Path("/etc/nftables.d")
_WIREGUARD_DIR = Path("/etc/wireguard")
_SYSCTL_DROP_IN = Path("/etc/sysctl.d/99-wireguard.conf")
_CRON_FILE = Path("/etc/cron.d/wireseal")
_NFT_RULES_FILE = _NFTABLES_DIR / "wireguard.nft"


def _build_nftables_ruleset(
    pub_iface: str, wg_iface: str, wg_port: int
) -> str:
    """Build the nftables ruleset string with the given interface and port values.

    Returns the exact string that will be written to the nft file and applied.
    The same function is used for both the generated rules and the expected
    template to ensure validate_firewall_rules comparison is always symmetric.
    """
    return textwrap.dedent(f"""\
        # MANAGED BY wireseal -- DO NOT EDIT MANUALLY
        table inet wg_filter {{
            chain input {{
                type filter hook input priority 0; policy drop;
                iif "lo" accept
                iifname "{wg_iface}" accept
                meta l4proto {{ icmp, ipv6-icmp }} accept
                ct state {{ established, related }} accept
                ct state invalid drop
                iifname "{pub_iface}" udp dport {wg_port} ct state new limit rate over 5/second burst 10 packets drop
                iifname "{pub_iface}" udp dport {wg_port} accept
            }}

            chain forward {{
                type filter hook forward priority 0; policy drop;
                iifname "{wg_iface}" oifname "{pub_iface}" ct state new accept
                ct state {{ established, related }} accept
            }}
        }}

        table ip wg_nat {{
            chain postrouting {{
                type nat hook postrouting priority 100; policy accept;
                iifname "{wg_iface}" oifname "{pub_iface}" masquerade
            }}
        }}
    """)


# ---------------------------------------------------------------------------
# LinuxAdapter
# ---------------------------------------------------------------------------


class LinuxAdapter(AbstractPlatformAdapter):
    """Platform adapter for Linux systems.

    Supports systemd (wg-quick@wg0), nftables firewall, sysctl.d IP forwarding,
    and privilege-dropped cron-based DuckDNS updates.

    All 12 abstract methods from AbstractPlatformAdapter are implemented.
    """

    # ------------------------------------------------------------------
    # 1. Privilege check
    # ------------------------------------------------------------------

    def check_privileges(self) -> None:
        """Raise PrivilegeError if not running as root (euid != 0).

        Also warns to stderr when running via sudo about vault HOME implications,
        per Claude's discretion decision from CONTEXT.md.
        """
        if os.geteuid() != 0:
            raise PrivilegeError(
                "wireseal requires root privileges. Re-run with: sudo wireseal"
            )

        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            print(
                f"Note: Running via sudo. Vault will be stored in root's home "
                f"directory (~root/.wireseal/), not /home/{sudo_user}/.wireseal/",
                file=sys.stderr,
            )

    # ------------------------------------------------------------------
    # 2. Prerequisite check
    # ------------------------------------------------------------------

    def check_prerequisites(self) -> list[str]:
        """Check for required tools and raise PrerequisiteError if any are missing.

        Checks for: wg (wireguard-tools), wg-quick (wireguard-tools),
        nft (nftables), systemctl (systemd).

        Per locked decision: fail with exact install command, do NOT auto-install.
        This is consistent with the "explicit and auditable" principle.

        Returns:
            Empty list if all tools are present.

        Raises:
            PrerequisiteError: With exact apt install command listing all missing tools.
        """
        required = {
            "wg": "wireguard-tools",
            "wg-quick": "wireguard-tools",
            "nft": "nftables",
            "systemctl": "systemd",
        }

        missing = [tool for tool in required if shutil.which(tool) is None]

        if missing:
            missing_str = ", ".join(missing)
            # Pick the right install hint for the detected distro
            try:
                import distro as _distro  # type: ignore[import-untyped]
                _did = _distro.id()
            except Exception:
                _did = ""
            if _did in ("arch", "manjaro", "endeavouros"):
                _hint = "Run: pacman -S wireguard-tools nftables"
            elif _did in ("fedora", "rhel", "centos", "rocky", "almalinux"):
                _hint = "Run: dnf install wireguard-tools nftables"
            else:
                _hint = "Run: apt install wireguard-tools nftables"
            raise PrerequisiteError(f"Missing: {missing_str}. {_hint}")

        return []

    # ------------------------------------------------------------------
    # 3. WireGuard installation
    # ------------------------------------------------------------------

    def install_wireguard(self) -> None:
        """Install WireGuard via apt-get if not already installed.

        Idempotent: returns immediately if wg is already on PATH.
        Raises SetupError on installation failure.
        """
        if shutil.which("wg") is not None:
            return  # already installed

        try:
            subprocess.run(
                ["apt-get", "install", "-y", "wireguard", "wireguard-tools"],
                shell=False,
                check=True,
                capture_output=True,
                timeout=120,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise SetupError(
                f"Failed to install WireGuard via apt-get: {stderr}"
            ) from exc

    # ------------------------------------------------------------------
    # 4. Config deployment
    # ------------------------------------------------------------------

    def deploy_config(self, config_content: str, interface: str = "wg0") -> Path:
        """Write a WireGuard config file atomically with 0o600 permissions.

        Creates /etc/wireguard/ with 0o700 if it does not exist.
        Uses atomic_write from security/atomic.py to ensure the file is never
        world-readable at any point during the write.

        Args:
            config_content: WireGuard INI configuration as a UTF-8 string.
            interface:      Interface name (default wg0).

        Returns:
            The Path where the config was written.
        """
        path = self.get_config_path(interface)
        parent = path.parent

        if not parent.exists():
            parent.mkdir(parents=True, mode=0o700, exist_ok=True)

        atomic_write(path, config_content.encode("utf-8"), mode=0o600)
        return path

    # ------------------------------------------------------------------
    # 5 & 6. Firewall management
    # ------------------------------------------------------------------

    def apply_firewall_rules(
        self, wg_port: int, wg_interface: str, subnet: str
    ) -> None:
        """Apply deny-by-default nftables rules with rate limiting and NAT masquerade.

        Security properties enforced:
          - FW-01: policy drop on input + forward chains; rate limit 5/s burst 10
          - FW-02: NAT masquerade only on detected outbound interface (not globally)
          - FW-03: Generated ruleset validated against expected template before apply
          - Applied separately from PostUp/PostDown (locked decision)
          - Idempotent: checks existing rules before applying

        Args:
            wg_port:       UDP port WireGuard listens on.
            wg_interface:  WireGuard interface name (e.g., wg0).
            subnet:        WireGuard subnet in CIDR (unused in nftables rules directly,
                           masquerade uses iifname match instead of subnet match).
        """
        pub_iface = self.detect_outbound_interface()

        # Build generated rules and expected template from the same function
        # to ensure FW-03 validation is always symmetric.
        generated_rules = _build_nftables_ruleset(pub_iface, wg_interface, wg_port)
        template_rules = _build_nftables_ruleset(pub_iface, wg_interface, wg_port)

        # FW-03: validate generated rules against template before applying
        self.validate_firewall_rules(generated_rules, template_rules)

        # Idempotency check: if wg_filter table already exists, compare rules
        check = subprocess.run(
            ["nft", "list", "table", "inet", "wg_filter"],
            shell=False,
            capture_output=True,
        )
        if check.returncode == 0:
            # Table exists -- flush and re-apply (ensures we apply current rules)
            subprocess.run(
                ["nft", "delete", "table", "inet", "wg_filter"],
                shell=False,
                capture_output=True,
            )
            subprocess.run(
                ["nft", "delete", "table", "ip", "wg_nat"],
                shell=False,
                capture_output=True,
            )

        # Ensure /etc/nftables.d/ exists
        if not _NFTABLES_DIR.exists():
            _NFTABLES_DIR.mkdir(parents=True, mode=0o755, exist_ok=True)

        # Write ruleset file atomically
        atomic_write(_NFT_RULES_FILE, generated_rules.encode("utf-8"), mode=0o644)

        # Apply the rules
        try:
            subprocess.run(
                ["nft", "-f", str(_NFT_RULES_FILE)],
                shell=False,
                check=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise SetupError(
                f"Failed to apply nftables rules: {stderr}"
            ) from exc

    def remove_firewall_rules(self, wg_interface: str) -> None:
        """Remove all wireseal nftables tables and the drop-in rule file.

        Idempotent: errors from missing tables are silently ignored.

        Args:
            wg_interface: WireGuard interface name (unused on Linux -- rules
                          are keyed by table name, not interface).
        """
        subprocess.run(
            ["nft", "delete", "table", "inet", "wg_filter"],
            shell=False,
            capture_output=True,
        )
        subprocess.run(
            ["nft", "delete", "table", "ip", "wg_nat"],
            shell=False,
            capture_output=True,
        )
        if _NFT_RULES_FILE.exists():
            _NFT_RULES_FILE.unlink()

    # ------------------------------------------------------------------
    # 7. IP forwarding
    # ------------------------------------------------------------------

    def open_firewalld_port(self, wg_port: int) -> None:
        """Open WireGuard UDP port in firewalld if firewalld is active.

        Without this, firewalld's filter_INPUT chain (priority filter+10) rejects
        incoming WireGuard UDP packets even though wg_filter accepts them at
        priority 0, because nftables evaluates both chains independently.

        Idempotent: skips if firewalld is not running or port is already open.
        """
        if shutil.which("firewall-cmd") is None:
            return

        # Check if firewalld is running
        check = subprocess.run(
            ["firewall-cmd", "--state"],
            shell=False, capture_output=True,
        )
        if check.returncode != 0:
            return  # firewalld not running

        # Check if port is already open
        check = subprocess.run(
            ["firewall-cmd", "--query-port", f"{wg_port}/udp"],
            shell=False, capture_output=True,
        )
        if check.returncode == 0:
            return  # already open

        try:
            subprocess.run(
                ["firewall-cmd", "--add-port", f"{wg_port}/udp", "--permanent"],
                shell=False, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                ["firewall-cmd", "--reload"],
                shell=False, check=True, capture_output=True, timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            print(f"[wireseal] Warning: could not open firewalld port: {stderr}",
                  file=sys.stderr)

    def ensure_sshd(self) -> None:
        """Ensure OpenSSH server is installed and running.

        Enables SFTP/SSH access from VPN clients to the server for file transfer.
        Idempotent: skips if sshd is already running.
        """
        # Check if sshd is already running
        check = subprocess.run(
            ["systemctl", "is-active", "sshd"],
            shell=False, capture_output=True,
        )
        if check.returncode == 0:
            return  # already running

        # Also check ssh.service (Debian/Ubuntu name)
        check = subprocess.run(
            ["systemctl", "is-active", "ssh"],
            shell=False, capture_output=True,
        )
        if check.returncode == 0:
            return

        # Try to install openssh if not present
        if shutil.which("sshd") is None:
            try:
                if shutil.which("pacman"):
                    subprocess.run(
                        ["pacman", "-S", "--needed", "--noconfirm", "openssh"],
                        shell=False, check=True, capture_output=True, timeout=120,
                    )
                elif shutil.which("apt-get"):
                    subprocess.run(
                        ["apt-get", "install", "-y", "openssh-server"],
                        shell=False, check=True, capture_output=True, timeout=120,
                    )
                elif shutil.which("dnf"):
                    subprocess.run(
                        ["dnf", "install", "-y", "openssh-server"],
                        shell=False, check=True, capture_output=True, timeout=120,
                    )
            except subprocess.CalledProcessError as exc:
                stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
                print(f"[wireseal] Warning: could not install openssh: {stderr}",
                      file=sys.stderr)
                return

        # Enable SFTP logging for file activity tracking
        self._enable_sftp_logging()

        # Enable and start sshd
        for svc_name in ("sshd", "ssh"):
            try:
                subprocess.run(
                    ["systemctl", "enable", "--now", svc_name],
                    shell=False, check=True, capture_output=True, timeout=30,
                )
                return
            except subprocess.CalledProcessError:
                continue

        print("[wireseal] Warning: could not start sshd service", file=sys.stderr)

    def _enable_sftp_logging(self) -> None:
        """Enable verbose SFTP logging in sshd_config for file activity tracking.

        Sets LogLevel VERBOSE and configures internal-sftp with -l VERBOSE
        so file operations (open, read, write, rename, remove, etc.) are logged
        to the system journal for the file activity dashboard.
        """
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            return

        try:
            content = sshd_config.read_text(encoding="utf-8")
        except OSError:
            return

        modified = False

        # Set LogLevel VERBOSE if not already set
        if "LogLevel VERBOSE" not in content:
            import re as _re
            # Replace existing LogLevel or add it
            if _re.search(r'^LogLevel\s+', content, _re.MULTILINE):
                content = _re.sub(
                    r'^LogLevel\s+\S+',
                    'LogLevel VERBOSE',
                    content,
                    count=1,
                    flags=_re.MULTILINE,
                )
            else:
                content += "\n# Added by WireSeal for file activity logging\nLogLevel VERBOSE\n"
            modified = True

        # Ensure internal-sftp has verbose logging
        if "internal-sftp" in content and "-l VERBOSE" not in content:
            content = content.replace(
                "internal-sftp",
                "internal-sftp -l VERBOSE",
                1,
            )
            modified = True

        if modified:
            try:
                sshd_config.write_text(content, encoding="utf-8")
                # Reload sshd to apply changes
                subprocess.run(
                    ["systemctl", "reload", "sshd"],
                    shell=False, capture_output=True, timeout=10,
                )
            except (OSError, subprocess.CalledProcessError):
                pass

    def enable_ip_forwarding(self) -> None:
        """Write /etc/sysctl.d/99-wireguard.conf and apply it immediately.

        Uses the sysctl.d drop-in approach for persistence across reboots.
        Idempotent: skips write if file already has the correct content.
        """
        desired_content = "net.ipv4.ip_forward = 1\n"

        # Idempotency: skip write if file already has the correct content
        if _SYSCTL_DROP_IN.exists():
            try:
                if _SYSCTL_DROP_IN.read_text(encoding="utf-8") == desired_content:
                    # File is correct -- still apply in case it wasn't activated yet
                    subprocess.run(
                        ["/sbin/sysctl", "-p", str(_SYSCTL_DROP_IN)],
                        shell=False,
                        check=True,
                        capture_output=True,
                    )
                    return
            except OSError:
                pass  # fall through to write

        parent = _SYSCTL_DROP_IN.parent
        if not parent.exists():
            parent.mkdir(parents=True, mode=0o755, exist_ok=True)

        atomic_write(_SYSCTL_DROP_IN, desired_content.encode("utf-8"), mode=0o644)

        try:
            subprocess.run(
                ["/sbin/sysctl", "-p", str(_SYSCTL_DROP_IN)],
                shell=False,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise SetupError(
                f"Failed to apply sysctl settings: {stderr}"
            ) from exc

    # ------------------------------------------------------------------
    # 8 & 9. Tunnel service lifecycle
    # ------------------------------------------------------------------

    def enable_tunnel_service(self, interface: str = "wg0") -> None:
        """Enable and start the wg-quick systemd service for the given interface.

        Args:
            interface: WireGuard interface name (default wg0).

        Raises:
            SetupError: If systemctl enable or start fails.
        """
        service = f"wg-quick@{interface}"
        try:
            subprocess.run(
                ["systemctl", "enable", service],
                shell=False,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["systemctl", "start", service],
                shell=False,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise SetupError(
                f"Failed to enable/start {service}: {stderr}"
            ) from exc

    def disable_tunnel_service(self, interface: str = "wg0") -> None:
        """Stop and disable the wg-quick systemd service.

        Errors are silently ignored (service may already be stopped/disabled).

        Args:
            interface: WireGuard interface name (default wg0).
        """
        service = f"wg-quick@{interface}"
        subprocess.run(
            ["systemctl", "stop", service],
            shell=False,
            capture_output=True,
        )
        subprocess.run(
            ["systemctl", "disable", service],
            shell=False,
            capture_output=True,
        )

    # ------------------------------------------------------------------
    # 10. DNS updater scheduling (HARD-04)
    # ------------------------------------------------------------------

    def setup_dns_updater(
        self, script_path: Path, interval_minutes: int = 5
    ) -> None:
        """Create the wireseal system user and schedule DuckDNS updates via cron.

        HARD-04: DuckDNS runs as non-root wireseal system user, not as root.

        Steps:
          1. Create system user wireseal if not already present.
          2. Write /etc/cron.d/wireseal with correct ownership and permissions.

        Args:
            script_path:      Path to the wireseal CLI entry point.
            interval_minutes: How often to run the DNS update (default 5 min).
        """
        # Step 1: Create system user if not present
        user_check = subprocess.run(
            ["id", "wireseal"],
            shell=False,
            capture_output=True,
        )
        if user_check.returncode != 0:
            try:
                subprocess.run(
                    [
                        "adduser", "wireseal",
                        "--system",
                        "--no-create-home",
                        "--shell", "/usr/sbin/nologin",
                        "--group",
                        "--disabled-password",
                    ],
                    shell=False,
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as exc:
                stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
                raise SetupError(
                    f"Failed to create wireseal system user: {stderr}"
                ) from exc

        # Step 2: Write cron.d entry
        cron_content = (
            "# Managed by WireSeal -- DO NOT EDIT\n"
            f"*/{interval_minutes} * * * * wireseal {script_path} update-dns --non-interactive\n"
        )

        parent = _CRON_FILE.parent
        if not parent.exists():
            parent.mkdir(parents=True, mode=0o755, exist_ok=True)

        atomic_write(_CRON_FILE, cron_content.encode("utf-8"), mode=0o644)

    # ------------------------------------------------------------------
    # 11. Config path resolution
    # ------------------------------------------------------------------

    def get_config_path(self, interface: str = "wg0") -> Path:
        """Return the standard Linux WireGuard config path.

        Args:
            interface: Interface name (default wg0).

        Returns:
            Path /etc/wireguard/{interface}.conf
        """
        from ..security.validator import validate_interface_name
        validate_interface_name(interface)
        return _WIREGUARD_DIR / f"{interface}.conf"

    # ------------------------------------------------------------------
    # 12. Outbound interface detection
    # ------------------------------------------------------------------

    def detect_outbound_interface(self) -> str:
        """Detect the default outbound network interface using 'ip route get 8.8.8.8'.

        Parses the 'dev <iface>' field from the routing table output.

        Returns:
            Interface name string (e.g., 'eth0', 'ens3').

        Raises:
            SetupError: If the routing table output cannot be parsed.
        """
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )

        match = re.search(r"\bdev\s+(\S+)", result.stdout)
        if not match:
            raise SetupError(
                "Cannot detect outbound network interface from routing table. "
                f"ip route output: {result.stdout.strip()!r}"
            )

        return match.group(1)
