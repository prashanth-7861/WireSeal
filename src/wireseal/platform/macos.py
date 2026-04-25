"""macOS platform adapter for WireSeal.

Implements AbstractPlatformAdapter for macOS with:
  - Homebrew-aware WireGuard management (handles root refusal via SUDO_USER)
  - pfctl anchor-based firewall (survives OS updates, never edits /etc/pf.conf)
  - Runtime sysctl IP forwarding with launchd boot persistence (sysctl.conf
    is unreliable on macOS Sonoma/Sequoia 14+/15+)
  - launchd plist service management for tunnel and DNS updater
  - Non-admin user for DuckDNS updates (HARD-04)

macOS-specific caveats handled:
  - Homebrew refuses to run as root -- uses SUDO_USER env var to drop privileges
  - sysctl.conf unreliable on Sonoma/Sequoia -- companion launchd plist used
  - pfctl anchor required (not /etc/pf.conf edit) to survive OS updates
  - Intel Mac + Sequoia bottle issues with wireguard-tools warned to stderr
"""

from __future__ import annotations

import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .base import AbstractPlatformAdapter
from .exceptions import PrivilegeError, PrerequisiteError, SetupError
from ..security.atomic import atomic_write


class MacOSAdapter(AbstractPlatformAdapter):
    """macOS-specific platform adapter for WireSeal.

    All subprocess calls use ``shell=False`` and list-style arguments.
    Timeout defaults to 30 seconds for most operations (120 seconds for brew).
    """

    # Path used to store the pf token for cleanup (created on apply_firewall_rules)
    _PF_TOKEN_PATH = Path("/var/run/wireseal/pf_token")
    # Anchor name -- never use /etc/pf.conf
    _PF_ANCHOR = "com.apple/wireguard"

    def __init__(self) -> None:
        self._brew_prefix: str | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_brew_prefix(self) -> str:
        """Return the Homebrew prefix, caching the result after the first call.

        Raises:
            PrerequisiteError: If Homebrew is not installed.
        """
        if self._brew_prefix is not None:
            return self._brew_prefix

        try:
            result = subprocess.run(
                ["brew", "--prefix"],
                capture_output=True,
                text=True,
                shell=False,
                check=True,
                timeout=30,
            )
            self._brew_prefix = result.stdout.strip()
            return self._brew_prefix
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise PrerequisiteError(
                "Homebrew not found. Install from https://brew.sh and then run: "
                "brew install wireguard-tools"
            )

    def _run(
        self,
        args: list[str],
        *,
        check: bool = True,
        capture: bool = True,
        timeout: int = 30,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess:
        """Convenience wrapper: always shell=False."""
        return subprocess.run(
            args,
            shell=False,
            check=check,
            capture_output=capture,
            timeout=timeout,
            input=input_bytes,
        )

    def _chown_root_wheel(self, path: Path) -> None:
        """Set ownership to root:wheel on a file."""
        self._run(["chown", "root:wheel", str(path)])

    def _chmod(self, path: Path, mode: str) -> None:
        """Set file permissions using chmod."""
        self._run(["chmod", mode, str(path)])

    # ------------------------------------------------------------------
    # 1. Privilege check
    # ------------------------------------------------------------------

    def check_privileges(self) -> None:
        """Raise PrivilegeError when not running as root (euid != 0).

        Also prints a warning to stderr if SUDO_USER is set, reminding the
        operator about the vault HOME location.
        """
        if os.geteuid() != 0:
            raise PrivilegeError(
                "wireseal requires root privileges. Re-run with: sudo wireseal"
            )
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            print(
                f"Warning: running as root via sudo (original user: {sudo_user}). "
                f"The vault will be created under /Users/{sudo_user}/.wireseal/ "
                "unless VAULT_HOME is overridden.",
                file=sys.stderr,
            )

    # ------------------------------------------------------------------
    # 2. Prerequisite check
    # ------------------------------------------------------------------

    def check_prerequisites(self) -> list[str]:
        """Check for wg-quick, wg, and pfctl.

        Raises:
            PrerequisiteError: If wireguard-tools are missing.

        Returns:
            Empty list if all tools are present.
        """
        missing: list[str] = []

        if not shutil.which("wg-quick") or not shutil.which("wg"):
            raise PrerequisiteError(
                "Missing: wireguard-tools. Run: brew install wireguard-tools"
            )

        if not shutil.which("pfctl"):
            # pfctl is part of macOS base -- should always be present
            missing.append("pfctl")

        # Intel Mac + macOS Sequoia (15+) bottle warning
        if platform.machine() == "x86_64":
            try:
                mac_ver = platform.mac_ver()[0]  # e.g., "15.0" or "14.3.1"
                major = int(mac_ver.split(".")[0]) if mac_ver else 0
                if major >= 15:
                    print(
                        "Warning: Intel Macs on macOS Sequoia may have Homebrew bottle "
                        "issues with wireguard-tools. If brew install fails, try building "
                        "from source: brew install --build-from-source wireguard-tools",
                        file=sys.stderr,
                    )
            except (ValueError, IndexError):
                pass  # Cannot determine version -- skip warning

        return missing

    # ------------------------------------------------------------------
    # 3. WireGuard installation
    # ------------------------------------------------------------------

    def install_wireguard(self) -> None:
        """Install wireguard-tools via Homebrew, handling root refusal.

        Homebrew refuses to run as root. This method drops privileges to
        SUDO_USER when available; raises SetupError if running as true root.

        Raises:
            SetupError: If running as root without SUDO_USER.
            PrerequisiteError: If Homebrew is not installed.
        """
        if shutil.which("wg-quick"):
            return  # Idempotent -- already installed

        sudo_user = os.environ.get("SUDO_USER")
        if not sudo_user:
            raise SetupError(
                "Cannot install wireguard-tools: Homebrew refuses to run as root. "
                "Install manually: brew install wireguard-tools (as your regular user), "
                "then re-run wireseal."
            )

        self._run(
            ["sudo", "-u", sudo_user, "brew", "install", "wireguard-tools"],
            check=True,
            timeout=120,
        )

    # ------------------------------------------------------------------
    # 4. Config deployment
    # ------------------------------------------------------------------

    def deploy_config(self, config_content: str, interface: str = "wg0") -> Path:
        """Write WireGuard config to the Homebrew-prefix wireguard directory.

        Args:
            config_content: WireGuard INI configuration as a string.
            interface:       Interface name (default ``wg0``).

        Returns:
            Path where the config was written.
        """
        path = self.get_config_path(interface)
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, mode=0o700)
        atomic_write(path, config_content.encode("utf-8"), mode=0o600)
        return path

    # ------------------------------------------------------------------
    # 5 & 6. Firewall management (pfctl anchor -- NEVER /etc/pf.conf)
    # ------------------------------------------------------------------

    def apply_firewall_rules(
        self, wg_port: int, wg_interface: str, subnet: str
    ) -> None:
        """Apply deny-by-default + rate-limited UDP + NAT rules via pfctl anchor.

        Uses anchor ``com.apple/wireguard`` -- survives OS updates since the
        anchor is stored separately from /etc/pf.conf.

        Rate-limiting uses PF overload tables: UDP packets exceeding 5/second
        trigger an overload entry in <wg_bruteforce> which blocks the source.

        Args:
            wg_port:       UDP port WireGuard listens on.
            wg_interface:  WireGuard interface name (e.g., ``wg0``).
            subnet:        WireGuard subnet in CIDR notation (e.g., ``10.0.0.0/24``).
        """
        outbound = self.detect_outbound_interface()

        rules = (
            f"# wireseal managed rules -- DO NOT EDIT\n"
            f"nat on {outbound} from {subnet} to any -> ({outbound})\n"
            f"table <wg_bruteforce> persist\n"
            f"block drop in quick on {outbound} from <wg_bruteforce>\n"
            f"pass in quick on {outbound} proto udp from any to any port {wg_port} "
            f"keep state (max-pkt-rate 5/1, overload <wg_bruteforce> flush global)\n"
            f"block drop in on {outbound} all\n"
        )

        # Build template with the same values for FW-03 validation
        template = (
            f"nat on {outbound} from {subnet} to any -> ({outbound})\n"
            f"table <wg_bruteforce> persist\n"
            f"block drop in quick on {outbound} from <wg_bruteforce>\n"
            f"pass in quick on {outbound} proto udp from any to any port {wg_port} "
            f"keep state (max-pkt-rate 5/1, overload <wg_bruteforce> flush global)\n"
            f"block drop in on {outbound} all\n"
        )

        # FW-03: validate generated rules against template before applying
        self.validate_firewall_rules(rules, template)

        # Idempotency: re-apply only when config changed. pfctl normalizes its
        # output, so compare on the values that can actually drift (subnet,
        # port, outbound interface). If any expected token is missing, the
        # anchor is stale (e.g. user changed WG_PORT or WG_SUBNET) -- rebuild.
        existing = subprocess.run(
            ["pfctl", "-a", self._PF_ANCHOR, "-sr"],
            capture_output=True,
            text=True,
            shell=False,
        )
        if existing.returncode == 0 and existing.stdout.strip():
            out = existing.stdout
            expected_tokens = (
                f"from {subnet}",
                f"port = {wg_port}",
                outbound,
            )
            if all(tok in out for tok in expected_tokens):
                # Rules already loaded with matching config -- skip re-apply
                return
            # Stale anchor content -- flush before reloading
            subprocess.run(
                ["pfctl", "-a", self._PF_ANCHOR, "-F", "all"],
                capture_output=True,
                shell=False,
            )

        # Apply rules to anchor via stdin
        self._run(
            ["pfctl", "-a", self._PF_ANCHOR, "-f", "-"],
            input_bytes=rules.encode("utf-8"),
        )

        # Enable pf if not already enabled (ignore "already enabled" error)
        subprocess.run(
            ["pfctl", "-e"],
            shell=False,
            capture_output=True,
        )

        # Write pf token for cleanup
        token_path = self._PF_TOKEN_PATH
        if not token_path.parent.exists():
            token_path.parent.mkdir(parents=True, mode=0o700)
        # Token is informational -- use the anchor name as the token reference
        atomic_write(token_path, self._PF_ANCHOR.encode("utf-8"), mode=0o600)

    def remove_firewall_rules(self, wg_interface: str) -> None:
        """Flush the pfctl anchor and release the pf reference token.

        Args:
            wg_interface: WireGuard interface name (unused on macOS -- anchor
                          is keyed by name, not interface).
        """
        # Flush all rules from the anchor
        subprocess.run(
            ["pfctl", "-a", self._PF_ANCHOR, "-F", "all"],
            shell=False,
            capture_output=True,
        )

        # Release pf token if one was saved
        token_path = self._PF_TOKEN_PATH
        if token_path.exists():
            try:
                token = token_path.read_text().strip()
                if token and token != self._PF_ANCHOR:
                    # Only call pfctl -X if the token is a numeric pf reference
                    subprocess.run(
                        ["pfctl", "-X", token],
                        shell=False,
                        capture_output=True,
                    )
                token_path.unlink(missing_ok=True)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # 7. IP forwarding (runtime sysctl + launchd boot persistence)
    # ------------------------------------------------------------------

    def enable_ip_forwarding(self) -> None:
        """Enable IPv4 forwarding via sysctl -w and persist via launchd.

        sysctl.conf is unreliable on macOS Sonoma (14+) and Sequoia (15+).
        A companion launchd plist at boot time ensures forwarding survives
        reboots without relying on sysctl.conf.
        """
        # Apply immediately
        self._run(["/usr/sbin/sysctl", "-w", "net.inet.ip.forwarding=1"])

        # Build boot-persistence launchd plist
        plist_data = {
            "Label": "com.wireseal.sysctl",
            "ProgramArguments": ["/usr/sbin/sysctl", "-w", "net.inet.ip.forwarding=1"],
            "RunAtLoad": True,
            "LaunchOnlyOnce": True,
        }
        plist_bytes = plistlib.dumps(plist_data)
        plist_path = Path("/Library/LaunchDaemons/com.wireseal.sysctl.plist")

        atomic_write(plist_path, plist_bytes, mode=0o644)
        self._chown_root_wheel(plist_path)
        self._chmod(plist_path, "644")

        # Load (ignore "already loaded" error)
        subprocess.run(
            ["launchctl", "bootstrap", "system", str(plist_path)],
            shell=False,
            capture_output=True,
        )

    # ------------------------------------------------------------------
    # 8 & 9. Tunnel service lifecycle (launchd)
    # ------------------------------------------------------------------

    def enable_tunnel_service(self, interface: str = "wg0") -> None:
        """Install (but do NOT auto-load) a launchd plist for manual start.

        The plist is written with ``RunAtLoad=False`` and ``KeepAlive=False``
        so the tunnel stays off after reboot. The user controls lifecycle via
        the API Start/Stop buttons, which invoke ``wg-quick up/down`` directly.

        This matches the Windows ``start=demand`` / Linux non-enabled-unit
        model: registration exists, autostart does not.

        Args:
            interface: WireGuard interface name (default ``wg0``).
        """
        brew_prefix = self._get_brew_prefix()
        wg_quick = str(Path(brew_prefix) / "bin" / "wg-quick")
        config_path = self.get_config_path(interface)

        path_env = (
            f"{brew_prefix}/sbin:{brew_prefix}/bin:"
            "/usr/bin:/bin:/usr/sbin:/sbin"
        )
        plist_data = {
            "Label": f"com.wireseal.{interface}",
            "ProgramArguments": [wg_quick, "up", str(config_path)],
            # Manual start only — no boot autostart, no respawn.
            "KeepAlive": False,
            "RunAtLoad": False,
            "LaunchOnlyOnce": True,
            "StandardErrorPath": "/var/log/wireseal.err",
            "EnvironmentVariables": {"PATH": path_env},
        }
        plist_bytes = plistlib.dumps(plist_data)
        plist_path = Path(
            f"/Library/LaunchDaemons/com.wireseal.{interface}.plist"
        )

        atomic_write(plist_path, plist_bytes, mode=0o644)
        self._chown_root_wheel(plist_path)
        self._chmod(plist_path, "644")
        # Do NOT bootstrap/enable — user starts manually via API.

    def disable_tunnel_service(self, interface: str = "wg0") -> None:
        """Bootout and disable the WireGuard tunnel launchd service.

        Also runs ``wg-quick down`` to clean up the utun interface.

        Args:
            interface: WireGuard interface name (default ``wg0``).
        """
        label = f"system/com.wireseal.{interface}"
        subprocess.run(
            ["launchctl", "bootout", label],
            shell=False,
            capture_output=True,
        )
        subprocess.run(
            ["launchctl", "disable", label],
            shell=False,
            capture_output=True,
        )

        # Clean up the utun interface (ignore errors if already down)
        try:
            brew_prefix = self._get_brew_prefix()
            wg_quick = str(Path(brew_prefix) / "bin" / "wg-quick")
            subprocess.run(
                [wg_quick, "down", interface],
                shell=False,
                capture_output=True,
                timeout=30,
            )
        except (PrerequisiteError, OSError):
            pass  # If brew or wg-quick unavailable, interface cleanup skipped

    # ------------------------------------------------------------------
    # 10. DNS updater scheduling (non-admin user via launchd UserName)
    # ------------------------------------------------------------------

    def setup_dns_updater(
        self, script_path: Path, interval_minutes: int = 5
    ) -> None:
        """Schedule DuckDNS updates as a non-admin user via launchd (HARD-04).

        Creates the ``wireseal`` system user if it does not exist, then
        writes a launchd plist with ``UserName`` set to that account so
        the update script runs without root/admin privileges.

        Args:
            script_path:      Path to the DuckDNS update script.
            interval_minutes: Update interval in minutes (default 5).
        """
        self._ensure_wg_automate_user()

        plist_data = {
            "Label": "com.wireseal.dns",
            "ProgramArguments": [str(script_path), "update-dns", "--non-interactive"],
            "StartInterval": interval_minutes * 60,
            "UserName": "wireseal",
            "StandardErrorPath": "/var/log/wireseal-dns.err",
        }
        plist_bytes = plistlib.dumps(plist_data)
        plist_path = Path("/Library/LaunchDaemons/com.wireseal.dns.plist")

        # Detect whether plist content changed since last install — launchctl
        # bootstrap on an already-loaded service silently ignores new settings,
        # so we must bootout first when content differs.
        content_changed = True
        if plist_path.exists():
            try:
                content_changed = plist_path.read_bytes() != plist_bytes
            except OSError:
                content_changed = True

        atomic_write(plist_path, plist_bytes, mode=0o644)
        self._chown_root_wheel(plist_path)
        self._chmod(plist_path, "644")

        label = "system/com.wireseal.dns"
        if content_changed:
            # bootout returns nonzero if service not loaded — that's fine
            self._run(
                ["launchctl", "bootout", label],
                check=False,
            )
        self._run(["launchctl", "bootstrap", "system", str(plist_path)])

    # ------------------------------------------------------------------
    # 11. Config path resolution
    # ------------------------------------------------------------------

    def get_config_path(self, interface: str = "wg0") -> Path:
        """Return the Homebrew-prefix WireGuard config path.

        On Apple Silicon this is typically ``/opt/homebrew/etc/wireguard/wg0.conf``;
        on Intel it is ``/usr/local/etc/wireguard/wg0.conf``.

        Args:
            interface: WireGuard interface name (default ``wg0``).

        Returns:
            Absolute path to the config file.
        """
        from ..security.validator import validate_interface_name
        validate_interface_name(interface)
        prefix = self._get_brew_prefix()
        return Path(prefix) / "etc" / "wireguard" / f"{interface}.conf"

    # ------------------------------------------------------------------
    # 12. Outbound interface detection
    # ------------------------------------------------------------------

    def detect_outbound_interface(self) -> str:
        """Return the default outbound interface by parsing ``route -n get 8.8.8.8``.

        Returns:
            Interface name string (e.g., ``"en0"``).

        Raises:
            SetupError: If the interface cannot be determined from route output.
        """
        result = self._run(
            ["route", "-n", "get", "8.8.8.8"],
            check=True,
        )
        output = result.stdout.decode("utf-8", errors="replace")
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("interface:"):
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1]

        raise SetupError("Cannot detect outbound network interface")

    # ------------------------------------------------------------------
    # Network services (SSH, hardening, security status)
    # ------------------------------------------------------------------

    def ensure_sshd(self) -> None:
        """Ensure SSH (Remote Login) is enabled on macOS.

        Uses systemsetup to enable SSH. macOS ships with sshd built-in.
        """
        # Check if already enabled
        result = subprocess.run(
            ["systemsetup", "-getremotelogin"],
            shell=False, capture_output=True, text=True, timeout=10,
        )
        if "On" in result.stdout:
            return

        subprocess.run(
            ["systemsetup", "-setremotelogin", "on"],
            shell=False, capture_output=True, timeout=10,
        )

    def open_firewalld_port(self, wg_port: int) -> None:
        """Ensure pf firewall allows WireGuard and SSH traffic.

        On macOS, the pf anchor already handles WireGuard.
        This ensures SSH (port 22) is also allowed.
        """
        # macOS application firewall (socketfilterfw) — allow sshd
        subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"],
            shell=False, capture_output=True,
        )
        sshd_path = shutil.which("sshd") or "/usr/sbin/sshd"
        subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--add", sshd_path],
            shell=False, capture_output=True,
        )
        subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--unblockapp", sshd_path],
            shell=False, capture_output=True,
        )

    def harden_server(self) -> list[str]:
        """Apply macOS-specific server hardening. Returns list of actions taken."""
        actions: list[str] = []
        actions += self._harden_ssh_macos()
        actions += self._harden_macos_firewall()
        return actions

    def _harden_ssh_macos(self) -> list[str]:
        """Harden SSH configuration on macOS."""
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            return []

        try:
            content = sshd_config.read_text(encoding="utf-8")
        except OSError:
            return []

        actions = []
        original = content

        hardening = {
            "PermitRootLogin": "no",
            "MaxAuthTries": "3",
            "LoginGraceTime": "30",
            "PermitEmptyPasswords": "no",
            "X11Forwarding": "no",
            "ClientAliveInterval": "300",
            "ClientAliveCountMax": "2",
        }

        for key, value in hardening.items():
            pattern = re.compile(rf'^#?\s*{key}\s+.*$', re.MULTILINE)
            replacement = f"{key} {value}"
            if pattern.search(content):
                new_content = pattern.sub(replacement, content, count=1)
                if new_content != content:
                    content = new_content
                    actions.append(f"SSH: {key} -> {value}")
            elif f"{key} {value}" not in content:
                content += f"\n{key} {value}"
                actions.append(f"SSH: {key} -> {value}")

        if content != original:
            try:
                sshd_config.write_text(content, encoding="utf-8")
                # Restart SSH on macOS
                subprocess.run(
                    ["launchctl", "stop", "com.openssh.sshd"],
                    shell=False, capture_output=True,
                )
                subprocess.run(
                    ["launchctl", "start", "com.openssh.sshd"],
                    shell=False, capture_output=True,
                )
            except OSError:
                pass

        return actions

    def _harden_macos_firewall(self) -> list[str]:
        """Enable macOS application firewall + stealth mode."""
        actions = []

        # Enable application firewall
        result = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"],
            shell=False, capture_output=True, text=True,
        )
        if result.returncode == 0:
            actions.append("Firewall: application firewall enabled")

        # Enable stealth mode (don't respond to pings from unknown sources)
        result = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setstealthmode", "on"],
            shell=False, capture_output=True, text=True,
        )
        if result.returncode == 0:
            actions.append("Firewall: stealth mode enabled")

        return actions

    def get_security_status(self) -> dict:
        """Check current macOS security posture."""
        from typing import Any
        status: dict[str, Any] = {
            "ssh_hardened": False,
            "kernel_hardened": False,
            "fail2ban_active": False,
            "fail2ban_bans": 0,
            "firewall_active": False,
            "ip_forwarding": False,
            "auto_updates": False,
            "open_ports": [],
            "checks": [],
        }

        # Check SSH hardening
        sshd_config = Path("/etc/ssh/sshd_config")
        if sshd_config.exists():
            try:
                content = sshd_config.read_text()
                root_disabled = "PermitRootLogin no" in content
                max_auth = "MaxAuthTries 3" in content or "MaxAuthTries 2" in content
                status["ssh_hardened"] = root_disabled and max_auth
                status["checks"].append({
                    "name": "Root login disabled",
                    "ok": root_disabled,
                    "fix": None if root_disabled else "Set PermitRootLogin no",
                })
                status["checks"].append({
                    "name": "Auth attempts limited",
                    "ok": max_auth,
                    "fix": None if max_auth else "Set MaxAuthTries 3",
                })
            except OSError:
                pass

        # Check macOS application firewall
        result = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            shell=False, capture_output=True, text=True,
        )
        fw_on = result.returncode == 0 and "enabled" in result.stdout.lower()
        status["firewall_active"] = fw_on
        status["checks"].append({
            "name": "macOS Application Firewall",
            "ok": fw_on,
            "fix": None if fw_on else "Click Harden Server to enable",
        })

        # Check stealth mode
        result = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
            shell=False, capture_output=True, text=True,
        )
        stealth_on = result.returncode == 0 and "enabled" in result.stdout.lower()
        status["checks"].append({
            "name": "Stealth mode (hide from scans)",
            "ok": stealth_on,
            "fix": None if stealth_on else "Click Harden Server to enable",
        })

        # Check pf firewall (WireGuard anchor)
        result = subprocess.run(
            ["pfctl", "-a", self._PF_ANCHOR, "-sr"],
            shell=False, capture_output=True, text=True,
        )
        pf_active = result.returncode == 0 and result.stdout.strip() != ""
        status["checks"].append({
            "name": "pf firewall (WireGuard rules)",
            "ok": pf_active,
        })

        # Check IP forwarding
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "net.inet.ip.forwarding"],
            shell=False, capture_output=True, text=True,
        )
        status["ip_forwarding"] = result.stdout.strip() == "1"
        status["checks"].append({
            "name": "IP forwarding enabled",
            "ok": status["ip_forwarding"],
        })

        # Check auto-updates
        result = subprocess.run(
            ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"],
            shell=False, capture_output=True, text=True,
        )
        auto_up = result.stdout.strip() == "1"
        status["auto_updates"] = auto_up
        status["checks"].append({
            "name": "Automatic software updates",
            "ok": auto_up,
            "fix": None if auto_up else "Enable in System Settings > Software Update",
        })

        # Check open ports
        try:
            result = subprocess.run(
                ["lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P"],
                shell=False, capture_output=True, text=True, timeout=10,
            )
            ports = []
            seen = set()
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    addr = parts[8]
                    if ":" in addr:
                        port_str = addr.rsplit(":", 1)[-1]
                        if port_str.isdigit():
                            port = int(port_str)
                            process = parts[0]
                            key = (port, "tcp")
                            if key not in seen:
                                seen.add(key)
                                ports.append({"port": port, "proto": "tcp", "process": process})
            status["open_ports"] = sorted(ports, key=lambda x: x["port"])[:50]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return status

    # ------------------------------------------------------------------
    # Internal: system user management
    # ------------------------------------------------------------------

    def _ensure_wg_automate_user(self) -> None:
        """Create the ``wireseal`` system user if it does not exist.

        Uses ``dscl`` to create a system user with no shell, UID < 500,
        and home directory ``/var/empty``.
        """
        # Check if user already exists
        check = subprocess.run(
            ["dscl", ".", "-read", "/Users/wireseal"],
            capture_output=True,
            shell=False,
        )
        if check.returncode == 0:
            return  # User exists -- skip creation

        # Find an available UID in the system range (300-499)
        uid = self._find_available_uid(300, 499)
        gid = uid  # Use matching GID for simplicity

        dscl_cmds = [
            ["dscl", ".", "-create", "/Users/wireseal"],
            ["dscl", ".", "-create", "/Users/wireseal", "UserShell", "/usr/bin/false"],
            ["dscl", ".", "-create", "/Users/wireseal", "UniqueID", str(uid)],
            ["dscl", ".", "-create", "/Users/wireseal", "PrimaryGroupID", str(gid)],
            [
                "dscl", ".", "-create", "/Users/wireseal",
                "NFSHomeDirectory", "/var/empty",
            ],
        ]
        for cmd in dscl_cmds:
            self._run(cmd)

    def _find_available_uid(self, low: int, high: int) -> int:
        """Find an unused UID in the range [low, high] via dscl.

        Args:
            low:  Lowest UID to try.
            high: Highest UID to try.

        Returns:
            An available UID.

        Raises:
            SetupError: If no UID is available in the given range.
        """
        for uid in range(low, high + 1):
            result = subprocess.run(
                ["dscl", ".", "-search", "/Users", "UniqueID", str(uid)],
                capture_output=True,
                shell=False,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return uid

        raise SetupError(
            f"No available UID in range {low}-{high} for WireSeal system user"
        )

    # ------------------------------------------------------------------
    # API server background-service lifecycle (launchd plist).
    # ------------------------------------------------------------------

    _API_SERVICE_LABEL = "com.wireseal.api"
    _API_SERVICE_PATH = Path("/Library/LaunchDaemons/com.wireseal.api.plist")

    def install_api_service(
        self, bind: str = "127.0.0.1", port: int = 8080,
        autostart: bool = True,
    ) -> None:
        """Write a LaunchDaemon plist for the WireSeal dashboard.

        Args:
            bind:      Address the dashboard binds to.
            port:      Dashboard port.
            autostart: Set ``RunAtLoad=true`` so it starts at boot.
        """
        wireseal_bin = shutil.which("wireseal") or "/usr/local/bin/wireseal"
        plist_dict = {
            "Label": self._API_SERVICE_LABEL,
            "ProgramArguments": [
                wireseal_bin, "serve",
                "--bind", bind,
                "--port", str(port),
            ],
            "RunAtLoad": bool(autostart),
            "KeepAlive": True,
            "StandardErrorPath": "/var/log/wireseal-api.err",
            "StandardOutPath":   "/var/log/wireseal-api.log",
        }
        plist_bytes = plistlib.dumps(plist_dict)
        # Reload only when content actually changed (avoids spurious bootouts).
        content_changed = True
        if self._API_SERVICE_PATH.exists():
            try:
                content_changed = (
                    self._API_SERVICE_PATH.read_bytes() != plist_bytes
                )
            except OSError:
                content_changed = True
        atomic_write(self._API_SERVICE_PATH, plist_bytes, mode=0o644)
        os.chown(self._API_SERVICE_PATH, 0, 0)  # root:wheel
        if content_changed:
            subprocess.run(
                ["launchctl", "bootout", f"system/{self._API_SERVICE_LABEL}"],
                check=False, capture_output=True,
            )
        subprocess.run(
            ["launchctl", "bootstrap", "system", str(self._API_SERVICE_PATH)],
            check=False, capture_output=True,
        )

    def uninstall_api_service(self) -> None:
        """Stop the LaunchDaemon and remove its plist."""
        subprocess.run(
            ["launchctl", "bootout", f"system/{self._API_SERVICE_LABEL}"],
            check=False, capture_output=True,
        )
        if self._API_SERVICE_PATH.exists():
            self._API_SERVICE_PATH.unlink()

    def start_api_service(self) -> None:
        subprocess.run(
            ["launchctl", "kickstart", "-k", f"system/{self._API_SERVICE_LABEL}"],
            check=True, capture_output=True,
        )

    def stop_api_service(self) -> None:
        subprocess.run(
            ["launchctl", "kill", "TERM", f"system/{self._API_SERVICE_LABEL}"],
            check=False, capture_output=True,
        )

    def api_service_status(self) -> dict:
        """Return ``{installed, running, enabled}``.

        On launchd, ``enabled`` ≡ ``RunAtLoad=true`` in the plist (we always
        set it to the same value the user picked at install time, so we
        report ``installed`` as a proxy here).
        """
        installed = self._API_SERVICE_PATH.exists()
        running = False
        try:
            out = subprocess.run(
                ["launchctl", "print", f"system/{self._API_SERVICE_LABEL}"],
                capture_output=True, text=True, check=False,
            )
            running = "state = running" in (out.stdout or "")
        except Exception:
            pass
        return {"installed": installed, "running": running, "enabled": installed}
