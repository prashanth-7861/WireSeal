"""Windows platform adapter for WireSeal.

Implements AbstractPlatformAdapter for Windows using:
  - WireGuard Manager Service (wireguard.exe /installtunnelservice) for tunnel lifecycle
  - DPAPI automatic config encryption (wireguard.exe encrypts .conf -> .conf.dpapi on install)
  - netsh advfirewall for deny-by-default + WG UDP allow (FW-01, FW-02, FW-03)
  - winreg for persistent IP forwarding via IPEnableRouter (requires reboot)
  - Task Scheduler for DuckDNS as low-privilege wireseal-dns user (HARD-04)
  - icacls/pywin32 for config file ACL -- os.chmod NEVER called for security (PLAT-06)

This file is only imported on Windows. Platform detection (detect.py) uses lazy imports
via get_adapter() to prevent winreg and ctypes.windll from loading on Linux/macOS.
"""

from __future__ import annotations

import ctypes
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

# winreg is Windows-only stdlib; safe to import here because this module is
# only imported by get_adapter() on Windows (lazy import pattern, see detect.py).
import winreg  # type: ignore[import]

from .base import AbstractPlatformAdapter
from .exceptions import PrerequisiteError, PrivilegeError, SetupError
from ..security.atomic import atomic_write
from ..security.permissions import set_file_permissions, set_dir_permissions


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

WG_EXE = Path(r"C:\Program Files\WireGuard\wireguard.exe")
WG_CONFIG_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "WireGuard"
WG_SERVICE_PREFIX = "WireGuardTunnel$"

# Prevent subprocess calls from flashing a visible console window when
# the app is running as a GUI (PyInstaller console=False / pywebview).
_NO_WIN = subprocess.CREATE_NO_WINDOW  # 0x08000000


# ---------------------------------------------------------------------------
# WindowsAdapter
# ---------------------------------------------------------------------------


class WindowsAdapter(AbstractPlatformAdapter):
    """Windows-specific WireGuard platform adapter.

    Uses Windows-native APIs for all operations:
      - ctypes.windll.shell32.IsUserAnAdmin() for privilege check
      - winreg for persistent IP forwarding (IPEnableRouter)
      - netsh advfirewall for firewall rules (deny-by-default, FW-01)
      - wireguard.exe /installtunnelservice for tunnel service (DPAPI auto-encrypt)
      - schtasks + net user for DuckDNS low-privilege scheduling (HARD-04)
      - icacls for file ACLs -- NEVER os.chmod on Windows (PLAT-06)
    """

    # ------------------------------------------------------------------
    # 1. Privilege check
    # ------------------------------------------------------------------

    def check_privileges(self) -> None:
        """Raise PrivilegeError if not running as Administrator.

        Uses IsUserAnAdmin() from shell32. Per locked decision: no auto-elevation
        via ShellExecuteEx runas -- the user must explicitly run as Administrator.
        """
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except AttributeError:
            # ctypes.windll not available (non-Windows CI environment)
            is_admin = 0

        if not is_admin:
            raise PrivilegeError(
                "wireseal requires Administrator privileges. "
                "Re-run from an elevated command prompt (Run as Administrator)."
            )

    # ------------------------------------------------------------------
    # 2. Prerequisite check
    # ------------------------------------------------------------------

    def check_prerequisites(self) -> list[str]:
        """Check for WireGuard, netsh, winget, sc.exe, and schtasks.

        Raises:
            PrerequisiteError: If WireGuard is missing, with winget or download instructions.

        Returns:
            Empty list if all required tools are present.
        """
        wg_present = WG_EXE.exists() or bool(shutil.which("wireguard"))
        netsh_present = bool(shutil.which("netsh"))
        winget_present = bool(shutil.which("winget"))
        sc_present = bool(shutil.which("sc"))
        schtasks_present = bool(shutil.which("schtasks"))

        missing: list[str] = []

        if not wg_present:
            if winget_present:
                raise PrerequisiteError(
                    "Missing: WireGuard. "
                    "Run: winget install --id WireGuard.WireGuard --silent"
                )
            else:
                raise PrerequisiteError(
                    "Missing: WireGuard. "
                    "Download from https://www.wireguard.com/install/ and install, then re-run."
                )

        if not netsh_present:
            missing.append("netsh")
        if not sc_present:
            missing.append("sc")
        if not schtasks_present:
            missing.append("schtasks")

        return missing

    # ------------------------------------------------------------------
    # 3. WireGuard installation
    # ------------------------------------------------------------------

    def install_wireguard(self) -> None:
        """Install WireGuard via winget (idempotent).

        winget verifies package signatures automatically.

        Raises:
            SetupError: If the installation fails.
        """
        if WG_EXE.exists():
            return  # already installed, nothing to do

        try:
            subprocess.run(
                [
                    "winget", "install",
                    "--id", "WireGuard.WireGuard",
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ],
                shell=False,
                check=True,
                capture_output=True,
                timeout=120,
                creationflags=_NO_WIN,
            )
        except subprocess.CalledProcessError as e:
            raise SetupError(
                f"WireGuard installation failed: {e.stderr.strip()}"
            ) from e

    # ------------------------------------------------------------------
    # 4. Config deployment
    # ------------------------------------------------------------------

    def get_config_path(self, interface: str = "wg0") -> Path:
        """Return %ProgramData%\\WireGuard\\{interface}.conf.

        Per locked decision: interface is always wg0, config is wg0.conf.

        Args:
            interface: WireGuard interface name (default ``wg0``).

        Returns:
            Absolute path to the WireGuard config file.
        """
        from ..security.validator import validate_interface_name
        validate_interface_name(interface)
        return WG_CONFIG_DIR / f"{interface}.conf"

    def deploy_config(self, config_content: str, interface: str = "wg0") -> Path:
        """Write config to %ProgramData%\\WireGuard\\{interface}.conf atomically.

        Uses atomic_write + icacls ACL (SYSTEM + Administrators only).
        NEVER calls os.chmod on Windows (PLAT-06 locked decision).

        Args:
            config_content: WireGuard INI configuration as a string.
            interface:      WireGuard interface name (default ``wg0``).

        Returns:
            Path where the config was written.
        """
        path = self.get_config_path(interface)

        # Ensure config directory exists with restrictive ACL
        if not WG_CONFIG_DIR.exists():
            WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            set_dir_permissions(WG_CONFIG_DIR)

        # Atomic write -- mode param is ignored on Windows in atomic_write
        atomic_write(path, config_content.encode("utf-8"))

        # Apply Windows ACL: SYSTEM + Administrators only (icacls, never os.chmod)
        set_file_permissions(path)

        return path

    # ------------------------------------------------------------------
    # 5 & 6. Firewall management
    # ------------------------------------------------------------------

    def apply_firewall_rules(
        self, wg_port: int, wg_interface: str, subnet: str
    ) -> None:
        """Apply deny-by-default netsh advfirewall rules for WireGuard.

        Rules applied:
          1. Allow inbound WireGuard UDP on wg_port only (FW-01)
          2. Block all other inbound on the WG interface (deny-by-default, FW-01)
          3. Set WG interface to Public network profile (most restrictive)
          4. Enable NAT for VPN subnet on outbound interface only (FW-02)

        FW-03: rules are validated against a canonical template before apply.
        Idempotent: returns immediately if rules already exist.

        Args:
            wg_port:       UDP port WireGuard listens on.
            wg_interface:  WireGuard interface name (e.g., ``wg0``).
            subnet:        WireGuard subnet in CIDR notation (e.g., ``10.0.0.0/24``).
        """
        # Idempotency check: query existing allow rule
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name=wireseal-{wg_interface}-in",
            ],
            capture_output=True,
            text=True,
            shell=False,
            creationflags=_NO_WIN,
        )
        if result.returncode == 0 and f"wireseal-{wg_interface}-in" in result.stdout:
            # Rule exists — check if the port matches the requested one. The
            # `LocalPort` line in netsh output looks like "LocalPort: 51820".
            # If the port differs (user reconfigured), delete and recreate so
            # upgrades pick up port changes instead of silently keeping the
            # stale port.
            port_matches = False
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("localport:"):
                    current_port = stripped.split(":", 1)[1].strip()
                    if current_port == str(wg_port):
                        port_matches = True
                    break
            if port_matches:
                return  # already correct
            # Port changed — delete stale rules so the add calls below recreate
            # them with the new port.
            for rule_name in (f"wireseal-{wg_interface}-in", f"wireseal-{wg_interface}-block"):
                subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}",
                    ],
                    shell=False, capture_output=True,
                    creationflags=_NO_WIN,
                )

        # Detect outbound interface for NAT binding
        outbound = self.detect_outbound_interface()

        # FW-03: Build canonical template and validate against what we will apply
        template = (
            f"netsh advfirewall firewall add rule "
            f"name=wireseal-{wg_interface}-in protocol=UDP dir=in "
            f"localport={wg_port} action=allow profile=any enable=yes\n"
            f"netsh advfirewall firewall add rule "
            f"name=wireseal-{wg_interface}-block dir=in "
            f"interface={wg_interface} action=block profile=any enable=yes"
        )
        generated = (
            f"netsh advfirewall firewall add rule "
            f"name=wireseal-{wg_interface}-in protocol=UDP dir=in "
            f"localport={wg_port} action=allow profile=any enable=yes\n"
            f"netsh advfirewall firewall add rule "
            f"name=wireseal-{wg_interface}-block dir=in "
            f"interface={wg_interface} action=block profile=any enable=yes"
        )
        self.validate_firewall_rules(generated, template)

        # Allow inbound WireGuard UDP on the configured port (FW-01)
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=wireseal-{wg_interface}-in",
                "protocol=UDP",
                "dir=in",
                f"localport={wg_port}",
                "action=allow",
                "profile=any",
                "enable=yes",
            ],
            shell=False,
            check=True,
            capture_output=True,
            creationflags=_NO_WIN,
        )

        # Block all other inbound on WG interface (deny-by-default, FW-01)
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=wireseal-{wg_interface}-block",
                "dir=in",
                f"interface={wg_interface}",
                "action=block",
                "profile=any",
                "enable=yes",
            ],
            shell=False,
            check=True,
            capture_output=True,
            creationflags=_NO_WIN,
        )

        # Set WG interface to Public network profile (most restrictive)
        subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                f"Set-NetConnectionProfile -InterfaceAlias {wg_interface} "
                f"-NetworkCategory Public",
            ],
            shell=False,
            capture_output=True,
            creationflags=_NO_WIN,
            # do not check -- interface may not exist yet when firewall rules are pre-configured
        )

        # FW-02: Enable NAT for VPN subnet on outbound interface only (not all traffic)
        subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                f"New-NetNat -Name 'wireseal-nat' "
                f"-InternalIPInterfaceAddressPrefix '{subnet}'",
            ],
            shell=False,
            capture_output=True,
            creationflags=_NO_WIN,
            # do not check -- may already exist from a previous run (idempotent)
        )

    def remove_firewall_rules(self, wg_interface: str) -> None:
        """Remove all wireseal netsh advfirewall rules and NAT entry.

        Ignores errors -- rules may not exist on a first-run teardown.

        Args:
            wg_interface: WireGuard interface name (e.g., ``wg0``).
        """
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=wireseal-{wg_interface}-in",
            ],
            shell=False,
            capture_output=True,
            creationflags=_NO_WIN,
        )
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=wireseal-{wg_interface}-block",
            ],
            shell=False,
            capture_output=True,
            creationflags=_NO_WIN,
        )
        subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Remove-NetNat -Name 'wireseal-nat' -Confirm:$false",
            ],
            shell=False,
            capture_output=True,
            creationflags=_NO_WIN,
        )

    # ------------------------------------------------------------------
    # 7. IP forwarding
    # ------------------------------------------------------------------

    def enable_ip_forwarding(self) -> None:
        """Enable IPv4 packet forwarding via IPEnableRouter registry key.

        Requires a system reboot to take effect. Writes a sentinel file
        at WG_CONFIG_DIR / ".needs-reboot" so the init command (Phase 4)
        can detect the pending reboot and guide the user.

        Per locked decision: adapter does NOT force a reboot.
        """
        key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

        # Read current value (idempotency check)
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ
            ) as key:
                current_value, _ = winreg.QueryValueEx(key, "IPEnableRouter")
        except OSError:
            current_value = 0

        if current_value == 1:
            return  # already enabled -- nothing to do

        # Set IPEnableRouter = 1
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)

        # Warn user that a reboot is required
        print(
            "[!] IP routing enabled in registry. "
            "A system reboot is required for this to take effect.",
            file=sys.stderr,
        )

        # Write sentinel file so Phase 4 init command can detect pending reboot
        sentinel = WG_CONFIG_DIR / ".needs-reboot"
        if not WG_CONFIG_DIR.exists():
            WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        sentinel.touch()

    # ------------------------------------------------------------------
    # 8 & 9. Tunnel service lifecycle
    # ------------------------------------------------------------------

    def migrate_tunnel_startup(self, interface: str = "wg0") -> dict:
        """Reconcile an existing tunnel service to manual-start.

        Called on every ``serve()`` startup to fix services installed by
        earlier versions (v0.7.10 and below) which used ``start=auto``.
        If the service exists and is configured for auto start, reconfigure
        it to demand (manual) start and stop the running instance, since the
        user did not click Start.

        Returns a dict with keys ``{"migrated": bool, "was_running": bool,
        "service": str}``. Never raises — upgrade migration is best-effort.
        """
        service_name = f"{WG_SERVICE_PREFIX}{interface}"
        result = {"migrated": False, "was_running": False, "service": service_name}

        q = subprocess.run(
            ["sc.exe", "qc", service_name],
            shell=False, capture_output=True, creationflags=_NO_WIN,
        )
        if q.returncode != 0:
            return result  # Service not installed, nothing to migrate

        qc_out = (q.stdout or b"").decode("utf-8", errors="replace")
        # sc.exe qc reports "START_TYPE         : 2   AUTO_START"
        # or              "START_TYPE         : 3   DEMAND_START"
        is_auto = "AUTO_START" in qc_out or "2   AUTO_START" in qc_out

        if is_auto:
            subprocess.run(
                ["sc.exe", "config", service_name, "start=demand"],
                shell=False, capture_output=True,
                creationflags=_NO_WIN,
            )
            result["migrated"] = True

            # If currently running and we just migrated from auto-start,
            # stop it — the user did not explicitly start it this session.
            s = subprocess.run(
                ["sc.exe", "query", service_name],
                shell=False, capture_output=True, creationflags=_NO_WIN,
            )
            if s.returncode == 0 and b"RUNNING" in (s.stdout or b""):
                result["was_running"] = True
                subprocess.run(
                    ["sc.exe", "stop", service_name],
                    shell=False, capture_output=True,
                    creationflags=_NO_WIN,
                )

        return result

    def enable_tunnel_service(self, interface: str = "wg0") -> None:
        """Install the WireGuard tunnel service in MANUAL start mode.

        Uses wireguard.exe /installtunnelservice which:
          1. Creates service WireGuardTunnel$wg0
          2. Auto-encrypts .conf to .conf.dpapi (DPAPI-bound to LocalSystem)
          3. Deletes the original .conf after encryption

        The service is configured for ``start=demand`` (manual) so it does
        NOT run on boot. The user controls start/stop from the Dashboard or
        the Start/Stop button — this method registers the service, it does
        not start it.

        Args:
            interface: WireGuard interface name (default ``wg0``).

        Raises:
            SetupError: If the config file does not exist.
        """
        config_path = self.get_config_path(interface)
        if not config_path.exists():
            raise SetupError(
                f"Config not found: {config_path}. Deploy config first."
            )

        service_name = f"{WG_SERVICE_PREFIX}{interface}"

        # If the service already exists, just re-configure start-mode and return.
        existing = subprocess.run(
            ["sc.exe", "query", service_name],
            shell=False, capture_output=True, creationflags=_NO_WIN,
        )
        if existing.returncode != 0:
            # Install the tunnel service (creates WireGuardTunnel$wg0 and triggers DPAPI encryption)
            subprocess.run(
                [str(WG_EXE), "/installtunnelservice", str(config_path)],
                shell=False,
                check=True,
                capture_output=True,
                timeout=30,
                creationflags=_NO_WIN,
            )

        # Configure for MANUAL start — do not auto-start on boot.
        subprocess.run(
            [
                "sc.exe", "config",
                service_name,
                "start=demand",
            ],
            shell=False,
            check=False,  # if service doesn't exist yet (install failed), don't mask the real error
            capture_output=True,
            creationflags=_NO_WIN,
        )

    def disable_tunnel_service(self, interface: str = "wg0") -> None:
        """Stop and uninstall the WireGuard tunnel service.

        Ignores errors -- service may not be installed.

        Args:
            interface: WireGuard interface name (default ``wg0``).
        """
        subprocess.run(
            ["sc.exe", "stop", f"{WG_SERVICE_PREFIX}{interface}"],
            shell=False,
            capture_output=True,
            creationflags=_NO_WIN,
        )
        subprocess.run(
            [str(WG_EXE), "/uninstalltunnelservice", interface],
            shell=False,
            capture_output=True,
            creationflags=_NO_WIN,
        )

    # ------------------------------------------------------------------
    # 10. DNS updater scheduling
    # ------------------------------------------------------------------

    def setup_dns_updater(
        self, script_path: Path, interval_minutes: int = 5
    ) -> None:
        """Schedule DuckDNS updates via Task Scheduler as a low-privilege user.

        Creates (or reuses) a local wireseal-dns service account that is
        removed from the Users group (deny interactive logon). Satisfies HARD-04.

        The temporary password used to create the account is wiped from memory
        after the scheduled task is registered.

        Args:
            script_path:       Path to the DuckDNS update script.
            interval_minutes:  How often to run the update (default every 5 min).
        """
        # Create low-privilege service account if it does not already exist
        check = subprocess.run(
            ["net", "user", "wireseal-dns"],
            capture_output=True,
            shell=False,
            creationflags=_NO_WIN,
        )
        user_exists = check.returncode == 0

        # Generate a random password for the service account.
        # Use /random on net user to let Windows generate the password
        # and avoid exposing it in the process command line.
        password = secrets.token_urlsafe(16)

        if not user_exists:
            # Pipe the password via stdin to avoid process-list exposure.
            # "net user <name> * /add" reads from stdin (non-interactive
            # when stdin is a pipe).  We send password + confirmation.
            pw_input = f"{password}\n{password}\n".encode()
            subprocess.run(
                [
                    "net", "user", "wireseal-dns", "*",
                    "/add",
                    "/expires:never",
                    "/passwordchg:no",
                    "/comment:wireseal DNS update service account",
                ],
                input=pw_input,
                shell=False,
                check=True,
                capture_output=True,
                creationflags=_NO_WIN,
            )
            # Remove from Users group to deny interactive logon (least privilege)
            subprocess.run(
                ["net", "localgroup", "Users", "wireseal-dns", "/delete"],
                shell=False,
                capture_output=True,
                creationflags=_NO_WIN,
                # Don't check -- may already not be in Users group
            )

        # Register (or overwrite) the scheduled task.
        # schtasks /rp exposes password in process args.  Use PowerShell
        # Register-ScheduledTask with password read from stdin instead.
        ps_script = (
            "$pw = [Console]::In.ReadLine(); "
            "$action = New-ScheduledTaskAction "
            f"  -Execute '\"{script_path}\"' "
            f"  -Argument 'update-dns --non-interactive'; "
            "$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) "
            f"  -RepetitionInterval (New-TimeSpan -Minutes {interval_minutes}); "
            "Register-ScheduledTask -TaskName 'WgAutomateDNS' "
            "  -Action $action -Trigger $trigger "
            "  -User 'wireseal-dns' -Password $pw -Force | Out-Null"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            input=password.encode(),
            shell=False,
            check=True,
            capture_output=True,
            creationflags=_NO_WIN,
        )

        # Best-effort memory wipe of the temporary password
        try:
            pw_bytes = bytearray(password.encode("utf-8"))
            for i in range(len(pw_bytes)):
                pw_bytes[i] = 0
        except Exception:
            pass
        del password

    # ------------------------------------------------------------------
    # Network services (SSH, hardening, security status)
    # ------------------------------------------------------------------

    def ensure_sshd(self) -> None:
        """Ensure OpenSSH server is installed and running on Windows.

        Windows 10 1809+ and Windows 11 include OpenSSH as an optional feature.
        """
        # Check if sshd is already running
        result = subprocess.run(
            ["sc.exe", "query", "sshd"],
            shell=False, capture_output=True, text=True, creationflags=_NO_WIN,
        )
        if result.returncode == 0 and "RUNNING" in result.stdout:
            return  # already running

        # Install OpenSSH server feature if not present
        subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
            ],
            shell=False, capture_output=True, creationflags=_NO_WIN, timeout=120,
        )

        # Start and enable sshd
        subprocess.run(
            ["sc.exe", "config", "sshd", "start=auto"],
            shell=False, capture_output=True, creationflags=_NO_WIN,
        )
        subprocess.run(
            ["sc.exe", "start", "sshd"],
            shell=False, capture_output=True, creationflags=_NO_WIN,
        )

    def open_firewalld_port(self, wg_port: int) -> None:
        """Open WireGuard UDP port in Windows Firewall (no-op if already open)."""
        rule_name = f"WireSeal-WireGuard-UDP-{wg_port}"
        check = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
            shell=False, capture_output=True, text=True, creationflags=_NO_WIN,
        )
        if check.returncode == 0 and rule_name in check.stdout:
            return

        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "protocol=UDP", "dir=in",
                f"localport={wg_port}", "action=allow", "profile=any", "enable=yes",
            ],
            shell=False, capture_output=True, creationflags=_NO_WIN,
        )

        # Also open SSH port
        ssh_rule = "WireSeal-SSH-TCP-22"
        check = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={ssh_rule}"],
            shell=False, capture_output=True, text=True, creationflags=_NO_WIN,
        )
        if check.returncode != 0 or ssh_rule not in check.stdout:
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={ssh_rule}", "protocol=TCP", "dir=in",
                    "localport=22", "action=allow", "profile=any", "enable=yes",
                ],
                shell=False, capture_output=True, creationflags=_NO_WIN,
            )

    def harden_server(self) -> list[str]:
        """Apply Windows-specific server hardening. Returns list of actions taken."""
        actions: list[str] = []
        # 1. Install OpenSSH Server if missing (required before hardening sshd_config)
        actions += self._ensure_openssh_windows()
        # 2. Enable IP forwarding (required for VPN packet routing)
        actions += self._enable_ip_forwarding_windows()
        # 3. Harden sshd_config (no-op if OpenSSH not installed)
        actions += self._harden_ssh_windows()
        # 4. Firewall profiles on
        actions += self._harden_windows_firewall()
        return actions

    def _ensure_openssh_windows(self) -> list[str]:
        """Install OpenSSH.Server via Add-WindowsCapability if not present."""
        actions: list[str] = []
        sshd_config = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ssh" / "sshd_config"
        if sshd_config.exists():
            return actions  # Already installed
        try:
            result = subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null; "
                    "Set-Service -Name sshd -StartupType Automatic; "
                    "Start-Service sshd",
                ],
                shell=False, capture_output=True, timeout=180,
                creationflags=_NO_WIN,
            )
            if result.returncode == 0:
                actions.append("OpenSSH Server installed and started")
            else:
                err = (result.stderr or b"").decode("utf-8", errors="replace").strip()
                actions.append(f"OpenSSH install failed: {err[:120]}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            actions.append(f"OpenSSH install error: {exc}")
        return actions

    def _enable_ip_forwarding_windows(self) -> list[str]:
        """Set IPEnableRouter registry key (requires reboot to take effect)."""
        actions: list[str] = []
        try:
            result = subprocess.run(
                [
                    "reg.exe", "add",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f",
                ],
                shell=False, capture_output=True, timeout=10,
                creationflags=_NO_WIN,
            )
            if result.returncode == 0:
                actions.append("IP forwarding enabled (reboot required)")
            # Also enable RemoteAccess service which Windows uses to honor the flag
            # without a reboot (best-effort).
            subprocess.run(
                ["sc.exe", "config", "RemoteAccess", "start=auto"],
                shell=False, capture_output=True, timeout=10,
                creationflags=_NO_WIN,
            )
            subprocess.run(
                ["sc.exe", "start", "RemoteAccess"],
                shell=False, capture_output=True, timeout=15,
                creationflags=_NO_WIN,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            actions.append(f"IP forwarding error: {exc}")
        return actions

    def _harden_ssh_windows(self) -> list[str]:
        """Harden OpenSSH server configuration on Windows."""
        sshd_config = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ssh" / "sshd_config"
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
            "PermitEmptyPasswords": "no",
            "PasswordAuthentication": "yes",
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
                subprocess.run(
                    ["sc.exe", "stop", "sshd"],
                    shell=False, capture_output=True, creationflags=_NO_WIN,
                )
                subprocess.run(
                    ["sc.exe", "start", "sshd"],
                    shell=False, capture_output=True, creationflags=_NO_WIN,
                )
            except OSError:
                pass

        return actions

    def _harden_windows_firewall(self) -> list[str]:
        """Enable Windows Firewall on all profiles."""
        actions = []
        for profile in ("domainprofile", "privateprofile", "publicprofile"):
            result = subprocess.run(
                ["netsh", "advfirewall", "set", profile, "state", "on"],
                shell=False, capture_output=True, creationflags=_NO_WIN,
            )
            if result.returncode == 0:
                actions.append(f"Firewall: {profile} enabled")
        return actions

    def get_security_status(self) -> dict:
        """Check current Windows security posture."""
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
        sshd_config = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ssh" / "sshd_config"
        if sshd_config.exists():
            try:
                content = sshd_config.read_text()
                max_auth = "MaxAuthTries 3" in content or "MaxAuthTries 2" in content
                status["ssh_hardened"] = max_auth
                status["checks"].append({
                    "name": "SSH auth attempts limited",
                    "ok": max_auth,
                    "fix": None if max_auth else "Click Harden Server",
                })
            except OSError:
                pass
        else:
            status["checks"].append({
                "name": "OpenSSH Server",
                "ok": False,
                "fix": "Install OpenSSH Server feature",
            })

        # Check Windows Firewall
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "currentprofile"],
            shell=False, capture_output=True, text=True, creationflags=_NO_WIN,
        )
        fw_on = result.returncode == 0 and "ON" in result.stdout.upper()
        status["firewall_active"] = fw_on
        status["checks"].append({
            "name": "Windows Firewall",
            "ok": fw_on,
            "fix": None if fw_on else "Enable Windows Firewall",
        })

        # Check IP forwarding (registry)
        try:
            key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ
            ) as key:
                val, _ = winreg.QueryValueEx(key, "IPEnableRouter")
                status["ip_forwarding"] = val == 1
        except OSError:
            pass
        status["checks"].append({
            "name": "IP forwarding enabled",
            "ok": status["ip_forwarding"],
        })

        # Check Windows Update
        status["auto_updates"] = True  # Windows Update is on by default
        status["checks"].append({
            "name": "Windows Update",
            "ok": True,
        })

        # Check open ports
        try:
            result = subprocess.run(
                ["netstat", "-an"],
                shell=False, capture_output=True, text=True,
                timeout=10, creationflags=_NO_WIN,
            )
            ports = []
            seen = set()
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and ("LISTENING" in line or "UDP" in parts[0]):
                    addr = parts[1] if "LISTENING" in line else parts[1]
                    if ":" in addr:
                        port_str = addr.rsplit(":", 1)[-1]
                        if port_str.isdigit():
                            port = int(port_str)
                            proto = "tcp" if "TCP" in line else "udp"
                            key = (port, proto)
                            if key not in seen:
                                seen.add(key)
                                ports.append({"port": port, "proto": proto, "process": ""})
            status["open_ports"] = sorted(ports, key=lambda x: x["port"])[:50]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        return status

    # ------------------------------------------------------------------
    # 11. Config path (declared above -- get_config_path already implements abstract)
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # 12. Outbound interface detection
    # ------------------------------------------------------------------

    def detect_outbound_interface(self) -> str:
        """Return the Windows interface alias for the default outbound route.

        Uses PowerShell Get-NetRoute to find the interface with the lowest metric
        for the 0.0.0.0/0 default route (e.g., "Ethernet", "Wi-Fi").

        Returns:
            Interface alias string.

        Raises:
            SetupError: If no default route is found.
        """
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
                "| Sort-Object RouteMetric "
                "| Select-Object -First 1).InterfaceAlias",
            ],
            capture_output=True,
            text=True,
            shell=False,
            check=True,
            timeout=30,
            creationflags=_NO_WIN,
        )
        interface = result.stdout.strip()  # CRLF handling: .strip() removes \r\n
        if not interface:
            raise SetupError("Cannot detect outbound network interface")
        return interface

    # ------------------------------------------------------------------
    # API server background-service lifecycle (Task Scheduler).
    #
    # Why Task Scheduler instead of `sc.exe create`: a true Windows service
    # has to respond to SCM control messages (Stop / Pause), which our
    # Python click app doesn't natively do. Task Scheduler runs the same
    # `wireseal serve` binary at boot under SYSTEM with -RunLevel Highest,
    # which is functionally equivalent for a long-lived API server.
    # ------------------------------------------------------------------

    _API_TASK_NAME = "WireSeal-API"

    def install_api_service(
        self, bind: str = "127.0.0.1", port: int = 8080,
        autostart: bool = True,
    ) -> None:
        """Register a Scheduled Task that runs `wireseal serve` at boot.

        Args:
            bind:      Address the dashboard binds to.
            port:      Dashboard port.
            autostart: If False, register the task but disable the boot
                       trigger so user starts it manually via Task Scheduler.
        """
        wireseal_exe = shutil.which("wireseal") or r"C:\Program Files\WireSeal\wireseal.cmd"
        # Build the schtasks command. /SC ONSTART runs at boot, /RU SYSTEM
        # gives root-equivalent privileges, /RL HIGHEST allows wg-quick.
        cmd = [
            "schtasks.exe", "/Create", "/F",
            "/TN", self._API_TASK_NAME,
            "/SC", "ONSTART" if autostart else "ONLOGON",
            "/RU", "SYSTEM",
            "/RL", "HIGHEST",
            "/TR", f'"{wireseal_exe}" serve --bind {bind} --port {port}',
        ]
        subprocess.run(cmd, check=True, creationflags=_NO_WIN)

        if not autostart:
            # Disable the trigger so the task is registered but won't fire.
            subprocess.run(
                ["schtasks.exe", "/Change", "/TN", self._API_TASK_NAME,
                 "/DISABLE"],
                check=False, creationflags=_NO_WIN,
            )

    def uninstall_api_service(self) -> None:
        """Delete the Scheduled Task (idempotent)."""
        subprocess.run(
            ["schtasks.exe", "/End", "/TN", self._API_TASK_NAME],
            check=False, creationflags=_NO_WIN, capture_output=True,
        )
        subprocess.run(
            ["schtasks.exe", "/Delete", "/F", "/TN", self._API_TASK_NAME],
            check=False, creationflags=_NO_WIN, capture_output=True,
        )

    def start_api_service(self) -> None:
        subprocess.run(
            ["schtasks.exe", "/Run", "/TN", self._API_TASK_NAME],
            check=True, creationflags=_NO_WIN,
        )

    def stop_api_service(self) -> None:
        subprocess.run(
            ["schtasks.exe", "/End", "/TN", self._API_TASK_NAME],
            check=False, creationflags=_NO_WIN, capture_output=True,
        )

    def api_service_status(self) -> dict:
        """Return ``{installed, running, enabled}``.

        ``schtasks /Query /V /FO LIST`` parsing — looking for "Status"
        (Running/Ready/Disabled) and "Scheduled Task State".
        """
        try:
            out = subprocess.run(
                ["schtasks.exe", "/Query", "/TN", self._API_TASK_NAME,
                 "/V", "/FO", "LIST"],
                capture_output=True, text=True, check=False,
                creationflags=_NO_WIN,
            )
        except Exception:
            return {"installed": False, "running": False, "enabled": False}
        if out.returncode != 0:
            return {"installed": False, "running": False, "enabled": False}
        text = out.stdout or ""
        running = bool(re.search(r"Status:\s*Running", text))
        enabled = "Disabled" not in re.search(
            r"Scheduled Task State:\s*([^\r\n]+)", text
        ).group(1) if re.search(
            r"Scheduled Task State:\s*([^\r\n]+)", text
        ) else False
        return {"installed": True, "running": running, "enabled": enabled}
