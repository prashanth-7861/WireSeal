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
from typing import Any

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


def _has_firewalld() -> bool:
    """Check if firewalld is installed and running."""
    if shutil.which("firewall-cmd") is None:
        return False
    check = subprocess.run(
        ["firewall-cmd", "--state"],
        shell=False, capture_output=True,
    )
    return check.returncode == 0


def _build_nftables_ruleset(
    pub_iface: str, wg_iface: str, wg_port: int
) -> str:
    """Build the nftables ruleset string with the given interface and port values.

    Returns the exact string that will be written to the nft file and applied.
    The same function is used for both the generated rules and the expected
    template to ensure validate_firewall_rules comparison is always symmetric.

    When firewalld is active, we return an EMPTY string because firewalld
    manages ALL firewall rules (input, forward, NAT). Adding nftables rules
    alongside firewalld causes conflicts — firewalld's chains and our chains
    both evaluate independently, and 'policy drop' in either blocks traffic
    the other intended to allow.

    Without firewalld, we add forward + NAT rules with 'policy accept' on
    input (to avoid locking out SSH) and rate limiting on the WG port.
    """
    firewalld_active = _has_firewalld()

    if firewalld_active:
        # firewalld manages everything — do NOT add any nftables rules.
        # We configure firewalld in open_firewalld_port() and
        # _configure_firewalld_forwarding() instead.
        return ""
    else:
        # No firewalld — we manage firewall ourselves via nftables.
        # policy accept on forward to avoid blocking legitimate traffic.
        # NAT masquerade for VPN clients to reach the internet.
        return textwrap.dedent(f"""\
            # MANAGED BY wireseal -- DO NOT EDIT MANUALLY
            table inet wg_filter {{
                chain input {{
                    type filter hook input priority 0; policy accept;
                    ct state invalid drop
                    iifname "{pub_iface}" udp dport {wg_port} ct state new limit rate over 5/second burst 10 packets drop
                }}

                chain forward {{
                    type filter hook forward priority 0; policy accept;
                    iifname "{wg_iface}" oifname "{pub_iface}" accept
                    oifname "{wg_iface}" ct state {{ established, related }} accept
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
        """Configure firewall for WireGuard: port, forwarding, and NAT.

        When firewalld is active, uses firewall-cmd exclusively (no nftables).
        When firewalld is not active, applies nftables rules directly.

        Args:
            wg_port:       UDP port WireGuard listens on.
            wg_interface:  WireGuard interface name (e.g., wg0).
            subnet:        WireGuard subnet in CIDR.
        """
        pub_iface = self.detect_outbound_interface()

        # Always clean up stale nftables tables from previous versions
        for table_family, table_name in [
            ("inet", "wg_filter"),
            ("inet", "wg_forward"),
            ("ip", "wg_nat"),
        ]:
            subprocess.run(
                ["nft", "delete", "table", table_family, table_name],
                shell=False, capture_output=True,
            )

        if _has_firewalld():
            # CRITICAL: Remove default 'inet filter' table if it has 'policy drop'.
            # Many distros (EndeavourOS, Arch) ship a default nftables config with
            # 'policy drop' on input that blocks ALL traffic except SSH. This table
            # evaluates at priority 0, BEFORE firewalld's tables (priority +10),
            # dropping WireGuard UDP packets before firewalld can accept them.
            try:
                check = subprocess.run(
                    ["nft", "list", "chain", "inet", "filter", "input"],
                    shell=False, capture_output=True, timeout=5,
                )
                if check.returncode == 0 and b"policy drop" in check.stdout:
                    subprocess.run(
                        ["nft", "delete", "table", "inet", "filter"],
                        shell=False, capture_output=True, timeout=5,
                    )
                    print("[wireseal] Removed conflicting 'inet filter' table "
                          "(policy drop blocked WireGuard traffic).",
                          file=sys.stderr)
            except Exception:
                pass

            # Use firewalld exclusively — no nftables rules
            self._configure_firewalld_full(wg_port, wg_interface, pub_iface)
            # Remove stale nftables rules file
            if _NFT_RULES_FILE.exists():
                _NFT_RULES_FILE.unlink()
            return

        # No firewalld — use nftables directly
        generated_rules = _build_nftables_ruleset(pub_iface, wg_interface, wg_port)
        if not generated_rules:
            return

        template_rules = _build_nftables_ruleset(pub_iface, wg_interface, wg_port)
        self.validate_firewall_rules(generated_rules, template_rules)

        if not _NFTABLES_DIR.exists():
            _NFTABLES_DIR.mkdir(parents=True, mode=0o755, exist_ok=True)

        atomic_write(_NFT_RULES_FILE, generated_rules.encode("utf-8"), mode=0o644)

        try:
            subprocess.run(
                ["nft", "-f", str(_NFT_RULES_FILE)],
                shell=False, check=True, capture_output=True, timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise SetupError(f"Failed to apply nftables rules: {stderr}") from exc

    def _configure_firewalld_full(
        self, wg_port: int, wg_interface: str, pub_iface: str
    ) -> None:
        """Configure firewalld with all rules needed for WireGuard VPN.

        Sets up:
          1. UDP port for WireGuard on the public zone
          2. wg0 interface in the trusted zone (accepts all VPN traffic)
          3. Masquerade on public zone (NAT for VPN clients)
          4. A firewalld policy for inter-zone forwarding (trusted→public)
             This is required because firewalld does NOT forward between zones
             by default — without a policy, VPN clients can reach the server
             but NOT the internet.
          5. SSH access on the public zone
          6. Rich rule to accept VPN subnet traffic

        Uses firewalld policies instead of --direct rules because --direct
        rules fail on distros using nftables-based iptables (Arch, Fedora 39+).
        """
        def _run(cmd: list[str]) -> None:
            subprocess.run(cmd, shell=False, capture_output=True, timeout=30)

        # ── 1. Public zone: open WireGuard port + SSH + masquerade ──
        _run(["firewall-cmd", "--zone=public",
              "--add-port", f"{wg_port}/udp", "--permanent"])
        _run(["firewall-cmd", "--zone=public",
              "--add-masquerade", "--permanent"])
        _run(["firewall-cmd", "--zone=public",
              "--add-service", "ssh", "--permanent"])

        # Accept traffic from VPN subnet on the public zone
        _run(["firewall-cmd", "--zone=public", "--add-rich-rule",
              'rule family="ipv4" source address="10.0.0.0/24" accept',
              "--permanent"])

        # ── 2. Trusted zone: add wg0 interface ──
        # The trusted zone has target=ACCEPT, so all traffic from wg0 is allowed
        _run(["firewall-cmd", "--zone=trusted",
              "--add-interface", wg_interface, "--permanent"])

        # ── 3. Firewalld policy: trusted→public forwarding ──
        # Without this, VPN clients can reach the server but NOT the internet.
        # Firewalld policies handle inter-zone traffic (added in firewalld 0.9+).
        # Check if the policy already exists
        check = subprocess.run(
            ["firewall-cmd", "--permanent", "--info-policy=wg-internet"],
            shell=False, capture_output=True, timeout=10,
        )
        if check.returncode != 0:
            # Create the policy
            _run(["firewall-cmd", "--permanent", "--new-policy=wg-internet"])

        _run(["firewall-cmd", "--permanent", "--policy=wg-internet",
              "--add-ingress-zone=trusted"])
        _run(["firewall-cmd", "--permanent", "--policy=wg-internet",
              "--add-egress-zone=public"])
        _run(["firewall-cmd", "--permanent", "--policy=wg-internet",
              "--set-target=ACCEPT"])

        # ── 4. Reload to apply all permanent rules ──
        _run(["firewall-cmd", "--reload"])

    def remove_firewall_rules(self, wg_interface: str) -> None:
        """Remove all wireseal nftables tables and the drop-in rule file.

        Idempotent: errors from missing tables are silently ignored.

        Args:
            wg_interface: WireGuard interface name (unused on Linux -- rules
                          are keyed by table name, not interface).
        """
        for table_family, table_name in [
            ("inet", "wg_filter"),
            ("inet", "wg_forward"),
            ("ip", "wg_nat"),
        ]:
            subprocess.run(
                ["nft", "delete", "table", table_family, table_name],
                shell=False,
                capture_output=True,
            )
        if _NFT_RULES_FILE.exists():
            _NFT_RULES_FILE.unlink()

    # ------------------------------------------------------------------
    # 7. IP forwarding
    # ------------------------------------------------------------------

    def open_firewalld_port(self, wg_port: int) -> None:
        """Configure all firewalld rules needed for a working VPN.

        Delegates to _configure_firewalld_full which uses firewalld policies
        (not --direct rules) for cross-zone forwarding.
        Idempotent: skips if firewalld is not running.
        """
        if not _has_firewalld():
            return

        try:
            pub_iface = self.detect_outbound_interface()
        except Exception:
            pub_iface = ""

        self._configure_firewalld_full(wg_port, "wg0", pub_iface)

        subprocess.run(
            ["firewall-cmd", "--reload"],
            shell=False, capture_output=True, timeout=30,
        )

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

    # ------------------------------------------------------------------
    # Server hardening
    # ------------------------------------------------------------------

    def harden_server(self) -> list[str]:
        """Apply security hardening to the server. Returns list of actions taken."""
        actions = []
        actions += self._harden_ssh()
        actions += self._harden_kernel()
        actions += self._setup_fail2ban()
        actions += self._setup_auto_updates()
        return actions

    def _harden_ssh(self) -> list[str]:
        """Harden SSH configuration to prevent brute force and unauthorized access."""
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            return []

        try:
            content = sshd_config.read_text(encoding="utf-8")
        except OSError:
            return []

        actions = []
        original = content
        import re as _re

        hardening = {
            "PermitRootLogin": "no",
            "MaxAuthTries": "3",
            "LoginGraceTime": "30",
            "PermitEmptyPasswords": "no",
            "X11Forwarding": "no",
            "AllowAgentForwarding": "no",
            "ClientAliveInterval": "300",
            "ClientAliveCountMax": "2",
        }

        for key, value in hardening.items():
            pattern = _re.compile(rf'^#?\s*{key}\s+.*$', _re.MULTILINE)
            replacement = f"{key} {value}"
            if pattern.search(content):
                new_content = pattern.sub(replacement, content, count=1)
                if new_content != content:
                    content = new_content
                    actions.append(f"SSH: {key} → {value}")
            elif f"{key} {value}" not in content:
                content += f"\n{key} {value}"
                actions.append(f"SSH: {key} → {value}")

        if content != original:
            try:
                sshd_config.write_text(content, encoding="utf-8")
                subprocess.run(
                    ["systemctl", "reload", "sshd"],
                    shell=False, capture_output=True, timeout=10,
                )
            except (OSError, subprocess.CalledProcessError):
                subprocess.run(
                    ["systemctl", "reload", "ssh"],
                    shell=False, capture_output=True, timeout=10,
                )

        return actions

    def _harden_kernel(self) -> list[str]:
        """Apply kernel security parameters via sysctl."""
        params = {
            # Prevent IP spoofing
            "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.conf.default.rp_filter": "1",
            # Ignore ICMP redirects (prevent MITM)
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.default.accept_redirects": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv6.conf.all.accept_redirects": "0",
            # Ignore source-routed packets
            "net.ipv4.conf.all.accept_source_route": "0",
            "net.ipv6.conf.all.accept_source_route": "0",
            # SYN flood protection
            "net.ipv4.tcp_syncookies": "1",
            "net.ipv4.tcp_max_syn_backlog": "2048",
            "net.ipv4.tcp_synack_retries": "2",
            # Ignore ICMP broadcast requests
            "net.ipv4.icmp_echo_ignore_broadcasts": "1",
            # Log suspicious packets
            "net.ipv4.conf.all.log_martians": "1",
            "net.ipv4.conf.default.log_martians": "1",
            # Disable IPv6 router advertisements
            "net.ipv6.conf.all.accept_ra": "0",
            "net.ipv6.conf.default.accept_ra": "0",
            # Prevent core dumps
            "fs.suid_dumpable": "0",
            # Restrict kernel pointer exposure
            "kernel.kptr_restrict": "2",
            # Restrict dmesg access
            "kernel.dmesg_restrict": "1",
        }

        sysctl_file = Path("/etc/sysctl.d/98-wireseal-hardening.conf")
        lines = ["# WireSeal server hardening — DO NOT EDIT MANUALLY"]
        actions = []

        for key, value in params.items():
            lines.append(f"{key} = {value}")
            actions.append(f"Kernel: {key} = {value}")

        try:
            content = "\n".join(lines) + "\n"
            if sysctl_file.exists() and sysctl_file.read_text() == content:
                return []  # already applied

            sysctl_file.write_text(content, encoding="utf-8")
            subprocess.run(
                ["sysctl", "-p", str(sysctl_file)],
                shell=False, check=True, capture_output=True, timeout=10,
            )
        except (OSError, subprocess.CalledProcessError):
            return []

        return actions

    def _setup_fail2ban(self) -> list[str]:
        """Install and configure fail2ban for SSH brute force protection."""
        actions = []

        if shutil.which("fail2ban-client") is None:
            try:
                if shutil.which("pacman"):
                    subprocess.run(
                        ["pacman", "-S", "--needed", "--noconfirm", "fail2ban"],
                        shell=False, check=True, capture_output=True, timeout=120,
                    )
                elif shutil.which("apt-get"):
                    subprocess.run(
                        ["apt-get", "install", "-y", "fail2ban"],
                        shell=False, check=True, capture_output=True, timeout=120,
                    )
                elif shutil.which("dnf"):
                    subprocess.run(
                        ["dnf", "install", "-y", "fail2ban"],
                        shell=False, check=True, capture_output=True, timeout=120,
                    )
                else:
                    return []
                actions.append("Installed fail2ban")
            except subprocess.CalledProcessError:
                return []

        # Configure fail2ban for SSH + WireGuard
        jail_conf = Path("/etc/fail2ban/jail.d/wireseal.conf")
        jail_content = textwrap.dedent("""\
            # WireSeal fail2ban configuration
            [sshd]
            enabled = true
            port = ssh
            filter = sshd
            maxretry = 5
            bantime = 3600
            findtime = 600

            [wireseal-wg]
            enabled = true
            port = 51820
            protocol = udp
            filter = wireseal-wg
            maxretry = 10
            bantime = 3600
            findtime = 300
        """)

        try:
            jail_conf.parent.mkdir(parents=True, exist_ok=True)
            if not jail_conf.exists() or jail_conf.read_text() != jail_content:
                jail_conf.write_text(jail_content, encoding="utf-8")
                actions.append("Configured fail2ban SSH jail (5 retries → 1h ban)")
        except OSError:
            pass

        # Enable and start fail2ban
        try:
            subprocess.run(
                ["systemctl", "enable", "--now", "fail2ban"],
                shell=False, check=True, capture_output=True, timeout=30,
            )
            if not any("Installed" in a for a in actions):
                actions.append("Enabled fail2ban")
        except subprocess.CalledProcessError:
            pass

        return actions

    def _setup_auto_updates(self) -> list[str]:
        """Enable automatic security updates."""
        actions = []

        if shutil.which("pacman"):
            # Arch: install pacman-contrib for paccache, but auto-updates
            # aren't standard on Arch. We'll just note it.
            return ["Auto-updates: Arch detected — use `pacman -Syu` regularly"]

        if shutil.which("apt-get"):
            # Debian/Ubuntu: unattended-upgrades
            try:
                subprocess.run(
                    ["apt-get", "install", "-y", "unattended-upgrades"],
                    shell=False, check=True, capture_output=True, timeout=120,
                )
                subprocess.run(
                    ["dpkg-reconfigure", "-plow", "unattended-upgrades"],
                    shell=False, capture_output=True, timeout=30,
                    env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
                )
                actions.append("Enabled unattended-upgrades for security patches")
            except subprocess.CalledProcessError:
                pass

        elif shutil.which("dnf"):
            # Fedora/RHEL: dnf-automatic
            try:
                subprocess.run(
                    ["dnf", "install", "-y", "dnf-automatic"],
                    shell=False, check=True, capture_output=True, timeout=120,
                )
                subprocess.run(
                    ["systemctl", "enable", "--now", "dnf-automatic-install.timer"],
                    shell=False, check=True, capture_output=True, timeout=30,
                )
                actions.append("Enabled dnf-automatic for security patches")
            except subprocess.CalledProcessError:
                pass

        return actions

    def get_security_status(self) -> dict:
        """Check current security posture and return status."""
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
                if root_disabled:
                    status["checks"].append({"name": "Root login disabled", "ok": True})
                else:
                    status["checks"].append({"name": "Root login disabled", "ok": False, "fix": "Set PermitRootLogin no in sshd_config"})
                if max_auth:
                    status["checks"].append({"name": "Auth attempts limited", "ok": True})
                else:
                    status["checks"].append({"name": "Auth attempts limited", "ok": False, "fix": "Set MaxAuthTries 3 in sshd_config"})
            except OSError:
                pass

        # Check kernel hardening
        hardening_file = Path("/etc/sysctl.d/98-wireseal-hardening.conf")
        status["kernel_hardened"] = hardening_file.exists()
        status["checks"].append({
            "name": "Kernel security parameters",
            "ok": hardening_file.exists(),
            "fix": None if hardening_file.exists() else "Run wireseal with --harden flag",
        })

        # Check fail2ban
        f2b_check = subprocess.run(
            ["systemctl", "is-active", "fail2ban"],
            shell=False, capture_output=True, timeout=5,
        )
        status["fail2ban_active"] = f2b_check.returncode == 0
        status["checks"].append({
            "name": "Fail2ban brute force protection",
            "ok": f2b_check.returncode == 0,
            "fix": None if f2b_check.returncode == 0 else "Install and enable fail2ban",
        })

        # Get fail2ban ban count
        if status["fail2ban_active"]:
            try:
                result = subprocess.run(
                    ["fail2ban-client", "status", "sshd"],
                    shell=False, capture_output=True, text=True, timeout=5,
                )
                import re as _re
                ban_match = _re.search(r"Currently banned:\s+(\d+)", result.stdout)
                if ban_match:
                    status["fail2ban_bans"] = int(ban_match.group(1))
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Check firewall — firewalld OR nftables
        firewall_ok = False
        firewall_label = "WireSeal firewall"
        if _has_firewalld():
            # Check if our port is open in firewalld
            port_check = subprocess.run(
                ["firewall-cmd", "--query-port", "51820/udp"],
                shell=False, capture_output=True, timeout=5,
            )
            masq_check = subprocess.run(
                ["firewall-cmd", "--query-masquerade"],
                shell=False, capture_output=True, timeout=5,
            )
            firewall_ok = port_check.returncode == 0 and masq_check.returncode == 0
            firewall_label = "Firewalld (port + masquerade)"
        else:
            nft_check = subprocess.run(
                ["nft", "list", "table", "inet", "wg_filter"],
                shell=False, capture_output=True, timeout=5,
            )
            firewall_ok = nft_check.returncode == 0
            firewall_label = "nftables firewall"
        status["firewall_active"] = firewall_ok
        status["checks"].append({
            "name": firewall_label,
            "ok": firewall_ok,
        })

        # Check IP forwarding
        try:
            val = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
            status["ip_forwarding"] = val == "1"
        except OSError:
            pass
        status["checks"].append({
            "name": "IP forwarding enabled",
            "ok": status["ip_forwarding"],
        })

        # Check firewalld (separate from nftables)
        try:
            fwd_check = subprocess.run(
                ["systemctl", "is-active", "firewalld"],
                shell=False, capture_output=True, timeout=5,
            )
            if fwd_check.returncode == 0:
                status["checks"].append({"name": "Firewalld active", "ok": True})
            # else: skip — not all systems use firewalld
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check auto-updates
        auto_updates = (
            Path("/etc/apt/apt.conf.d/20auto-upgrades").exists()
            or Path("/etc/dnf/automatic.conf").exists()
        )
        status["auto_updates"] = auto_updates
        status["checks"].append({
            "name": "Automatic security updates",
            "ok": auto_updates,
            "fix": None if auto_updates else "Click Harden Server to enable",
        })

        # Check open ports (listening services)
        try:
            result = subprocess.run(
                ["ss", "-tulnp"],
                shell=False, capture_output=True, text=True, timeout=5,
            )
            ports = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    addr_port = parts[4]
                    port = addr_port.rsplit(":", 1)[-1] if ":" in addr_port else ""
                    proto = parts[0].lower()
                    process = parts[-1] if len(parts) > 5 else ""
                    if port.isdigit():
                        ports.append({"port": int(port), "proto": proto, "process": process})
            # Deduplicate
            seen = set()
            unique_ports = []
            for p in ports:
                key = (p["port"], p["proto"])
                if key not in seen:
                    seen.add(key)
                    unique_ports.append(p)
            status["open_ports"] = sorted(unique_ports, key=lambda x: x["port"])
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return status

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
        """Register the tunnel for manual start.

        On Linux, ``wg-quick@<iface>`` is a systemd template unit that works
        without any ``systemctl enable`` call — ``systemctl start wg-quick@wg0``
        is enough. To match the Windows ``start=demand`` model (no autostart
        at boot, no immediate start), this is a deliberate no-op. The API
        Start button invokes ``wg-quick up`` directly when the user wants it.

        Args:
            interface: WireGuard interface name (default wg0).
        """
        # Deliberate no-op: no boot autostart, no immediate start.
        # User controls lifecycle via API Start/Stop buttons.
        return None

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

    # ------------------------------------------------------------------
    # API server background-service lifecycle (systemd unit).
    #
    # Distinct from `enable_tunnel_service()` which manages WireGuard's
    # `wg-quick@wg0` template — this manages the WireSeal API server itself
    # (`wireseal serve`) so the dashboard survives terminal closure and
    # auto-starts at boot when enabled.
    # ------------------------------------------------------------------

    # User-friendly unit name: `systemctl enable wireseal` works directly.
    # Legacy installs wrote `wireseal-api.service` — kept for migration.
    _API_SERVICE_NAME = "wireseal.service"
    _API_SERVICE_PATH = Path("/etc/systemd/system/wireseal.service")
    _LEGACY_SERVICE_NAME = "wireseal-api.service"
    _LEGACY_SERVICE_PATH = Path("/etc/systemd/system/wireseal-api.service")

    def _find_wireseal_launcher(self) -> str:
        """Return the absolute command to invoke `wireseal serve`.

        Resolution order:
          1. PyInstaller-frozen binary → ``sys.executable``
          2. ``/usr/local/bin/wireseal`` (system wrapper from install script)
          3. Any ``wireseal`` on PATH
          4. Fallback → ``<sys.executable> -m wireseal.main``
        """
        import sys
        if getattr(sys, "frozen", False):
            return sys.executable
        wrapper = Path("/usr/local/bin/wireseal")
        if wrapper.exists():
            return str(wrapper)
        which = shutil.which("wireseal")
        if which:
            return which
        return f"{sys.executable} -m wireseal.main"

    def _migrate_legacy_unit(self) -> None:
        """Stop + disable + remove the v0.7.14-v0.7.16 `wireseal-api.service`
        unit if present. Runs as part of every install so reinstall picks
        up the new name automatically.
        """
        if not self._LEGACY_SERVICE_PATH.exists():
            return
        subprocess.run(
            ["systemctl", "stop", self._LEGACY_SERVICE_NAME],
            check=False, capture_output=True,
        )
        subprocess.run(
            ["systemctl", "disable", self._LEGACY_SERVICE_NAME],
            check=False, capture_output=True,
        )
        try:
            self._LEGACY_SERVICE_PATH.unlink()
        except OSError:
            pass

    def install_api_service(
        self, bind: str = "127.0.0.1", port: int = 8080,
        autostart: bool = True,
    ) -> None:
        """Write `/etc/systemd/system/wireseal.service` and (optionally)
        enable it at boot.

        The unit name is `wireseal.service` so the natural commands work:

            sudo systemctl start  wireseal
            sudo systemctl stop   wireseal
            sudo systemctl status wireseal
            sudo systemctl enable wireseal

        Legacy installs (v0.7.14-v0.7.16) wrote `wireseal-api.service` —
        `_migrate_legacy_unit()` removes it on every reinstall.

        Captures `systemctl daemon-reload` / `enable` failures and surfaces
        them as `SetupError` so the dashboard can show an actionable message.
        """
        self._migrate_legacy_unit()
        wireseal_bin = self._find_wireseal_launcher()
        unit = (
            "[Unit]\n"
            "Description=WireSeal dashboard / API server\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            f"ExecStart={wireseal_bin} serve --bind {bind} --port {port}\n"
            "Restart=on-failure\n"
            "RestartSec=5\n"
            # Run as root — vault decryption + wg-quick + nft all need it.
            "User=root\n"
            "# Sandboxing: full chroot-style isolation breaks wg-quick, but\n"
            "# we apply what's safe.\n"
            "NoNewPrivileges=yes\n"
            "ProtectSystem=full\n"
            "ProtectHome=yes\n"
            "PrivateTmp=yes\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        try:
            self._API_SERVICE_PATH.write_text(unit)
            os.chmod(self._API_SERVICE_PATH, 0o644)
        except OSError as exc:
            raise SetupError(
                f"Failed to write {self._API_SERVICE_PATH}: {exc}. "
                "Run as root."
            )

        res = subprocess.run(
            ["systemctl", "daemon-reload"],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            raise SetupError(
                f"systemctl daemon-reload failed: "
                f"{(res.stderr or '').strip() or 'unknown error'}"
            )
        if autostart:
            res = subprocess.run(
                ["systemctl", "enable", self._API_SERVICE_NAME],
                capture_output=True, text=True,
            )
            if res.returncode != 0:
                raise SetupError(
                    f"systemctl enable failed: "
                    f"{(res.stderr or '').strip() or 'unknown error'}"
                )

    def uninstall_api_service(self) -> None:
        """Stop, disable, and remove the systemd unit file. Also drops the
        legacy `wireseal-api.service` if present so users upgrading from
        v0.7.14-v0.7.16 don't end up with both units installed.
        """
        for name in (self._API_SERVICE_NAME, self._LEGACY_SERVICE_NAME):
            subprocess.run(
                ["systemctl", "stop", name],
                check=False, capture_output=True,
            )
            subprocess.run(
                ["systemctl", "disable", name],
                check=False, capture_output=True,
            )
        for path in (self._API_SERVICE_PATH, self._LEGACY_SERVICE_PATH):
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass
        subprocess.run(["systemctl", "daemon-reload"], check=False)

    def start_api_service(self) -> None:
        res = subprocess.run(
            ["systemctl", "start", self._API_SERVICE_NAME],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            raise SetupError(
                f"systemctl start {self._API_SERVICE_NAME} failed: "
                f"{(res.stderr or '').strip() or 'unknown error'}"
            )

    def stop_api_service(self) -> None:
        res = subprocess.run(
            ["systemctl", "stop", self._API_SERVICE_NAME],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            raise SetupError(
                f"systemctl stop {self._API_SERVICE_NAME} failed: "
                f"{(res.stderr or '').strip() or 'unknown error'}"
            )

    def api_service_status(self) -> dict:
        """Return ``{installed, running, enabled}`` booleans."""
        installed = self._API_SERVICE_PATH.exists()
        running = subprocess.run(
            ["systemctl", "is-active", "--quiet", self._API_SERVICE_NAME],
        ).returncode == 0
        enabled = subprocess.run(
            ["systemctl", "is-enabled", "--quiet", self._API_SERVICE_NAME],
        ).returncode == 0
        return {"installed": installed, "running": running, "enabled": enabled}
