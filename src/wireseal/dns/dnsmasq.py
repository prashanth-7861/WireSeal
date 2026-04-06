"""dnsmasq config writer and lifecycle manager for WireSeal split-DNS."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_HOSTNAME_RE = re.compile(r'^[a-z0-9][a-z0-9\-\.]{0,251}[a-z0-9]$', re.IGNORECASE)
_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def validate_hostname(hostname: str) -> None:
    """Raise ValueError if hostname is not a safe, valid DNS name."""
    if not hostname or len(hostname) > 253:
        raise ValueError(f"Invalid hostname: {hostname!r}")
    if not _HOSTNAME_RE.match(hostname):
        raise ValueError(f"Hostname contains invalid characters: {hostname!r}")
    # Explicitly reject injection vectors
    for bad in ("\n", "\r", " ", "\t", "#", "="):
        if bad in hostname:
            raise ValueError(f"Hostname contains forbidden character: {bad!r}")


def validate_ip(ip: str) -> None:
    """Raise ValueError if IP is not a valid IPv4 address."""
    if not _IPV4_RE.match(ip):
        raise ValueError(f"Invalid IPv4 address: {ip!r}")
    octets = [int(o) for o in ip.split(".")]
    if not all(0 <= o <= 255 for o in octets):
        raise ValueError(f"IPv4 octet out of range: {ip!r}")


class DnsmasqManager:
    """Manages the dnsmasq config fragment for WireSeal internal DNS mappings."""

    # Platform-specific config fragment paths
    _LINUX_CONF = Path("/etc/dnsmasq.d/wireseal.conf")
    _MACOS_RESOLVER_DIR = Path("/etc/resolver")

    def __init__(self, wg_interface: str = "wg0"):
        self.wg_interface = wg_interface

    def is_available(self) -> bool:
        """Return True if dnsmasq is installed (found in PATH)."""
        try:
            result = subprocess.run(
                ["which", "dnsmasq"] if sys.platform != "win32" else ["where", "dnsmasq"],
                capture_output=True, timeout=3,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def is_running(self) -> bool:
        """Return True if dnsmasq process is currently running."""
        try:
            result = subprocess.run(
                ["pgrep", "-x", "dnsmasq"],
                capture_output=True, timeout=3,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def write_config(self, dns_mappings: dict[str, str]) -> Path | None:
        """Write dnsmasq config fragment. Returns written path or None if unavailable."""
        if sys.platform == "darwin":
            return self._write_macos(dns_mappings)
        elif sys.platform == "win32":
            return None  # Windows: warn only, no dnsmasq
        else:
            return self._write_linux(dns_mappings)

    def _write_linux(self, dns_mappings: dict[str, str]) -> Path:
        """Write /etc/dnsmasq.d/wireseal.conf (Linux)."""
        lines = [
            f"# WireSeal split-DNS — auto-generated, do not edit manually",
            f"# Managed by wireseal serve. Reload with: sudo pkill -HUP dnsmasq",
            f"interface={self.wg_interface}",
            f"bind-interfaces",
            "",
        ]
        for hostname, ip in sorted(dns_mappings.items()):
            validate_hostname(hostname)
            validate_ip(ip)
            lines.append(f"address=/{hostname}/{ip}")
        content = "\n".join(lines) + "\n"

        conf_path = self._LINUX_CONF
        # Write via sudo tee (file is root-owned)
        try:
            proc = subprocess.run(
                ["sudo", "-n", "tee", str(conf_path)],
                input=content.encode(),
                capture_output=True, timeout=5,
            )
            if proc.returncode != 0:
                # Fall back: try direct write (running as root)
                conf_path.parent.mkdir(parents=True, exist_ok=True)
                conf_path.write_text(content)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            conf_path.parent.mkdir(parents=True, exist_ok=True)
            conf_path.write_text(content)
        return conf_path

    def _write_macos(self, dns_mappings: dict[str, str]) -> Path:
        """Write /etc/resolver/<domain> files (macOS)."""
        resolver_dir = self._MACOS_RESOLVER_DIR
        resolver_dir.mkdir(parents=True, exist_ok=True)
        # Group by TLD-style domain (last label of hostname)
        written = set()
        for hostname, ip in dns_mappings.items():
            validate_hostname(hostname)
            validate_ip(ip)
            domain = hostname.split(".")[-1]
            resolver_file = resolver_dir / domain
            resolver_file.write_text(f"nameserver {ip}\n")
            written.add(resolver_file)
        return resolver_dir

    def reload(self) -> bool:
        """Send SIGHUP to dnsmasq to reload config. Returns True on success."""
        if sys.platform == "win32":
            return False
        try:
            result = subprocess.run(
                ["sudo", "-n", "pkill", "-HUP", "dnsmasq"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def remove_config(self) -> None:
        """Remove the WireSeal dnsmasq config fragment (called on shutdown)."""
        if sys.platform == "linux":
            try:
                subprocess.run(
                    ["sudo", "-n", "rm", "-f", str(self._LINUX_CONF)],
                    capture_output=True, timeout=5,
                )
            except Exception:
                pass
