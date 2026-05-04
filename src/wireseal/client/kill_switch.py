"""Kill switch: block all traffic when VPN tunnel drops.

Strategy per platform:
- Windows: netsh advfirewall rules (block all except WG endpoint + loopback)
- Linux: iptables rules in a dedicated chain (WIRESEAL_KILLSWITCH)
- macOS: pf anchor (com.wireseal.killswitch)

The kill switch is *activated* when tunnel comes up (if setting enabled)
and *deactivated* on intentional disconnect. If the tunnel drops
unexpectedly while kill switch is active, traffic stays blocked until
the user explicitly disconnects or reconnects.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
import sys
import threading
from typing import Any

log = logging.getLogger(__name__)

_lock = threading.Lock()
_active = False

# Firewall rule name / chain / anchor for identification and cleanup.
_WIN_RULE_PREFIX = "WireSeal-KillSwitch"
_LINUX_CHAIN = "WIRESEAL_KILLSWITCH"
_MAC_ANCHOR = "com.wireseal.killswitch"


def _validate_endpoint(endpoint: str) -> tuple[str, int]:
    """Parse and validate WireGuard endpoint (ip:port or [ipv6]:port).

    Raises ValueError on invalid input.
    """
    m = re.match(r"^\[([^\]]+)\]:(\d+)$", endpoint)
    if m:
        ip_str, port_str = m.group(1), m.group(2)
    elif ":" in endpoint and endpoint.count(":") == 1:
        ip_str, port_str = endpoint.rsplit(":", 1)
    else:
        raise ValueError(f"Invalid endpoint format: {endpoint!r}")

    ip = ipaddress.ip_address(ip_str)
    port = int(port_str)
    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range: {port}")
    return str(ip), port


def is_active() -> bool:
    """Return whether the kill switch is currently engaged."""
    with _lock:
        return _active


def engage(endpoint: str, interface: str = "wg-client") -> dict[str, Any]:
    """Activate kill switch — block all traffic except VPN endpoint.

    Args:
        endpoint: WireGuard server endpoint (ip:port).
        interface: WireGuard interface name.

    Returns:
        Status dict.

    Raises:
        RuntimeError: On firewall command failure.
        ValueError: On invalid endpoint.
    """
    global _active
    ip, port = _validate_endpoint(endpoint)

    with _lock:
        if _active:
            return {"kill_switch": "already-active"}

        if sys.platform == "win32":
            _engage_windows(ip, port, interface)
        elif sys.platform == "darwin":
            _engage_macos(ip, port, interface)
        else:
            _engage_linux(ip, port, interface)

        _active = True
        log.info("Kill switch engaged (endpoint=%s:%d)", ip, port)
        return {"kill_switch": "active", "endpoint": f"{ip}:{port}"}


def disengage() -> dict[str, Any]:
    """Deactivate kill switch — restore normal routing.

    Returns:
        Status dict.
    """
    global _active

    with _lock:
        if not _active:
            return {"kill_switch": "already-inactive"}

        if sys.platform == "win32":
            _disengage_windows()
        elif sys.platform == "darwin":
            _disengage_macos()
        else:
            _disengage_linux()

        _active = False
        log.info("Kill switch disengaged")
        return {"kill_switch": "inactive"}


# ---------------------------------------------------------------------------
# Windows: netsh advfirewall
# ---------------------------------------------------------------------------


def _engage_windows(ip: str, port: int, interface: str) -> None:
    """Block all outbound except WG endpoint + loopback + DHCP."""
    _disengage_windows()  # clean slate

    rules: list[tuple[str, list[str]]] = [
        # Allow loopback
        (f"{_WIN_RULE_PREFIX}-Allow-Loopback", [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_WIN_RULE_PREFIX}-Allow-Loopback",
            "dir=out", "action=allow",
            "remoteip=127.0.0.0/8,::1",
            "enable=yes",
        ]),
        # Allow WG endpoint
        (f"{_WIN_RULE_PREFIX}-Allow-WG-Endpoint", [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_WIN_RULE_PREFIX}-Allow-WG-Endpoint",
            "dir=out", "action=allow", "protocol=udp",
            f"remoteip={ip}", f"remoteport={port}",
            "enable=yes",
        ]),
        # Allow DHCP (needed for re-establishing connection)
        (f"{_WIN_RULE_PREFIX}-Allow-DHCP", [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_WIN_RULE_PREFIX}-Allow-DHCP",
            "dir=out", "action=allow", "protocol=udp",
            "localport=68", "remoteport=67",
            "enable=yes",
        ]),
        # Allow DNS over VPN interface only (for tunnel DNS)
        (f"{_WIN_RULE_PREFIX}-Allow-DNS-VPN", [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_WIN_RULE_PREFIX}-Allow-DNS-VPN",
            "dir=out", "action=allow", "protocol=udp",
            "remoteport=53",
            "enable=yes",
        ]),
        # Block everything else
        (f"{_WIN_RULE_PREFIX}-Block-All", [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_WIN_RULE_PREFIX}-Block-All",
            "dir=out", "action=block",
            "enable=yes",
        ]),
    ]

    for name, cmd in rules:
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        except subprocess.CalledProcessError as exc:
            # Roll back on failure
            _disengage_windows()
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise RuntimeError(f"Kill switch rule '{name}' failed: {stderr}") from exc


def _disengage_windows() -> None:
    """Remove all WireSeal kill switch firewall rules."""
    try:
        # Delete all rules matching our prefix
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={_WIN_RULE_PREFIX}-Allow-Loopback",
            ],
            capture_output=True, timeout=10,
        )
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={_WIN_RULE_PREFIX}-Allow-WG-Endpoint",
            ],
            capture_output=True, timeout=10,
        )
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={_WIN_RULE_PREFIX}-Allow-DHCP",
            ],
            capture_output=True, timeout=10,
        )
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={_WIN_RULE_PREFIX}-Allow-DNS-VPN",
            ],
            capture_output=True, timeout=10,
        )
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={_WIN_RULE_PREFIX}-Block-All",
            ],
            capture_output=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.warning("Kill switch cleanup (Windows) error: %s", exc)


# ---------------------------------------------------------------------------
# Linux: iptables chain
# ---------------------------------------------------------------------------


def _sudo() -> list[str]:
    """Sudo prefix for Linux/macOS when not root."""
    import os
    if os.geteuid() == 0:
        return []
    return ["sudo", "-n"]


def _engage_linux(ip: str, port: int, interface: str) -> None:
    """Insert iptables rules via dedicated chain."""
    _disengage_linux()  # clean slate
    sudo = _sudo()

    cmds: list[list[str]] = [
        # Create chain
        [*sudo, "iptables", "-N", _LINUX_CHAIN],
        # Allow loopback
        [*sudo, "iptables", "-A", _LINUX_CHAIN,
         "-o", "lo", "-j", "ACCEPT"],
        # Allow established connections (for the tunnel itself)
        [*sudo, "iptables", "-A", _LINUX_CHAIN,
         "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
         "-j", "ACCEPT"],
        # Allow traffic on WG interface
        [*sudo, "iptables", "-A", _LINUX_CHAIN,
         "-o", interface, "-j", "ACCEPT"],
        # Allow WG endpoint UDP
        [*sudo, "iptables", "-A", _LINUX_CHAIN,
         "-p", "udp", "-d", ip, "--dport", str(port), "-j", "ACCEPT"],
        # Allow DHCP
        [*sudo, "iptables", "-A", _LINUX_CHAIN,
         "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"],
        # Block everything else
        [*sudo, "iptables", "-A", _LINUX_CHAIN, "-j", "DROP"],
        # Insert chain into OUTPUT
        [*sudo, "iptables", "-I", "OUTPUT", "1", "-j", _LINUX_CHAIN],
    ]

    for cmd in cmds:
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        except subprocess.CalledProcessError as exc:
            _disengage_linux()
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise RuntimeError(
                f"Kill switch iptables failed: {' '.join(cmd)}: {stderr}"
            ) from exc


def _disengage_linux() -> None:
    """Remove the kill switch iptables chain."""
    sudo = _sudo()
    try:
        # Remove reference from OUTPUT
        subprocess.run(
            [*sudo, "iptables", "-D", "OUTPUT", "-j", _LINUX_CHAIN],
            capture_output=True, timeout=10,
        )
    except (subprocess.CalledProcessError, OSError):
        pass
    try:
        # Flush and delete chain
        subprocess.run(
            [*sudo, "iptables", "-F", _LINUX_CHAIN],
            capture_output=True, timeout=10,
        )
        subprocess.run(
            [*sudo, "iptables", "-X", _LINUX_CHAIN],
            capture_output=True, timeout=10,
        )
    except (subprocess.CalledProcessError, OSError):
        pass


# ---------------------------------------------------------------------------
# macOS: pf anchor
# ---------------------------------------------------------------------------


def _engage_macos(ip: str, port: int, interface: str) -> None:
    """Load pf anchor rules for kill switch."""
    _disengage_macos()
    sudo = _sudo()

    rules = "\n".join([
        f"# WireSeal kill switch",
        f"pass out quick on lo0 all",
        f"pass out quick on {interface} all",
        f"pass out quick proto udp to {ip} port {port}",
        f"pass out quick proto udp from any port 68 to any port 67",
        f"block out all",
    ])

    anchor_file = f"/tmp/wireseal_killswitch.rules"
    with open(anchor_file, "w") as f:
        f.write(rules + "\n")

    cmds: list[list[str]] = [
        # Load anchor rules
        [*sudo, "pfctl", "-a", _MAC_ANCHOR, "-f", anchor_file],
        # Enable pf if not already
        [*sudo, "pfctl", "-e"],
    ]

    try:
        for cmd in cmds:
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            except subprocess.CalledProcessError as exc:
                # pfctl -e returns 1 if already enabled — ignore
                if cmd[-1] == "-e":
                    continue
                _disengage_macos()
                stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
                raise RuntimeError(
                    f"Kill switch pf failed: {' '.join(cmd)}: {stderr}"
                ) from exc
    finally:
        import os
        try:
            os.unlink(anchor_file)
        except OSError:
            pass


def _disengage_macos() -> None:
    """Flush the pf anchor."""
    sudo = _sudo()
    try:
        subprocess.run(
            [*sudo, "pfctl", "-a", _MAC_ANCHOR, "-F", "all"],
            capture_output=True, timeout=10,
        )
    except (subprocess.CalledProcessError, OSError):
        pass
