"""Lightweight TCP connect port scanning for per-device detail.

Scans a curated list of common LAN service ports using non-blocking
``socket.create_connection``. Zero external dependencies, bounded
concurrency, short timeouts. Restricted to private/LAN addresses to
avoid being turned into a port scanner for arbitrary internet hosts.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)

# Curated common LAN ports → friendly service label.
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    515: "Printer (LPR)",
    548: "AFP",
    554: "RTSP",
    631: "Printer (IPP)",
    993: "IMAPS",
    1883: "MQTT",
    1900: "SSDP/UPnP",
    2049: "NFS",
    3000: "HTTP (dev)",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP/HTTP",
    5432: "PostgreSQL",
    5900: "VNC",
    8006: "Proxmox",
    8080: "HTTP-alt",
    8096: "Jellyfin",
    8123: "Home Assistant",
    8443: "HTTPS-alt",
    9000: "HTTP (admin)",
    9100: "Printer (Raw)",
    32400: "Plex",
    51413: "Transmission",
}

# Hard cap so a custom port list can't be abused for a full 65k sweep.
_MAX_PORTS = 64
_DEFAULT_TIMEOUT = 0.5
_DEFAULT_WORKERS = 24


def is_scannable_ip(ip: str) -> bool:
    """Return True only for private/link-local unicast LAN addresses.

    Blocks public, loopback, multicast, and reserved addresses so the
    scanner cannot be pointed at arbitrary internet hosts.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_multicast or addr.is_reserved:
        return False
    if addr.is_unspecified:
        return False
    return bool(addr.is_private or addr.is_link_local)


def _probe_port(ip: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to ``ip:port`` succeeds."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def scan_ports(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
    workers: int = _DEFAULT_WORKERS,
) -> list[dict]:
    """TCP connect-scan ``ip`` for open ports.

    Args:
        ip: Target LAN IP. Must pass :func:`is_scannable_ip`.
        ports: Ports to probe. Defaults to :data:`COMMON_PORTS` keys.
        timeout: Per-port connect timeout in seconds.
        workers: Max concurrent connections.

    Returns:
        Sorted list of ``{"port": int, "service": str}`` for open ports.
        Empty list if the IP is not scannable.
    """
    if not is_scannable_ip(ip):
        log.warning("Refusing to scan non-LAN address: %s", ip)
        return []

    scan_list = ports if ports is not None else list(COMMON_PORTS.keys())
    # Dedupe, keep valid port range, enforce hard cap.
    scan_list = sorted({p for p in scan_list if 0 < p < 65536})[:_MAX_PORTS]

    open_ports: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_probe_port, ip, port, timeout): port for port in scan_list
        }
        for fut in as_completed(futures):
            port = futures[fut]
            if fut.result():
                open_ports.append(
                    {"port": port, "service": COMMON_PORTS.get(port, "")}
                )

    open_ports.sort(key=lambda d: d["port"])
    return open_ports
