"""LAN device discovery via ARP table parsing and optional ping sweep.

Cross-platform (Linux, macOS, Windows). Zero external dependencies.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Optional

from .oui import lookup_vendor

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    source: str = "arp_table"  # "arp_table" | "ping_sweep"
    last_seen: str = ""  # ISO-8601
    device_type: str = ""  # router|printer|nas|media|phone|computer|iot|unknown
    open_ports: list = field(default_factory=list)  # [{"port", "service"}]

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# ARP table readers (per-platform)
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2}")


def _normalize_mac(raw: str) -> str:
    """Normalize MAC to lowercase colon-separated format."""
    raw = raw.strip().lower().replace("-", ":")
    parts = raw.split(":")
    return ":".join(p.zfill(2) for p in parts)


def _resolve_hostname(ip: str) -> str:
    """Best-effort reverse DNS lookup. Returns '' on failure."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _read_arp_linux() -> list[Device]:
    """Parse ``ip neigh show`` output on Linux."""
    devices: list[Device] = []
    try:
        out = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0:
            return devices
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return devices

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for line in out.stdout.splitlines():
        # 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        parts = line.split()
        if len(parts) < 4:
            continue
        ip_str = parts[0]
        mac_match = _MAC_RE.search(line)
        if not mac_match:
            continue
        state = parts[-1].upper()
        if state in ("FAILED", "INCOMPLETE"):
            continue
        mac = _normalize_mac(mac_match.group())
        devices.append(Device(
            ip=ip_str, mac=mac,
            vendor=lookup_vendor(mac),
            last_seen=now,
        ))
    return devices


def _read_arp_windows_macos() -> list[Device]:
    """Parse ``arp -a`` output on Windows/macOS."""
    devices: list[Device] = []
    try:
        out = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0:
            return devices
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return devices

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # Match lines with an IP and a MAC:
    #   ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0  [macOS]
    #   192.168.1.1    aa-bb-cc-dd-ee-ff     dynamic  [Windows]
    ip_re = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    for line in out.stdout.splitlines():
        mac_match = _MAC_RE.search(line)
        ip_match = ip_re.search(line)
        if not mac_match or not ip_match:
            continue
        mac_raw = mac_match.group()
        # Skip broadcast / incomplete
        if mac_raw.replace("-", ":").lower() in ("ff:ff:ff:ff:ff:ff",):
            continue
        mac = _normalize_mac(mac_raw)
        ip_str = ip_match.group(1)
        devices.append(Device(
            ip=ip_str, mac=mac,
            vendor=lookup_vendor(mac),
            last_seen=now,
        ))
    return devices


def _is_unicast_device(dev: Device) -> bool:
    """Filter out multicast/broadcast MACs and non-unicast IPs."""
    # Multicast MACs: 01:00:5e:xx, 33:33:xx (IPv6 multicast)
    if dev.mac.startswith("01:00:5e") or dev.mac.startswith("33:33:"):
        return False
    # Broadcast MAC
    if dev.mac == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        addr = ipaddress.IPv4Address(dev.ip)
        if addr.is_multicast or addr.is_reserved or addr.is_loopback:
            return False
    except ValueError:
        return False
    return True


def read_arp_table() -> list[Device]:
    """Read the OS ARP/neighbor table. Returns discovered devices."""
    if sys.platform == "linux":
        devices = _read_arp_linux()
    else:
        devices = _read_arp_windows_macos()

    # Filter out multicast/broadcast entries
    devices = [d for d in devices if _is_unicast_device(d)]

    # Best-effort hostname resolution (parallel, bounded)
    def _resolve(dev: Device) -> None:
        dev.hostname = _resolve_hostname(dev.ip)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(_resolve, devices))

    # Coarse classification from vendor signal (refined later by port scan)
    from .classify import classify_device
    for dev in devices:
        dev.device_type = classify_device(vendor=dev.vendor)

    return devices


# ---------------------------------------------------------------------------
# Active ping sweep
# ---------------------------------------------------------------------------

_scan_lock = threading.Lock()
_scan_running = False
_scan_progress: dict = {"total": 0, "done": 0, "status": "idle"}
_scan_results: list[Device] = []


def _ping_one(ip: str) -> bool:
    """Ping a single IP. Returns True if reachable."""
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def ping_sweep(subnet: str, workers: int = 32) -> list[str]:
    """Parallel ping sweep of a subnet. Returns list of responding IPs."""
    global _scan_progress
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        log.warning("Invalid subnet for ping sweep: %s", subnet)
        return []

    hosts = [str(h) for h in network.hosts()]
    # Cap at /22 (1022 hosts) to avoid excessive scanning
    if len(hosts) > 1022:
        log.warning("Subnet too large for ping sweep: %s (%d hosts)", subnet, len(hosts))
        return []

    _scan_progress = {"total": len(hosts), "done": 0, "status": "scanning"}
    alive: list[str] = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_ping_one, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            _scan_progress["done"] += 1
            if fut.result():
                alive.append(futures[fut])

    _scan_progress["status"] = "done"
    return alive


def _run_scan(subnet: str) -> None:
    """Background scan thread: ping sweep then re-read ARP table."""
    global _scan_running, _scan_results, _scan_progress
    try:
        ping_sweep(subnet)
        # After ping sweep, ARP table should be populated
        _scan_results = read_arp_table()
        _scan_progress["status"] = "done"
    except Exception:
        log.exception("Scan failed")
        _scan_progress["status"] = "error"
    finally:
        with _scan_lock:
            _scan_running = False


_last_scan_time: float = 0.0
_SCAN_COOLDOWN = 30.0  # seconds


def start_scan(subnet: str) -> dict:
    """Start a background ping sweep. Returns status dict."""
    global _scan_running, _last_scan_time, _scan_progress, _scan_results

    with _scan_lock:
        if _scan_running:
            return {"ok": False, "reason": "scan_in_progress"}

        now = time.time()
        if now - _last_scan_time < _SCAN_COOLDOWN:
            remaining = int(_SCAN_COOLDOWN - (now - _last_scan_time))
            return {"ok": False, "reason": "cooldown", "retry_after": remaining}

        _scan_running = True
        _last_scan_time = now
        _scan_progress = {"total": 0, "done": 0, "status": "starting"}
        _scan_results = []

    t = threading.Thread(target=_run_scan, args=(subnet,), daemon=True)
    t.start()
    return {"ok": True}


def get_scan_status() -> dict:
    """Return current scan progress and results."""
    with _scan_lock:
        running = _scan_running

    return {
        "running": running,
        "progress": dict(_scan_progress),
        "devices": [d.to_dict() for d in _scan_results],
    }


# ---------------------------------------------------------------------------
# Combined discovery
# ---------------------------------------------------------------------------

def discover_devices(subnet: Optional[str] = None, active_scan: bool = False) -> list[Device]:
    """Discover devices on the LAN.

    If *active_scan* is True and *subnet* is provided, runs a ping sweep
    first to populate the ARP table before reading it.
    """
    if active_scan and subnet:
        ping_sweep(subnet)
    return read_arp_table()
