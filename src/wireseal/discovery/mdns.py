"""mDNS/DNS-SD service discovery via the ``zeroconf`` library.

Optional dependency — gracefully degrades if zeroconf is not installed.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any

log = logging.getLogger(__name__)

# Service types to browse — covers most common home network services
SERVICE_TYPES: list[str] = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ipp._tcp.local.",          # IPP printers
    "_printer._tcp.local.",      # LPR printers
    "_pdl-datastream._tcp.local.",  # Raw printing (port 9100)
    "_smb._tcp.local.",          # SMB/CIFS file shares
    "_afpovertcp._tcp.local.",   # AFP file shares (macOS)
    "_nfs._tcp.local.",          # NFS shares
    "_sftp-ssh._tcp.local.",     # SFTP
    "_ssh._tcp.local.",          # SSH
    "_airplay._tcp.local.",      # AirPlay
    "_raop._tcp.local.",         # AirPlay audio
    "_googlecast._tcp.local.",   # Chromecast
    "_hap._tcp.local.",          # HomeKit
    "_spotify-connect._tcp.local.",  # Spotify Connect
    "_daap._tcp.local.",         # iTunes/DAAP
    "_media._tcp.local.",        # Generic media
    "_plex._tcp.local.",         # Plex Media Server
]

# Human-friendly type labels
_TYPE_LABELS: dict[str, str] = {
    "_http._tcp": "HTTP",
    "_https._tcp": "HTTPS",
    "_ipp._tcp": "Printer (IPP)",
    "_printer._tcp": "Printer (LPR)",
    "_pdl-datastream._tcp": "Printer (Raw)",
    "_smb._tcp": "File Share (SMB)",
    "_afpovertcp._tcp": "File Share (AFP)",
    "_nfs._tcp": "File Share (NFS)",
    "_sftp-ssh._tcp": "SFTP",
    "_ssh._tcp": "SSH",
    "_airplay._tcp": "AirPlay",
    "_raop._tcp": "AirPlay Audio",
    "_googlecast._tcp": "Chromecast",
    "_hap._tcp": "HomeKit",
    "_spotify-connect._tcp": "Spotify Connect",
    "_daap._tcp": "iTunes/DAAP",
    "_media._tcp": "Media",
    "_plex._tcp": "Plex",
}


def _type_label(stype: str) -> str:
    """Return human-friendly label for a service type."""
    key = stype.replace(".local.", "").rstrip(".")
    return _TYPE_LABELS.get(key, key)


@dataclass
class MdnsService:
    name: str = ""
    type: str = ""
    protocol: str = "mdns"
    host: str = ""
    ip: str = ""
    port: int = 0
    manufacturer: str = ""
    model: str = ""
    properties: dict = None

    def __post_init__(self):
        if self.properties is None:
            self.properties = {}

    def to_dict(self) -> dict:
        return asdict(self)


def _is_available() -> bool:
    """Check whether the zeroconf library is installed."""
    try:
        import zeroconf  # noqa: F401
        return True
    except ImportError:
        return False


def discover_mdns(timeout: float = 5.0) -> list[MdnsService]:
    """Browse mDNS/DNS-SD for common service types.

    Returns an empty list if zeroconf is not installed.
    """
    if not _is_available():
        log.info("zeroconf not installed — skipping mDNS discovery")
        return []

    from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf

    services: list[MdnsService] = []
    found_lock = threading.Lock()

    class _Listener:
        def add_service(self, zc: Any, stype: str, name: str) -> None:
            info = zc.get_service_info(stype, name, timeout=3000)
            if info is None:
                return
            svc = _info_to_service(info, stype)
            if svc:
                with found_lock:
                    services.append(svc)

        def remove_service(self, zc: Any, stype: str, name: str) -> None:
            pass

        def update_service(self, zc: Any, stype: str, name: str) -> None:
            pass

    zc = Zeroconf()
    listener = _Listener()
    browsers = []
    try:
        for stype in SERVICE_TYPES:
            browsers.append(ServiceBrowser(zc, stype, listener))
        # Let the browsers discover for the given timeout
        time.sleep(timeout)
    finally:
        zc.close()

    return services


def _info_to_service(info: Any, stype: str) -> MdnsService | None:
    """Convert a zeroconf ServiceInfo to our MdnsService dataclass."""
    # Extract IP addresses
    ip = ""
    if hasattr(info, "parsed_addresses"):
        addrs = info.parsed_addresses()
        if addrs:
            # Prefer IPv4
            for a in addrs:
                if ":" not in a:
                    ip = a
                    break
            if not ip:
                ip = addrs[0]
    elif hasattr(info, "addresses") and info.addresses:
        import socket
        ip = socket.inet_ntoa(info.addresses[0])

    if not ip:
        return None

    # Extract properties
    props: dict[str, str] = {}
    if hasattr(info, "properties") and info.properties:
        for k, v in info.properties.items():
            key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
            val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
            props[key] = val

    name = info.name if hasattr(info, "name") else ""
    # Strip the service type suffix from the name
    if name.endswith(f".{stype}"):
        name = name[: -(len(stype) + 1)]

    host = info.server if hasattr(info, "server") else ""
    if host.endswith("."):
        host = host[:-1]

    return MdnsService(
        name=name or f"Service ({ip})",
        type=_type_label(stype),
        host=host,
        ip=ip,
        port=info.port if hasattr(info, "port") else 0,
        manufacturer=props.get("manufacturer", props.get("vendor", "")),
        model=props.get("model", props.get("md", "")),
        properties=props,
    )


def is_available() -> bool:
    """Public check for zeroconf availability."""
    return _is_available()
