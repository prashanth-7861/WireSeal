"""SSDP/UPnP service discovery via stdlib UDP multicast.

Sends M-SEARCH to 239.255.255.250:1900, parses responses, and
optionally fetches device description XML for friendly names.
"""

from __future__ import annotations

import logging
import re
import socket
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

log = logging.getLogger(__name__)

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900

_M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


@dataclass
class SsdpService:
    name: str = ""
    type: str = "upnp"
    protocol: str = "ssdp"
    host: str = ""
    ip: str = ""
    port: int = 0
    manufacturer: str = ""
    model: str = ""
    location: str = ""
    properties: dict = None

    def __post_init__(self):
        if self.properties is None:
            self.properties = {}

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_headers(raw: str) -> dict[str, str]:
    """Parse HTTP-style headers from an SSDP response."""
    headers: dict[str, str] = {}
    for line in raw.split("\r\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().upper()] = value.strip()
    return headers


def _fetch_device_description(location: str) -> Optional[dict]:
    """Fetch UPnP device description XML and extract key fields."""
    try:
        req = Request(location, headers={"User-Agent": "WireSeal/1.0"})
        with urlopen(req, timeout=3) as resp:
            data = resp.read(64 * 1024)  # Cap at 64KB
    except (URLError, OSError, TimeoutError):
        return None

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None

    # UPnP XML uses namespaces — strip them for simpler lookup
    ns_re = re.compile(r"\{[^}]+\}")

    def _find(tag: str) -> str:
        for elem in root.iter():
            clean_tag = ns_re.sub("", elem.tag)
            if clean_tag == tag and elem.text:
                return elem.text.strip()
        return ""

    return {
        "friendly_name": _find("friendlyName"),
        "manufacturer": _find("manufacturer"),
        "model_name": _find("modelName"),
        "model_description": _find("modelDescription"),
        "device_type": _find("deviceType"),
    }


def _extract_ip_port(location: str) -> tuple[str, int]:
    """Extract IP and port from a LOCATION URL."""
    # e.g. http://192.168.1.1:8080/description.xml
    match = re.match(r"https?://([^/:]+):?(\d+)?", location)
    if match:
        ip = match.group(1)
        port = int(match.group(2)) if match.group(2) else 80
        return ip, port
    return "", 0


def discover_ssdp(timeout: float = 3.0, fetch_descriptions: bool = True) -> list[SsdpService]:
    """Send SSDP M-SEARCH and collect discovered services.

    Args:
        timeout: How long to listen for responses (seconds).
        fetch_descriptions: Whether to fetch device description XML for
            friendly names. Adds latency but provides richer metadata.

    Returns:
        List of discovered SSDP services.
    """
    services: list[SsdpService] = []
    seen_locations: set[str] = set()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(_M_SEARCH.encode("utf-8"), (_SSDP_ADDR, _SSDP_PORT))
    except OSError as exc:
        log.warning("SSDP socket error: %s", exc)
        return services

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break

            raw = data.decode("utf-8", errors="replace")
            headers = _parse_headers(raw)
            location = headers.get("LOCATION", "")

            if not location or location in seen_locations:
                continue
            seen_locations.add(location)

            ip, port = _extract_ip_port(location)
            if not ip:
                continue

            svc = SsdpService(
                ip=ip,
                port=port,
                location=location,
                host=ip,
            )

            st = headers.get("ST", "")
            if st:
                svc.properties["st"] = st
                # Classify device type from ST header
                st_lower = st.lower()
                if "mediaserver" in st_lower:
                    svc.type = "upnp:mediaserver"
                elif "mediarenderer" in st_lower:
                    svc.type = "upnp:mediarenderer"
                elif "internetgateway" in st_lower:
                    svc.type = "upnp:gateway"
                elif "printer" in st_lower:
                    svc.type = "upnp:printer"

            if fetch_descriptions:
                desc = _fetch_device_description(location)
                if desc:
                    svc.name = desc["friendly_name"] or f"UPnP Device ({ip})"
                    svc.manufacturer = desc["manufacturer"]
                    svc.model = desc["model_name"]
                    if desc["device_type"]:
                        svc.properties["device_type"] = desc["device_type"]
                else:
                    svc.name = f"UPnP Device ({ip})"
            else:
                svc.name = f"UPnP Device ({ip})"

            services.append(svc)
    finally:
        sock.close()

    return services
