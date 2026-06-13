"""Heuristic device-type classification from passive + active signals.

Combines OUI vendor, open TCP ports, and discovered mDNS/SSDP service
types into a single coarse device category. Intentionally conservative:
returns ``"unknown"`` rather than guessing wildly.
"""

from __future__ import annotations

# Coarse device categories surfaced in the UI.
ROUTER = "router"
PRINTER = "printer"
NAS = "nas"
MEDIA = "media"
PHONE = "phone"
COMPUTER = "computer"
IOT = "iot"
UNKNOWN = "unknown"

# Vendor substrings (lowercase) → category. First match wins.
_VENDOR_HINTS: list[tuple[str, str]] = [
    ("synology", NAS),
    ("qnap", NAS),
    ("western digital", NAS),
    ("netgear", ROUTER),
    ("tp-link", ROUTER),
    ("ubiquiti", ROUTER),
    ("mikrotik", ROUTER),
    ("asustek", ROUTER),
    ("arris", ROUTER),
    ("cisco", ROUTER),
    ("hewlett", PRINTER),
    ("brother", PRINTER),
    ("canon", PRINTER),
    ("epson", PRINTER),
    ("lexmark", PRINTER),
    ("roku", MEDIA),
    ("sonos", MEDIA),
    ("nvidia", MEDIA),
    ("amazon", IOT),
    ("espressif", IOT),
    ("nest", IOT),
    ("ring", IOT),
    ("philips", IOT),
]

# Open-port signatures → category.
_PRINTER_PORTS = {515, 631, 9100}
_NAS_PORTS = {445, 548, 2049, 5000}
_MEDIA_PORTS = {8096, 32400, 554}
_COMPUTER_PORTS = {22, 3389, 5900}


def _from_service_types(service_types: list[str]) -> str | None:
    """Classify from discovered mDNS/SSDP service-type labels."""
    joined = " ".join(service_types).lower()
    if any(k in joined for k in ("printer", "ipp")):
        return PRINTER
    if any(k in joined for k in ("plex", "airplay", "chromecast", "media", "daap")):
        return MEDIA
    if any(k in joined for k in ("smb", "afp", "nfs", "file share")):
        return NAS
    if "gateway" in joined:
        return ROUTER
    return None


def _from_ports(ports: set[int]) -> str | None:
    """Classify from open-port signatures (most specific first)."""
    if ports & _PRINTER_PORTS:
        return PRINTER
    if ports & _MEDIA_PORTS:
        return MEDIA
    if ports & _NAS_PORTS:
        return NAS
    if ports & _COMPUTER_PORTS:
        return COMPUTER
    return None


def _from_vendor(vendor: str) -> str | None:
    """Classify from OUI vendor string."""
    v = (vendor or "").lower()
    if not v or v == "unknown":
        return None
    for needle, category in _VENDOR_HINTS:
        if needle in v:
            return category
    if "apple" in v:
        # Apple covers phones, computers, TVs — leave to other signals.
        return None
    return None


def classify_device(
    vendor: str = "",
    open_ports: list[int] | None = None,
    service_types: list[str] | None = None,
    is_gateway: bool = False,
) -> str:
    """Return a coarse device category from the available signals.

    Priority: gateway flag > service types > open ports > vendor.
    Returns :data:`UNKNOWN` when no signal matches.
    """
    if is_gateway:
        return ROUTER

    ports = {p for p in (open_ports or []) if isinstance(p, int)}
    types = service_types or []

    return (
        _from_service_types(types)
        or _from_ports(ports)
        or _from_vendor(vendor)
        or UNKNOWN
    )
