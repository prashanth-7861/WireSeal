from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name


# ---------------------------------------------------------------------------
# Network discovery handlers (device enumeration + service discovery)
# ---------------------------------------------------------------------------


def _get_lan_subnet() -> str:
    """Return the LAN subnet from vault cache, or detect it."""
    with _lock:
        cache = _session.get("cache") or {}
    lan_subnet = cache.get("server", {}).get("lan_subnet", "")
    if not lan_subnet:
        try:
            from wireseal.platform.detect import get_adapter
            adapter = get_adapter()
            lan_subnet = adapter.detect_lan_subnet()
        except Exception:
            pass
    return lan_subnet


def _h_network_devices(req, _groups):
    """GET /api/network/devices — passive ARP table read."""
    _require_unlocked()

    from wireseal.discovery.devices import read_arp_table

    devices = read_arp_table()
    lan_subnet = _get_lan_subnet()

    return {
        "devices": [d.to_dict() for d in devices],
        "lan_subnet": lan_subnet,
        "platform": sys.platform,
        "scan_available": bool(lan_subnet),
    }


def _h_network_scan(req, _groups):
    """POST /api/network/scan — trigger active ping sweep."""
    _require_unlocked()

    from wireseal.discovery.devices import start_scan

    lan_subnet = _get_lan_subnet()
    if not lan_subnet:
        raise _ApiError("LAN subnet not detected. Cannot scan.", 400)

    result = start_scan(lan_subnet)
    return result


def _h_network_scan_status(req, _groups):
    """GET /api/network/scan/status — poll scan progress."""
    _require_unlocked()

    from wireseal.discovery.devices import get_scan_status

    return get_scan_status()


def _h_network_services(req, _groups):
    """GET /api/network/services — cached service discovery."""
    _require_unlocked()

    from wireseal.discovery.services import get_cached_services

    result = get_cached_services()
    return result


def _h_network_services_scan(req, _groups):
    """POST /api/network/services/scan — force fresh discovery."""
    _require_unlocked()

    from wireseal.discovery.services import discover_all_services

    result = discover_all_services()
    return result
