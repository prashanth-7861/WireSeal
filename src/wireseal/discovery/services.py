"""Unified service discovery coordinator.

Runs mDNS and SSDP discovery in parallel, deduplicates by (ip, port),
and caches results with a configurable TTL.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)

_cache_lock = threading.Lock()
_cached_services: list[dict] = []
_cache_time: float = 0.0
_CACHE_TTL = 30.0  # seconds


def discover_all_services(timeout: float = 5.0) -> dict:
    """Run mDNS + SSDP discovery in parallel, cache, and return results."""
    global _cached_services, _cache_time

    mdns_results: list[dict] = []
    ssdp_results: list[dict] = []
    mdns_available = False

    def _run_mdns() -> None:
        nonlocal mdns_results, mdns_available
        from .mdns import discover_mdns, is_available
        mdns_available = is_available()
        if mdns_available:
            services = discover_mdns(timeout=timeout)
            mdns_results = [s.to_dict() for s in services]

    def _run_ssdp() -> None:
        nonlocal ssdp_results
        from .ssdp import discover_ssdp
        services = discover_ssdp(timeout=timeout)
        ssdp_results = [s.to_dict() for s in services]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_run_mdns), pool.submit(_run_ssdp)]
        for f in futures:
            try:
                f.result(timeout=timeout + 5)
            except Exception:
                log.exception("Service discovery worker failed")

    # Deduplicate by (ip, port)
    seen: set[tuple[str, int]] = set()
    combined: list[dict] = []
    # mDNS results tend to have richer metadata, prioritize them
    for svc in mdns_results + ssdp_results:
        key = (svc.get("ip", ""), svc.get("port", 0))
        if key not in seen:
            seen.add(key)
            combined.append(svc)

    with _cache_lock:
        _cached_services = combined
        _cache_time = time.time()

    return {
        "services": combined,
        "mdns_available": mdns_available,
        "ssdp_available": True,
        "cached": False,
        "cache_age_seconds": 0,
    }


def get_cached_services() -> dict:
    """Return cached service discovery results, or run fresh if expired."""
    with _cache_lock:
        age = time.time() - _cache_time
        if _cached_services and age < _CACHE_TTL:
            return {
                "services": list(_cached_services),
                "mdns_available": True,  # approximate; updated on fresh scan
                "ssdp_available": True,
                "cached": True,
                "cache_age_seconds": int(age),
            }

    return discover_all_services()
