"""Public IP resolver with 2-of-3 HTTPS consensus.

Queries 3 independent HTTPS endpoints concurrently and returns the public IPv4
address that at least 2 sources agree on. Fail-closed: if no consensus is
reached, IPConsensusError is raised and no address is returned.

Security properties:
  - DNS-01: 2-of-3 consensus required; fail closed on disagreement
  - DNS-02: Returned address validated as public IPv4 (RFC 1918, loopback,
    multicast, link-local, and reserved ranges rejected)
  - HTTPS only with ssl.create_default_context() (certificate verification)
  - stdlib urllib only -- no third-party requests library
"""

from __future__ import annotations

import ipaddress
import ssl
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP_SOURCES: tuple[str, ...] = (
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://icanhazip.com",
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class IPConsensusError(Exception):
    """Raised when fewer than 2 of 3 HTTPS sources agree on the public IP.

    Satisfies DNS-01 (fail closed): callers always receive a validated
    public IPv4 or an exception -- never an unvalidated or ambiguous address.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _fetch_ip(url: str, timeout: float = 5.0) -> str | None:
    """Fetch the public IP string from a single HTTPS source.

    Uses ssl.create_default_context() to ensure certificate verification is
    active (equivalent to requests' verify=True).

    Args:
        url:     HTTPS URL that returns the caller's public IP as plain text.
        timeout: Per-source network timeout in seconds (default 5.0).

    Returns:
        Stripped IP string on success, None on any error (network error,
        timeout, non-200 response, etc.). Individual source failures are
        never propagated to callers.
    """
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, context=ctx, timeout=timeout) as resp:
            body = resp.read()
        return body.decode("ascii", errors="replace").strip()
    except Exception:
        return None


def _is_public_ipv4(addr: str) -> bool:
    """Return True iff addr is a valid, globally routable IPv4 address.

    Rejects:
      - Non-parseable strings (ValueError)
      - Private ranges (RFC 1918: 10/8, 172.16/12, 192.168/16)
      - Loopback (127/8)
      - Multicast (224/4)
      - Link-local (169.254/16)
      - Reserved / unspecified addresses

    Satisfies DNS-02.

    Args:
        addr: String to test.

    Returns:
        True only if addr is a globally routable public IPv4 address.
    """
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return False

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_public_ip() -> ipaddress.IPv4Address:
    """Query 3 independent HTTPS sources and return the consensus public IPv4.

    Submits all 3 requests concurrently (max_workers=3) with a 10-second
    wall-clock timeout so a hanging source never blocks indefinitely.

    Returns:
        ipaddress.IPv4Address representing the public IP that at least 2
        of the 3 sources agreed on.

    Raises:
        IPConsensusError: Fewer than 2 sources returned the same public IPv4.
            Callers should treat this as a hard abort for any DNS update
            operation (DNS-01 fail-closed guarantee).
    """
    results: list[str] = []

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(_fetch_ip, url): url for url in _IP_SOURCES}
        for future in as_completed(futures, timeout=10):
            ip_str = future.result()
            if ip_str is not None and _is_public_ipv4(ip_str):
                results.append(ip_str)

    counts = Counter(results)
    if counts:
        winning_ip, winning_count = counts.most_common(1)[0]
        if winning_count >= 2:
            return ipaddress.IPv4Address(winning_ip)

    raise IPConsensusError(
        "No 2-of-3 IP consensus achieved. DNS update aborted."
    )
