"""Dynamic DNS package for WireGuard Automate.

Public API:
  - resolve_public_ip: Query 3 HTTPS sources and return consensus IPv4Address
  - IPConsensusError: Raised when fewer than 2 sources agree
  - update_dns: Update DuckDNS record with vault-sourced SecretBytes token
  - DuckDNSError: Raised on any DuckDNS update failure
"""

from __future__ import annotations

from .ip_resolver import IPConsensusError, resolve_public_ip

# duckdns is imported lazily to avoid ImportError if duckdns.py is not yet present
# (during Task 1 execution). After Task 2 completes this becomes a direct import.
try:
    from .duckdns import DuckDNSError, update_dns
except ImportError:  # pragma: no cover
    DuckDNSError = None  # type: ignore[assignment,misc]
    update_dns = None  # type: ignore[assignment]

__all__ = [
    "resolve_public_ip",
    "IPConsensusError",
    "update_dns",
    "DuckDNSError",
]
