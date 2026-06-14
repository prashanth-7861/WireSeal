"""Per-client resource ACLs enforced via a dedicated nftables table (Linux).

Each client may run in ``allow_all`` (default, unrestricted) or ``restricted``
mode. In restricted mode only the listed destinations are reachable from that
client's WireGuard source IP; everything else from that client is dropped.

Design:
  - A dedicated ``inet wg_acl`` table with a forward-hook chain at priority -10
    runs *before* the existing ``wg_forward`` accept chain. Restricted clients
    get explicit accept rules then a catch-all drop on their source IP;
    allow_all clients have no rules and simply fall through to the normal accept
    path. Established/related is always accepted so return traffic flows.
  - The ruleset is written to ``/etc/nftables.d/wireseal-acl.nft`` (sourced on
    boot by the managed include) and applied immediately with ``nft -f``.
  - Inputs are validated through :mod:`ipaddress` and a proto/port whitelist, so
    no untrusted string ever reaches the nft script (injection-safe).

Non-Linux servers: unsupported — callers receive ``(False, reason)``.
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
import sys
from pathlib import Path

from ..security.atomic import atomic_write

log = logging.getLogger("wireseal.acl")

ACL_NFT_FILE = Path("/etc/nftables.d/wireseal-acl.nft")

ALLOW_ALL = "allow_all"
RESTRICTED = "restricted"
_PROTOS = ("tcp", "udp", "any")
_MAX_RULES_PER_CLIENT = 64


class AclError(ValueError):
    """Raised when an ACL rule or mode is invalid."""


def validate_rule(rule: dict) -> dict:
    """Validate + normalize a single ACL rule.

    Returns ``{"dest": str, "port": int|None, "proto": "tcp"|"udp"|"any"}``.
    Raises :class:`AclError` on anything malformed.
    """
    if not isinstance(rule, dict):
        raise AclError("rule must be an object")
    dest = str(rule.get("dest", "")).strip()
    if not dest:
        raise AclError("rule.dest is required")
    try:
        # Accept a host (10.0.0.10) or CIDR (10.0.0.0/24). strict=False allows host bits.
        net = ipaddress.ip_network(dest, strict=False)
    except ValueError as exc:
        raise AclError(f"rule.dest invalid IP/CIDR: {dest!r}") from exc

    proto = str(rule.get("proto", "any")).strip().lower() or "any"
    if proto not in _PROTOS:
        raise AclError(f"rule.proto must be one of {_PROTOS}")

    port_raw = rule.get("port")
    port: int | None = None
    if port_raw not in (None, "", 0, "0"):
        try:
            port = int(port_raw)
        except (TypeError, ValueError) as exc:
            raise AclError("rule.port must be an integer") from exc
        if not (1 <= port <= 65535):
            raise AclError("rule.port out of range (1-65535)")
        if proto == "any":
            raise AclError("rule.proto must be tcp or udp when a port is set")

    return {"dest": str(net if "/" in dest else net.network_address), "port": port, "proto": proto}


def _client_host_ip(client: dict) -> str | None:
    """Return the client's WireGuard source IP (no /suffix), or None."""
    raw = str(client.get("ip", "")).split("/")[0].strip()
    if not raw:
        return None
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        return None


def _rule_lines(saddr: str, rule: dict) -> str:
    proto = rule["proto"]
    port = rule["port"]
    daddr_kw = "ip6 daddr" if ":" in rule["dest"] else "ip daddr"
    saddr_kw = "ip6 saddr" if ":" in saddr else "ip saddr"
    base = f"add rule inet wg_acl forward {saddr_kw} {saddr} {daddr_kw} {rule['dest']}"
    if port is not None and proto in ("tcp", "udp"):
        return f"{base} {proto} dport {port} accept"
    return f"{base} accept"


def build_ruleset(clients: dict) -> str:
    """Build an idempotent ``nft -f`` script for all restricted clients."""
    lines = [
        "#!/usr/sbin/nft -f",
        "# Managed by WireSeal -- per-client ACLs. DO NOT EDIT.",
        "add table inet wg_acl",
        "flush table inet wg_acl",
        "add chain inet wg_acl forward { type filter hook forward priority -10 ; policy accept ; }",
        "add rule inet wg_acl forward ct state established,related accept",
    ]
    for name, client in (clients or {}).items():
        acl = client.get("acl") or {}
        if acl.get("mode") != RESTRICTED:
            continue
        saddr = _client_host_ip(client)
        if not saddr:
            log.warning("ACL skipped for %s: no valid client IP", name)
            continue
        rules = acl.get("rules") or []
        saddr_kw = "ip6 saddr" if ":" in saddr else "ip saddr"
        for rule in rules[:_MAX_RULES_PER_CLIENT]:
            try:
                lines.append(_rule_lines(saddr, validate_rule(rule)))
            except AclError as exc:
                log.warning("ACL rule skipped for %s: %s", name, exc)
        # Catch-all drop for this client (after its accept rules).
        lines.append(f"add rule inet wg_acl forward {saddr_kw} {saddr} drop")
    return "\n".join(lines) + "\n"


def apply_client_acls(clients: dict) -> tuple[bool, str | None]:
    """Write + apply the ACL ruleset. Returns (ok, warning_or_none)."""
    if sys.platform != "linux":
        return False, "Per-client ACLs require a Linux server."
    nft = shutil.which("nft")
    if not nft:
        return False, "nftables (nft) is not installed."
    script = build_ruleset(clients)
    try:
        ACL_NFT_FILE.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(ACL_NFT_FILE, script.encode("utf-8"), mode=0o644)
    except OSError as exc:
        return False, f"Could not write ACL file (need root?): {exc}"
    try:
        result = subprocess.run(
            [nft, "-f", str(ACL_NFT_FILE)],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"nft apply failed: {exc}"
    if result.returncode != 0:
        return False, f"nft rejected the ruleset: {result.stderr.strip()}"
    return True, None
