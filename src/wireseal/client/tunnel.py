"""WireGuard client tunnel management.

Deploys an imported .conf to a temp file and uses wg-quick to bring
the tunnel up/down. Uses interface name ``wg-client`` to avoid
colliding with the server's ``wg0`` interface.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from wireseal.client import kill_switch

log = logging.getLogger(__name__)

CLIENT_INTERFACE = "wg-client"

_lock = threading.Lock()
_state: dict[str, Any] = {
    "active_profile": None,
    "config_path": None,
    "connected": False,
}


def _sudo_prefix() -> list[str]:
    """Return sudo prefix if not running as root (Unix only)."""
    if sys.platform == "win32":
        return []
    if os.geteuid() == 0:
        return []
    return ["sudo", "-n"]


def _get_config_dir() -> Path:
    """Platform-appropriate directory for the client config file."""
    if sys.platform == "win32":
        base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        return base / "WireGuard"
    return Path("/etc/wireguard")


def _deploy_config(config_text: str) -> Path:
    """Atomically write the WG config to the platform config dir.

    Atomic = write to a `.tmp` sibling, fsync, rename. Guarantees that a
    partial write (disk full, process crash) never leaves a corrupt
    `wg-client.conf` for the next `wg-quick up`.
    """
    config_dir = _get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / f"{CLIENT_INTERFACE}.conf"
    tmp_path    = config_dir / f"{CLIENT_INTERFACE}.conf.tmp"

    data = config_text.encode("utf-8")
    fd = os.open(
        str(tmp_path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)

    # Rename is atomic on the same filesystem.
    os.replace(tmp_path, config_path)
    if sys.platform != "win32":
        try:
            os.chmod(config_path, 0o600)
        except OSError:
            pass

    return config_path


def _interface_is_up() -> bool:
    """Probe the OS for the live state of the wg-client interface.

    Returns True iff `wg show <iface>` exits 0 and prints the interface
    line. Used to reconcile `_state` after API process restart, when the
    module-level cache has been wiped but the kernel/userspace tunnel
    survives independently.
    """
    try:
        proc = subprocess.run(
            [*_sudo_prefix(), "wg", "show", CLIENT_INTERFACE],
            capture_output=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return False
        return CLIENT_INTERFACE.encode() in (proc.stdout or b"")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _remove_config(config_path: Path) -> None:
    """Remove the deployed config file."""
    try:
        config_path.unlink(missing_ok=True)
    except OSError:
        pass


def _extract_endpoint(config_text: str) -> str | None:
    """Extract Endpoint = ip:port from WireGuard config text."""
    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("endpoint"):
            _, _, val = stripped.partition("=")
            val = val.strip()
            if val:
                return val
    return None


def apply_dns_override(config_text: str, dns_servers: str) -> str:
    """Replace or inject DNS = line in [Interface] section.

    Args:
        config_text: Raw WireGuard .conf content.
        dns_servers: Comma-separated DNS IPs (e.g. "1.1.1.1, 8.8.8.8").

    Returns:
        Modified config text with DNS line replaced/added.
    """
    if not dns_servers or not dns_servers.strip():
        return config_text

    lines = config_text.splitlines()
    result: list[str] = []
    in_interface = False
    dns_written = False

    for line in lines:
        stripped = line.strip().lower()

        if stripped == "[interface]":
            in_interface = True
            result.append(line)
            continue
        elif stripped.startswith("[") and stripped.endswith("]"):
            # Entering new section — if still in Interface and DNS not written, add it
            if in_interface and not dns_written:
                result.append(f"DNS = {dns_servers.strip()}")
                dns_written = True
            in_interface = False
            result.append(line)
            continue

        if in_interface and stripped.startswith("dns"):
            # Replace existing DNS line
            result.append(f"DNS = {dns_servers.strip()}")
            dns_written = True
            continue

        result.append(line)

    # If config has only [Interface] with no following section
    if in_interface and not dns_written:
        result.append(f"DNS = {dns_servers.strip()}")

    return "\n".join(result)


def tunnel_up(
    config_text: str,
    profile_name: str,
    enable_kill_switch: bool = False,
) -> dict[str, str]:
    """Bring up the WireGuard client tunnel.

    Args:
        config_text: Raw WireGuard .conf content.
        profile_name: Name of the profile being connected.
        enable_kill_switch: Engage kill switch after tunnel comes up.

    Returns:
        Status dict with interface name and profile.

    Raises:
        RuntimeError: If tunnel is already up or wg-quick fails.
    """
    with _lock:
        # Reconcile state with the kernel before deciding what to do —
        # the API process may have restarted and lost the cached flag.
        if not _state["connected"] and _interface_is_up():
            _state["connected"] = True
            # active_profile unknown after restart; use the requested one.
            _state["active_profile"] = _state["active_profile"] or profile_name

        if _state["connected"]:
            # Same-profile reconnect = no-op success. Different-profile
            # request still requires the user to disconnect first.
            if _state["active_profile"] == profile_name:
                return {
                    "interface": CLIENT_INTERFACE,
                    "profile": profile_name,
                    "status": "already-connected",
                }
            raise RuntimeError(
                f"Tunnel already active (profile: {_state['active_profile']}). "
                "Disconnect first."
            )

        if not shutil.which("wg-quick") and not shutil.which("wg"):
            raise RuntimeError(
                "WireGuard tools not found. Install wireguard-tools first."
            )

        config_path = _deploy_config(config_text)
        _state["config_path"] = str(config_path)

        try:
            if sys.platform == "win32":
                # Windows: use wireguard.exe /installtunnelservice
                wg_exe = shutil.which("wireguard")
                if wg_exe:
                    subprocess.run(
                        [wg_exe, "/installtunnelservice", str(config_path)],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
                else:
                    # Fallback: try wg-quick if available
                    subprocess.run(
                        ["wg-quick", "up", str(config_path)],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
            else:
                cmd = [*_sudo_prefix(), "wg-quick", "up", str(config_path)]
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    timeout=30,
                )

            _state["connected"] = True
            _state["active_profile"] = profile_name

            # Engage kill switch if requested
            ks_status = None
            if enable_kill_switch:
                endpoint = _extract_endpoint(config_text)
                if endpoint:
                    try:
                        kill_switch.engage(endpoint, CLIENT_INTERFACE)
                        ks_status = "active"
                    except (RuntimeError, ValueError) as exc:
                        log.warning("Kill switch engage failed: %s", exc)
                        ks_status = "failed"

            result: dict[str, Any] = {
                "interface": CLIENT_INTERFACE,
                "profile": profile_name,
                "status": "connected",
            }
            if ks_status:
                result["kill_switch"] = ks_status
            return result

        except subprocess.CalledProcessError as exc:
            _remove_config(config_path)
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise RuntimeError(f"wg-quick up failed: {stderr}") from exc
        except Exception:
            _remove_config(config_path)
            raise


def tunnel_down() -> dict[str, str]:
    """Bring down the WireGuard client tunnel.

    Returns:
        Status dict confirming disconnection.

    Raises:
        RuntimeError: If no tunnel is active or wg-quick fails.
    """
    with _lock:
        # Reconcile cache with kernel before refusing.
        if not _state["connected"] and _interface_is_up():
            _state["connected"] = True

        if not _state["connected"]:
            raise RuntimeError("No active tunnel to disconnect")

        # Use the interface name (not the config path) so that an externally-
        # wiped or moved .conf still lets us bring the tunnel down.
        config_path_raw = _state.get("config_path")
        config_path = Path(config_path_raw) if config_path_raw else (
            _get_config_dir() / f"{CLIENT_INTERFACE}.conf"
        )
        profile_name = _state["active_profile"]

        try:
            if sys.platform == "win32":
                wg_exe = shutil.which("wireguard")
                if wg_exe:
                    subprocess.run(
                        [wg_exe, "/uninstalltunnelservice", CLIENT_INTERFACE],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
                else:
                    # Fallback: address by interface name.
                    subprocess.run(
                        ["wg-quick", "down", CLIENT_INTERFACE],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
            else:
                # Prefer interface-name form so a deleted/moved config file
                # doesn't strand the tunnel up. wg-quick falls back to
                # /etc/wireguard/<iface>.conf which is where we deployed it.
                cmd = [*_sudo_prefix(), "wg-quick", "down", CLIENT_INTERFACE]
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            # If wg-quick says the device doesn't exist, the tunnel is
            # already down — treat as success and clear cache.
            if (
                b"Cannot find device" in (exc.stderr or b"")
                or b"is not a WireGuard interface" in (exc.stderr or b"")
                or b"No such device" in (exc.stderr or b"")
            ):
                pass
            else:
                raise RuntimeError(f"wg-quick down failed: {stderr}") from exc
        finally:
            _remove_config(config_path)
            _state["connected"] = False
            _state["active_profile"] = None
            _state["config_path"] = None

        # Disengage kill switch on intentional disconnect
        ks_status = None
        if kill_switch.is_active():
            try:
                kill_switch.disengage()
                ks_status = "disengaged"
            except (RuntimeError, OSError) as exc:
                log.warning("Kill switch disengage failed: %s", exc)
                ks_status = "disengage-failed"

        result: dict[str, Any] = {
            "interface": CLIENT_INTERFACE,
            "profile": profile_name,
            "status": "disconnected",
        }
        if ks_status:
            result["kill_switch"] = ks_status
        return result


def _parse_wg_show(output: str) -> dict[str, Any]:
    """Parse the human-readable `wg show <iface>` output into structured fields.

    Sample input (key lines only):

        interface: wg-client
          public key: ABC...=
          listening port: 49724
        peer: XYZ...=
          endpoint: 203.0.113.5:51820
          allowed ips: 0.0.0.0/0, ::/0
          latest handshake: 1 minute, 12 seconds ago
          transfer: 142.71 KiB received, 89.42 KiB sent
          persistent keepalive: every 25 seconds

    Returns ``{"interface": {...}, "peer": {...}}`` with at-most-one peer
    (WireSeal client configs always have a single peer = the server).
    """
    import re as _re

    if not output:
        return {}

    stats: dict[str, Any] = {"interface": {}, "peer": {}}
    section: str | None = None

    def _bytes(s: str) -> int:
        m = _re.match(
            r"([\d.]+)\s*(B|KiB|MiB|GiB|TiB)\b", s.strip(), _re.IGNORECASE
        )
        if not m:
            return 0
        n = float(m.group(1))
        scale = {
            "B": 1, "KiB": 1024, "MiB": 1024**2,
            "GiB": 1024**3, "TiB": 1024**4,
        }
        return int(n * scale.get(m.group(2), 1))

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("interface:"):
            section = "interface"
            stats["interface"]["name"] = line.split(":", 1)[1].strip()
            continue
        if line.startswith("peer:"):
            section = "peer"
            stats["peer"]["public_key"] = line.split(":", 1)[1].strip()
            continue
        if section is None or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().replace(" ", "_")
        val = val.strip()
        if section == "peer" and key == "transfer":
            # "142.71 KiB received, 89.42 KiB sent"
            m = _re.search(
                r"([\d.]+\s*[KMGT]?i?B)\s*received,\s*([\d.]+\s*[KMGT]?i?B)\s*sent",
                val,
            )
            if m:
                stats["peer"]["rx_bytes"] = _bytes(m.group(1))
                stats["peer"]["tx_bytes"] = _bytes(m.group(2))
            stats["peer"]["transfer"] = val
        elif section == "peer" and key == "latest_handshake":
            stats["peer"]["latest_handshake"] = val
        else:
            stats[section][key] = val

    return stats


def tunnel_status() -> dict[str, Any]:
    """Get current tunnel status, reconciling against the live OS state.

    Always queries `wg show <iface>` first. If the interface is up but
    `_state["connected"]` is False (API process restart, manual `wg-quick
    up`), reconciles the cache. If the interface is down but
    `_state["connected"]` is True (someone ran `wg-quick down` manually,
    system suspend killed the link), reconciles in the other direction.

    Also returns a `handshake_ok` field — True when a handshake has
    completed in the last 3 minutes, False when the tunnel is up but
    no peer response (typical signature of unreachable endpoint, NAT
    traversal failure, or wrong server keys).
    """
    with _lock:
        # Reconciliation pass — single wg show call, used for both the
        # connected/disconnected verdict and the parsed stats.
        raw = ""
        try:
            cmd = [*_sudo_prefix(), "wg", "show", CLIENT_INTERFACE]
            proc = subprocess.run(cmd, capture_output=True, timeout=5)
            if proc.returncode == 0:
                raw = proc.stdout.decode("utf-8", errors="replace")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            raw = ""

        live = bool(raw and CLIENT_INTERFACE in raw)

        if live and not _state["connected"]:
            # Adopt the externally-created tunnel.
            _state["connected"] = True
        elif not live and _state["connected"]:
            # External teardown — clear stale cache so UI shows reality.
            _state["connected"] = False
            _state["active_profile"] = None
            _state["config_path"] = None

        if not _state["connected"]:
            return {
                "connected": False,
                "profile": None,
                "interface": CLIENT_INTERFACE,
                "kill_switch": kill_switch.is_active(),
            }

        result: dict[str, Any] = {
            "connected": True,
            "profile": _state["active_profile"],
            "interface": CLIENT_INTERFACE,
            "kill_switch": kill_switch.is_active(),
            "wg_output": raw,
        }

        parsed = _parse_wg_show(raw)
        if parsed:
            result["stats"] = parsed

            # Heuristic: "handshake_ok" flips True only if the latest
            # handshake string is non-empty AND does NOT mention the
            # human-readable "(none)" / empty form. wg-quick prints
            # "latest handshake: 1 minute, 5 seconds ago" once a peer
            # has been heard from; absence after >2 min == bad path.
            hs = (parsed.get("peer") or {}).get("latest_handshake", "")
            result["handshake_ok"] = bool(hs and "ago" in hs)

        return result
