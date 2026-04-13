"""WireGuard client tunnel management.

Deploys an imported .conf to a temp file and uses wg-quick to bring
the tunnel up/down. Uses interface name ``wg-client`` to avoid
colliding with the server's ``wg0`` interface.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

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
    """Write the config to the platform config directory.

    Returns the path to the deployed config file.
    """
    config_dir = _get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / f"{CLIENT_INTERFACE}.conf"

    config_path.write_text(config_text, encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(config_path, 0o600)

    return config_path


def _remove_config(config_path: Path) -> None:
    """Remove the deployed config file."""
    try:
        config_path.unlink(missing_ok=True)
    except OSError:
        pass


def tunnel_up(config_text: str, profile_name: str) -> dict[str, str]:
    """Bring up the WireGuard client tunnel.

    Args:
        config_text: Raw WireGuard .conf content.
        profile_name: Name of the profile being connected.

    Returns:
        Status dict with interface name and profile.

    Raises:
        RuntimeError: If tunnel is already up or wg-quick fails.
    """
    with _lock:
        if _state["connected"]:
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
            return {
                "interface": CLIENT_INTERFACE,
                "profile": profile_name,
                "status": "connected",
            }

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
        if not _state["connected"]:
            raise RuntimeError("No active tunnel to disconnect")

        config_path = Path(_state["config_path"])
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
                    subprocess.run(
                        ["wg-quick", "down", str(config_path)],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
            else:
                cmd = [*_sudo_prefix(), "wg-quick", "down", str(config_path)]
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise RuntimeError(f"wg-quick down failed: {stderr}") from exc
        finally:
            _remove_config(config_path)
            _state["connected"] = False
            _state["active_profile"] = None
            _state["config_path"] = None

        return {
            "interface": CLIENT_INTERFACE,
            "profile": profile_name,
            "status": "disconnected",
        }


def tunnel_status() -> dict[str, Any]:
    """Get current tunnel status.

    If connected, also queries wg show for live stats.
    """
    with _lock:
        if not _state["connected"]:
            return {
                "connected": False,
                "profile": None,
                "interface": CLIENT_INTERFACE,
            }

        result: dict[str, Any] = {
            "connected": True,
            "profile": _state["active_profile"],
            "interface": CLIENT_INTERFACE,
        }

        # Try to get live stats from wg show
        try:
            cmd = [*_sudo_prefix(), "wg", "show", CLIENT_INTERFACE]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=5,
            )
            if proc.returncode == 0:
                result["wg_output"] = proc.stdout.decode("utf-8", errors="replace")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return result
