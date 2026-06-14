"""Scheduled-backup installer + out-of-vault config for unattended runs.

A scheduled backup only needs to *copy the already-encrypted vault file* to a
destination — it never decrypts anything — so it can run without the vault
passphrase. This module persists the non-secret backup settings (plus the
WebDAV password, like the DuckDNS updater) to a root-only env file, then
installs an OS scheduler entry that invokes ``wireseal backup
--non-interactive`` on an interval.

Platform support:
  - Linux / macOS: ``/etc/cron.d/wireseal-backup`` (root crontab fragment)
  - Windows:       Scheduled Task ``WireSealBackup`` via ``schtasks``

Scheduling is best-effort: if the OS scheduler can't be written (e.g. the
server isn't running as root), ``install_schedule`` raises ``ScheduleError``
and the caller surfaces a warning — the manual "Trigger Backup Now" path is
unaffected.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..security.atomic import atomic_write
from ..security.validator import validate_script_path

# Valid schedule keywords → human label + cron time expression.
SCHEDULES: dict[str, str] = {
    "off": "",
    "hourly": "0 * * * *",
    "daily": "0 3 * * *",       # 03:00 local
    "weekly": "0 3 * * 0",      # Sunday 03:00 local
}

_CRON_FILE = Path("/etc/cron.d/wireseal-backup")
_WIN_TASK_NAME = "WireSealBackup"


class ScheduleError(RuntimeError):
    """Raised when an OS scheduler entry cannot be installed or removed."""


# ---------------------------------------------------------------------------
# Out-of-vault env file (so cron can run without the passphrase)
# ---------------------------------------------------------------------------

def backup_env_path() -> Path:
    """Return the platform-appropriate path for the backup env file."""
    if sys.platform == "win32":
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "WireSeal"
        return base / "backup.env"
    return Path("/etc/wireseal/backup.env")


# Keys persisted to the env file. webdav_pass is the only secret; it lives in
# a 0600 root-owned file exactly like the DuckDNS token.
_ENV_KEYS = (
    "destination", "local_path", "ssh_host", "ssh_user", "ssh_path",
    "webdav_url", "webdav_user", "webdav_pass", "keep_n",
)


def _sanitize_env_value(value: object) -> str:
    """Flatten a config value to a single safe env line value (no newlines)."""
    s = "" if value is None else str(value)
    # Strip CR/LF so a crafted value can't inject extra KEY=VALUE lines.
    return s.replace("\r", "").replace("\n", "")


def write_backup_env(cfg: dict, vault_path: Path) -> Path:
    """Persist non-interactive backup settings to a root-only env file.

    Args:
        cfg: The merged backup_config dict (may include webdav_pass).
        vault_path: Path to the live vault that will be copied.

    Returns:
        The path written.
    """
    path = backup_env_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [f"VAULT_PATH={_sanitize_env_value(vault_path)}"]
    for key in _ENV_KEYS:
        if key in cfg and cfg[key] not in (None, ""):
            lines.append(f"{key.upper()}={_sanitize_env_value(cfg[key])}")
    content = "\n".join(lines) + "\n"

    atomic_write(path, content.encode("utf-8"), mode=0o600)
    return path


def read_backup_env() -> dict | None:
    """Read the backup env file written by :func:`write_backup_env`.

    Returns a config dict (with ``vault_path``) or ``None`` if absent.
    """
    path = backup_env_path()
    if not path.exists():
        return None
    cfg: dict[str, object] = {}
    vault_path: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or "=" not in raw:
            continue
        key, _, value = raw.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "vault_path":
            vault_path = value
        elif key in _ENV_KEYS:
            cfg[key] = int(value) if key == "keep_n" and value.isdigit() else value
    if vault_path is None:
        return None
    cfg["vault_path"] = vault_path
    return cfg


def remove_backup_env() -> None:
    """Delete the backup env file if present (best-effort)."""
    try:
        backup_env_path().unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


# ---------------------------------------------------------------------------
# OS scheduler entry
# ---------------------------------------------------------------------------

def _wireseal_executable() -> Path:
    """Resolve the wireseal CLI entry point for the scheduler command."""
    found = shutil.which("wireseal")
    if found:
        return Path(found)
    # Fallback: the running interpreter's script dir.
    candidate = Path(sys.argv[0]) if sys.argv and sys.argv[0] else Path("wireseal")
    return candidate


def build_cron_content(schedule: str, exe: Path) -> str:
    """Build the /etc/cron.d/wireseal-backup fragment for *schedule*."""
    import shlex
    expr = SCHEDULES[schedule]
    # SEC (H-01): shell-quote the executable path so spaces/metacharacters in
    # the resolved path cannot split the cron command into a different binary.
    return (
        "# Managed by WireSeal -- DO NOT EDIT\n"
        f"{expr} root {shlex.quote(str(exe))} backup --non-interactive\n"
    )


def install_schedule(schedule: str) -> None:
    """Install an OS scheduler entry that runs the unattended backup.

    Args:
        schedule: one of ``hourly`` | ``daily`` | ``weekly``.

    Raises:
        ScheduleError: if the entry cannot be written, or schedule is invalid.
    """
    if schedule not in SCHEDULES or schedule == "off":
        raise ScheduleError(f"Invalid backup schedule: {schedule!r}")

    exe = _wireseal_executable()
    try:
        validate_script_path(exe)
    except Exception as exc:  # validator raises ValueError/OSError variants
        raise ScheduleError(f"Refusing to schedule unsafe executable path: {exc}") from exc

    if sys.platform == "win32":
        _install_windows(schedule, exe)
    else:
        _install_cron(schedule, exe)


def remove_schedule() -> None:
    """Remove the OS scheduler entry (best-effort, no error if absent)."""
    if sys.platform == "win32":
        subprocess.run(
            ["schtasks", "/delete", "/tn", _WIN_TASK_NAME, "/f"],
            shell=False, capture_output=True, timeout=30,
        )
    else:
        try:
            _CRON_FILE.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ScheduleError(f"Could not remove cron entry: {exc}") from exc


def schedule_status() -> dict:
    """Return ``{"schedule_active": bool}`` reflecting the installed entry."""
    if sys.platform == "win32":
        result = subprocess.run(
            ["schtasks", "/query", "/tn", _WIN_TASK_NAME],
            shell=False, capture_output=True, timeout=30,
        )
        return {"schedule_active": result.returncode == 0}
    return {"schedule_active": _CRON_FILE.exists()}


def _install_cron(schedule: str, exe: Path) -> None:
    content = build_cron_content(schedule, exe)
    parent = _CRON_FILE.parent
    try:
        if not parent.exists():
            parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        atomic_write(_CRON_FILE, content.encode("utf-8"), mode=0o644)
    except OSError as exc:
        raise ScheduleError(
            f"Could not write {_CRON_FILE} (need root?): {exc}"
        ) from exc


# Map schedule → schtasks /sc + optional /d arguments.
_WIN_SCHED_ARGS: dict[str, list[str]] = {
    "hourly": ["/sc", "hourly"],
    "daily": ["/sc", "daily", "/st", "03:00"],
    "weekly": ["/sc", "weekly", "/d", "SUN", "/st", "03:00"],
}


def _install_windows(schedule: str, exe: Path) -> None:
    args = _WIN_SCHED_ARGS[schedule]
    cmd = [
        "schtasks", "/create", "/tn", _WIN_TASK_NAME, "/f",
        "/ru", "SYSTEM",
        "/tr", f'"{exe}" backup --non-interactive',
        *args,
    ]
    result = subprocess.run(cmd, shell=False, capture_output=True, timeout=30)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise ScheduleError(f"schtasks failed: {stderr}")
