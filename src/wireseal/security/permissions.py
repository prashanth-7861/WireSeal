"""Cross-platform file and directory permission enforcement for WireSeal.

Sets restrictive permissions on WireGuard config files and the vault directory:
  - Unix: standard chmod (0o600 for files, 0o700 for directories)
  - Windows: icacls to restrict to SYSTEM + Administrators only

CONFIG-03: Config files written with 600 permissions (Unix) / SYSTEM+Admins ACL (Windows).
VAULT-02:  Vault directory restricted to owner only.
"""

import os
import stat
import subprocess
import sys
import warnings
from pathlib import Path

# On Windows, prevent subprocess calls (icacls) from flashing a console window.
_SP_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def set_file_permissions(path: Path, mode: int = 0o600) -> None:
    """Set restrictive permissions on a file.

    Unix: chmod to the given mode (default 0o600 = owner read/write only).
    Windows: use icacls to grant read/write to SYSTEM and Administrators only,
             removing all inherited permissions. Falls back to pywin32 if available,
             or logs a warning if neither succeeds.

    Args:
        path: Path to the file.
        mode: Unix permission mode (default 0o600). Ignored on Windows.
    """
    if sys.platform != "win32":
        os.chmod(path, mode)
    else:
        _set_windows_file_permissions(path)


def set_dir_permissions(path: Path, mode: int = 0o700) -> None:
    """Set restrictive permissions on a directory.

    Unix: chmod to the given mode (default 0o700 = owner read/write/execute only).
    Windows: use icacls with container/object inheritance flags for SYSTEM + Administrators.

    Args:
        path: Path to the directory.
        mode: Unix permission mode (default 0o700). Ignored on Windows.
    """
    if sys.platform != "win32":
        os.chmod(path, mode)
    else:
        _set_windows_dir_permissions(path)


def check_file_permissions(path: Path) -> bool:
    """Check whether a file has the expected restrictive permissions.

    Unix: returns True if mode is exactly 0o600.
    Windows: best-effort check by parsing icacls output for unexpected grants.

    Args:
        path: Path to the file to check.

    Returns:
        True if permissions appear correct, False if not or if check is inconclusive.
    """
    if sys.platform != "win32":
        current_mode = stat.S_IMODE(path.stat().st_mode)
        return current_mode == 0o600
    else:
        return _check_windows_permissions(path)


# ---------------------------------------------------------------------------
# Windows helpers
# ---------------------------------------------------------------------------


def _set_windows_file_permissions(path: Path) -> None:
    """Set SYSTEM + Administrators + current user R,W permissions on a file using icacls."""
    try:
        current_user = os.environ.get("USERNAME", "")
        cmd = [
            "icacls", str(path),
            "/inheritance:r",
            "/grant:r", "SYSTEM:(R,W)",
            "/grant:r", "Administrators:(R,W)",
        ]
        if current_user:
            cmd.extend(["/grant:r", f"{current_user}:(R,W)"])
        subprocess.run(cmd, check=True, capture_output=True, creationflags=_SP_FLAGS)
    except Exception as exc:
        # Try pywin32 as fallback
        if _try_pywin32_file_permissions(path):
            return
        warnings.warn(
            f"Could not set restrictive permissions on {path}: {exc}. "
            "The file may be accessible to other users. "
            "Run as Administrator or ensure icacls is available.",
            stacklevel=3,
        )


def _set_windows_dir_permissions(path: Path) -> None:
    """Set SYSTEM + Administrators + current user full control on a directory using icacls."""
    try:
        current_user = os.environ.get("USERNAME", "")
        cmd = [
            "icacls", str(path),
            "/inheritance:r",
            "/grant:r", "SYSTEM:(OI)(CI)F",
            "/grant:r", "Administrators:(OI)(CI)F",
        ]
        if current_user:
            cmd.extend(["/grant:r", f"{current_user}:(OI)(CI)F"])
        subprocess.run(cmd, check=True, capture_output=True, creationflags=_SP_FLAGS)
    except Exception as exc:
        warnings.warn(
            f"Could not set restrictive permissions on directory {path}: {exc}. "
            "The directory may be accessible to other users.",
            stacklevel=3,
        )


def _try_pywin32_file_permissions(path: Path) -> bool:
    """Attempt to set permissions using pywin32, if available.

    Returns True if successful, False if pywin32 is not installed or fails.
    """
    try:
        import win32security  # type: ignore[import]
        import ntsecuritycon as con  # type: ignore[import]

        sd = win32security.GetFileSecurity(
            str(path), win32security.DACL_SECURITY_INFORMATION
        )
        dacl = win32security.ACL()

        for account_name in ("SYSTEM", "Administrators"):
            sid, _, _ = win32security.LookupAccountName(None, account_name)
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
                sid,
            )

        sd.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetFileSecurity(
            str(path), win32security.DACL_SECURITY_INFORMATION, sd
        )
        return True
    except ImportError:
        return False
    except Exception:
        return False


def _check_windows_permissions(path: Path) -> bool:
    """Best-effort check for restrictive Windows ACL via icacls output parsing."""
    try:
        result = subprocess.run(
            ["icacls", str(path)],
            capture_output=True,
            text=True,
            check=True,
            creationflags=_SP_FLAGS,
        )
        output = result.stdout
        # A file with correct permissions should only list SYSTEM and Administrators.
        # If we see "Everyone", "Users", or "Authenticated Users", permissions are too open.
        bad_entries = ["Everyone", "Users:", "Authenticated Users"]
        return not any(bad in output for bad in bad_entries)
    except Exception:
        return False
