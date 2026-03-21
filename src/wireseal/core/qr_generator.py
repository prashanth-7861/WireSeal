"""In-memory QR code generator for WireGuard client configs.

Generates ASCII QR codes from WireGuard client config strings using the
qrcode library. No image file is ever written by generate_qr_terminal —
the config string (which contains the client private key) stays in memory.

CLIENT-04: ASCII terminal QR, 60-second auto-clear.
CLIENT-08: --save-qr writes to disk with 600 permissions;
           --auto-delete removes the file after 5 minutes via daemon timer.

Security note: config_str contains the client private key. It must not be
written to disk by generate_qr_terminal. Only save_qr (called explicitly
by the user with --save-qr) writes it to disk, with restrictive permissions
and a clear private-key warning.
"""

import io
import threading
import warnings
from pathlib import Path

import qrcode
import qrcode.constants

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

#: Seconds before the terminal is cleared after displaying a QR code.
QR_DISPLAY_TIMEOUT = 60


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_qr_terminal(config_str: str) -> str:
    """Generate an ASCII QR code from a WireGuard config string.

    The config_str (which contains the client private key) is encoded
    entirely in memory using qrcode.QRCode and io.StringIO. No file is
    written at any point.

    Args:
        config_str: Full WireGuard client config as a string (may contain
                    [Interface], PrivateKey, etc.).

    Returns:
        ASCII art QR code as a plain string (ready to print to the terminal).
    """
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=1,
        border=1,
    )
    qr.add_data(config_str)
    qr.make(fit=True)

    buffer = io.StringIO()
    qr.print_ascii(out=buffer)
    return buffer.getvalue()


def save_qr(
    config_str: str,
    path: Path,
    auto_delete: bool = False,
) -> None:
    """Save an ASCII QR code to a file with restrictive permissions.

    Generates the QR code in memory via generate_qr_terminal, then writes
    it to path as UTF-8 text with 600 permissions (owner read/write only on
    Unix; SYSTEM + Administrators ACL on Windows).

    If auto_delete=True, a daemon timer is started that calls path.unlink()
    after 300 seconds (5 minutes), satisfying CLIENT-08 --auto-delete.

    Args:
        config_str:  Full WireGuard client config string (contains private key).
        path:        Destination file path.
        auto_delete: If True, schedule the file for deletion after 5 minutes.
    """
    from wireseal.security.permissions import set_file_permissions

    # Generate QR in memory — the config_str never hits disk via this path
    qr_ascii = generate_qr_terminal(config_str)

    # Write to the requested path as UTF-8 text
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(qr_ascii, encoding="utf-8")

    # Apply restrictive permissions: 0o600 on Unix, Windows ACL equivalent
    set_file_permissions(path, mode=0o600)

    if auto_delete:
        warnings.warn(
            f"QR file will be auto-deleted in 5 minutes: {path}",
            stacklevel=2,
        )
        # Daemon timer: does not prevent interpreter exit
        timer = threading.Timer(300, _safe_unlink, args=(path,))
        timer.daemon = True
        timer.start()

    print(f"QR code written to: {path}")
    print("WARNING: This file contains a private key. Delete it after use.")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_unlink(path: Path) -> None:
    """Silently delete *path* if it still exists (used by auto-delete timer)."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
