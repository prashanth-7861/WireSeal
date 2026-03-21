"""Shared atomic file write helper for WireSeal.

Used by vault.py and config_builder.py to ensure all sensitive files are
written atomically with correct permissions set before the file becomes
visible at its final path.

Security properties:
  - Temp file created in same directory (same filesystem -- guaranteed atomic rename)
  - Unix: permissions set on temp file BEFORE rename (never world-readable mid-write)
  - os.fsync() flushes data to disk before rename
  - os.replace() is atomic on POSIX; uses MoveFileExW on Windows (best available)
  - Unix: parent directory fsync after rename (rename survives crash)
  - BaseException cleanup: temp file deleted on any failure (KeyboardInterrupt included)
"""

import os
import sys
import tempfile
from pathlib import Path


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write data to path atomically using temp file + fsync + os.replace.

    The destination file is never world-readable at any point:
      - Temp file is created in the same directory (same filesystem)
      - On Unix, permissions are set on the temp file BEFORE rename
      - os.fsync() ensures data is flushed to disk before rename
      - os.replace() is atomic on POSIX; on Windows it wraps MoveFileExW
        which is not guaranteed atomic but is the best available option

    Args:
        path: Destination path. Parent directory must exist.
        data: Binary data to write.
        mode: File permission bits (default 0o600 = owner read/write only).
              Ignored on Windows (ACL-based permissions).
    """
    parent = path.parent
    fd = -1
    tmp_path: Path | None = None

    try:
        fd, tmp_path_str = tempfile.mkstemp(dir=parent, prefix=".tmp_wga_")
        tmp_path = Path(tmp_path_str)

        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1  # mark closed so finally block skips double-close

        if sys.platform != "win32":
            # Set permissions BEFORE rename -- file is never world-readable
            os.chmod(tmp_path, mode)

        os.replace(tmp_path, str(path))
        tmp_path = None  # rename succeeded -- nothing to clean up

        # Flush the directory entry on POSIX (ensures rename survives crash)
        if sys.platform != "win32":
            dir_fd = os.open(str(parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    except BaseException:
        # Clean up temp file on any failure (including KeyboardInterrupt)
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
