"""Append-only audit log for WireSeal.

Every tool action is recorded with an ISO 8601 UTC timestamp, action type,
and metadata dict. Secret values are scrubbed before any entry is written to
disk, so no passphrase, WireGuard private key, or SecretBytes value ever
appears in the log.

Requirements satisfied:
  AUDIT-01 — Timestamps, action types, metadata with no secret leakage.
  AUDIT-02 — Log file permissions: 640 (rw-r-----) on Linux/macOS,
              SYSTEM-only ACL via icacls on Windows.
  AUDIT-03 — get_recent_entries(n) retrieval API for the Phase 4 CLI command.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .secret_types import SecretBytes

# Log rotation constants
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MiB
MAX_ROTATED  = 5                 # keep audit.log.1 through audit.log.5

# WireGuard private keys: base64-encoded 32 bytes, typically 44 chars (43 base64
# chars + one padding '=').  Some test vectors in the codebase use a 43-char
# representation (42 + '='), so the pattern accepts 42 or 43 base64 chars before
# the mandatory trailing '='.  Real wg keys are always 44 chars; the broader
# range ensures the guard is not fooled by similar-length strings.
_KEY_PATTERN = re.compile(r'^[A-Za-z0-9+/]{42,43}=$')


class AuditError(Exception):
    """Base error for audit log failures."""


@dataclass
class AuditEntry:
    """A single immutable audit log record.

    Fields
    ------
    timestamp : str
        ISO 8601 UTC timestamp, e.g. "2026-03-20T14:23:01.123456+00:00".
    action : str
        Short action-type label, e.g. "dns_update", "add_client".
    metadata : dict
        Arbitrary key/value context. Secrets must be scrubbed by the caller
        (or via _scrub_secrets) before populating this field.
    success : bool
        True if the recorded action succeeded.
    error : str | None
        Error message when success=False, otherwise None.
    """

    timestamp: str
    action: str
    metadata: dict
    success: bool
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable plain-dict representation."""
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "metadata": self.metadata,
            "success": self.success,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuditEntry":
        """Deserialize an AuditEntry from a plain dict (e.g. a parsed JSON line)."""
        return cls(
            timestamp=d["timestamp"],
            action=d["action"],
            metadata=d.get("metadata", {}),
            success=d["success"],
            error=d.get("error"),
        )


def _scrub_secrets(obj: object) -> object:
    """Recursively replace secrets in *obj* and return a scrubbed copy.

    Rules (AUDIT-01):
    - SecretBytes instances are replaced with the string "<redacted>".
    - String values that match a WireGuard private-key pattern (base64, 44
      chars, trailing "=") are replaced with "<redacted-key>".
    - Dicts and lists are walked recursively; the input is never mutated.

    Args:
        obj: The value to inspect.  Typically a dict or list, but any type
             is accepted.

    Returns:
        A new object of the same structure with secrets replaced.
    """
    if isinstance(obj, SecretBytes):
        return "<redacted>"
    if isinstance(obj, str):
        if _KEY_PATTERN.match(obj):
            return "<redacted-key>"
        return obj
    if isinstance(obj, dict):
        return {k: _scrub_secrets(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub_secrets(item) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# AuditLog — added in Task 2
# ---------------------------------------------------------------------------


class AuditLog:
    """Append-only audit log backed by a newline-delimited JSON file.

    Design invariants:
    - No file I/O occurs at instantiation or import time.
    - The log file (and any missing parent directories) are created lazily on
      the first call to log().
    - Permissions are enforced at file-creation time:
        Unix  → 0o640 (rw-r-----)
        Windows → SYSTEM + Administrators ACL via icacls (set_file_permissions
                  routes automatically; the mode argument is ignored on Windows)
    - get_recent_entries() is the read API consumed by Phase 4's CLI command.

    Args:
        log_path: Absolute path to the audit log file.
    """

    _class_lock = threading.Lock()  # Thread safety for concurrent API requests

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_parents_exist(self) -> None:
        """Create parent directories for the log file if they are missing."""
        if not self._log_path.parent.exists():
            self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def _apply_permissions(self) -> None:
        """Apply 640 permissions (Unix) or SYSTEM-only ACL (Windows) to the log file.

        Called after the first successful write so the file exists before any
        platform-specific ACL adjustment.  On Windows, icacls grants SYSTEM +
        Administrators and removes all other entries; this requires the process
        to be running as SYSTEM or an Administrator to be effective.  If the
        process lacks privilege, the ACL call may emit a warning (handled inside
        set_file_permissions) but will not raise, ensuring the log remains
        writable even in non-privileged test environments.

        AUDIT-02: 640 on Linux/macOS, SYSTEM+Administrators on Windows.
        """
        import sys
        import warnings
        from .permissions import set_file_permissions  # local import for side-effect safety

        if sys.platform == "win32":
            # On Windows, icacls /inheritance:r removes all inherited ACEs and
            # grants SYSTEM+Administrators only.  In production (running as
            # SYSTEM/Administrator) this is the correct behaviour.  In a
            # non-privileged environment, the call may lock out the current
            # user.  We detect this by probing writability; if locked out, we
            # re-grant the current user write access with a warning so the log
            # remains functional.  Full AUDIT-02 enforcement is only guaranteed
            # when running as SYSTEM or Administrator.
            import subprocess
            try:
                set_file_permissions(self._log_path, mode=0o640)
                # Quick writability probe
                with open(self._log_path, mode="a", encoding="utf-8") as _probe:
                    pass
            except PermissionError:
                # Locked out — restore current user's write access (best-effort)
                try:
                    import getpass
                    username = getpass.getuser()
                    _flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                    subprocess.run(
                        ["icacls", str(self._log_path), "/grant:r", f"{username}:(R,W)"],
                        check=True,
                        capture_output=True,
                        creationflags=_flags,
                    )
                except Exception:
                    pass
                warnings.warn(
                    f"Audit log {self._log_path} SYSTEM-only permissions could not be "
                    "enforced (process lacks Administrator rights). "
                    "AUDIT-02 requires running wireseal as Administrator on Windows.",
                    stacklevel=3,
                )
        else:
            set_file_permissions(self._log_path, mode=0o640)

    # ------------------------------------------------------------------
    # Log rotation
    # ------------------------------------------------------------------

    def _rotate(self) -> None:
        """Rotate the log file when it exceeds MAX_LOG_SIZE.

        Renames audit.log → audit.log.1, shifts .1→.2, etc.
        Deletes the oldest file if count exceeds MAX_ROTATED.
        Applies 0o640 permissions to rotated files on Unix.
        Must be called while holding _class_lock.
        """
        import sys

        # Shift existing rotated files up by one
        for i in range(MAX_ROTATED, 0, -1):
            src = self._log_path.parent / f"{self._log_path.name}.{i}"
            if i == MAX_ROTATED:
                # Delete the oldest
                try:
                    src.unlink(missing_ok=True)
                except OSError:
                    pass
                continue
            dst = self._log_path.parent / f"{self._log_path.name}.{i + 1}"
            if src.exists():
                try:
                    src.rename(dst)
                except OSError:
                    pass

        # Move current log to .1
        dst1 = self._log_path.parent / f"{self._log_path.name}.1"
        try:
            self._log_path.rename(dst1)
            if sys.platform != "win32":
                import os
                os.chmod(dst1, 0o640)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def log(
        self,
        action: str,
        metadata: dict,
        success: bool = True,
        error: str | None = None,
        actor: str | None = None,
    ) -> AuditEntry:
        """Append one entry to the audit log and return it.

        Thread-safe: uses a class-level lock so concurrent API handler threads
        don't corrupt the file. Rotates the log when it exceeds MAX_LOG_SIZE.

        AUDIT-01: _scrub_secrets() is applied to *metadata* before the entry
        is built, ensuring no SecretBytes value or WireGuard private key is
        ever serialised to disk.
        """
        import datetime  # deferred: no side effects at module import

        meta_with_actor = dict(metadata)
        if actor is not None and "actor" not in meta_with_actor:
            meta_with_actor["actor"] = actor
        scrubbed = _scrub_secrets(meta_with_actor)
        scrubbed_error = str(_scrub_secrets(error)) if error else error
        safe_action = action.replace("\n", " ").replace("\r", " ") if action else action
        safe_error = scrubbed_error.replace("\n", " ").replace("\r", " ") if scrubbed_error else scrubbed_error
        entry = AuditEntry(
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            action=safe_action,
            metadata=scrubbed,  # type: ignore[arg-type]
            success=success,
            error=safe_error,
        )

        with self._class_lock:
            try:
                self._ensure_parents_exist()

                # Rotate if the log exceeds the size limit
                if self._log_path.exists():
                    try:
                        if self._log_path.stat().st_size > MAX_LOG_SIZE:
                            self._rotate()
                    except OSError:
                        pass

                is_new = not self._log_path.exists()
                with open(self._log_path, mode="a", encoding="utf-8", newline="\n", buffering=1) as fh:
                    fh.write(json.dumps(entry.to_dict()) + "\n")
                if is_new:
                    self._apply_permissions()
            except OSError as exc:
                raise AuditError(f"Failed to write audit log entry: {exc}") from exc

        return entry

    # ------------------------------------------------------------------
    # Read API (AUDIT-03)
    # ------------------------------------------------------------------

    def get_recent_entries(self, n: int = 50) -> list[AuditEntry]:
        """Return the last *n* log entries, oldest first.

        Reads from rotated files (.1, .2, ...) when the current log doesn't
        have enough entries. AUDIT-03.
        """
        all_lines: list[str] = []

        # Collect lines from rotated files (oldest first) then current
        for i in range(MAX_ROTATED, 0, -1):
            rotated = self._log_path.parent / f"{self._log_path.name}.{i}"
            if rotated.exists():
                try:
                    all_lines.extend(rotated.read_text(encoding="utf-8").splitlines())
                except OSError:
                    continue
            if len(all_lines) >= n:
                break

        # Current log file
        if self._log_path.exists():
            try:
                all_lines.extend(self._log_path.read_text(encoding="utf-8").splitlines())
            except OSError:
                pass

        if not all_lines:
            return []

        recent_lines = all_lines[-n:] if len(all_lines) > n else all_lines

        entries: list[AuditEntry] = []
        for line in recent_lines:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                entries.append(AuditEntry.from_dict(d))
            except Exception:
                continue

        return entries
