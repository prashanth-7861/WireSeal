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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .secret_types import SecretBytes

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
                    subprocess.run(
                        ["icacls", str(self._log_path), "/grant:r", f"{username}:(R,W)"],
                        check=True,
                        capture_output=True,
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
    # Write API
    # ------------------------------------------------------------------

    def log(
        self,
        action: str,
        metadata: dict,
        success: bool = True,
        error: str | None = None,
    ) -> AuditEntry:
        """Append one entry to the audit log and return it.

        AUDIT-01: _scrub_secrets() is applied to *metadata* before the entry
        is built, ensuring no SecretBytes value or WireGuard private key is
        ever serialised to disk.

        Args:
            action:   Short action-type label (e.g. "dns_update").
            metadata: Arbitrary context dict; secrets will be scrubbed.
            success:  True if the action succeeded.
            error:    Error message if success=False.

        Returns:
            The AuditEntry that was written.

        Raises:
            AuditError: If the log file cannot be written.
        """
        import datetime  # deferred: no side effects at module import

        scrubbed = _scrub_secrets(metadata)
        # Sanitize action and error fields to prevent NDJSON log injection (HIGH-03)
        safe_action = action.replace("\n", " ").replace("\r", " ") if action else action
        safe_error = error.replace("\n", " ").replace("\r", " ") if error else error
        entry = AuditEntry(
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            action=safe_action,
            metadata=scrubbed,  # type: ignore[arg-type]
            success=success,
            error=safe_error,
        )

        try:
            self._ensure_parents_exist()
            is_new = not self._log_path.exists()
            with open(self._log_path, mode="a", encoding="utf-8", newline="\n", buffering=1) as fh:
                fh.write(json.dumps(entry.to_dict()) + "\n")
            # Apply permissions after the first successful write so the file
            # has already been created (and the write completed) before any
            # platform-specific ACL adjustment.  On Windows this avoids a
            # race where icacls would lock out the current non-SYSTEM process
            # before it could complete the open().  AUDIT-02.
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

        AUDIT-03: This method is the retrieval interface for the Phase 4
        audit-log CLI command.

        If the log file does not exist, an empty list is returned instead of
        raising an exception.  Malformed lines are silently skipped.

        Args:
            n: Maximum number of entries to return (default 50).

        Returns:
            List of AuditEntry objects, oldest first.
        """
        if not self._log_path.exists():
            return []

        try:
            lines = self._log_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []

        recent_lines = lines[-n:] if len(lines) > n else lines

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
