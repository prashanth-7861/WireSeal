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

import hashlib
import itertools
import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .secret_types import SecretBytes

# SEC-025: genesis hash for the audit log chain. The first real entry's
# chain_hash is sha256(GENESIS_HASH_HEX + canonical_json_without_chain).
# Using a fixed, published constant lets operators detect truncation: if
# the on-disk first record's prev_hash is not this constant, someone has
# cut off the head of the log.
_AUDIT_GENESIS_HASH = "0" * 64

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
    prev_hash: str | None = None   # SEC-025: parent entry's chain_hash
    chain_hash: str | None = None  # SEC-025: sha256(prev_hash + canonical body)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable plain-dict representation."""
        out: dict[str, Any] = {
            "timestamp": self.timestamp,
            "action": self.action,
            "metadata": self.metadata,
            "success": self.success,
            "error": self.error,
        }
        if self.prev_hash is not None:
            out["prev_hash"] = self.prev_hash
        if self.chain_hash is not None:
            out["chain_hash"] = self.chain_hash
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuditEntry":
        """Deserialize an AuditEntry from a plain dict (e.g. a parsed JSON line)."""
        return cls(
            timestamp=d["timestamp"],
            action=d["action"],
            metadata=d.get("metadata", {}),
            success=d["success"],
            error=d.get("error"),
            prev_hash=d.get("prev_hash"),
            chain_hash=d.get("chain_hash"),
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
    - get_recent_entries() is the read API consumed by the CLI/CLI command.
    - session_start() creates a per-session log file at ``<sessions_dir>/``
      that captures all log() calls until session_end() is called.
    - Session logs are named ``session-YYYYMMDD-HHMMSS-<random>.log``.

    Args:
        log_path: Absolute path to the audit log file.
    """

    _class_lock = threading.Lock()  # Thread safety for concurrent API requests
    _session_active = False
    _session_path: Path | None = None
    _session_file: object = None  # open file handle for the session log

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path

    # ------------------------------------------------------------------
    # Session log management
    # ------------------------------------------------------------------

    def session_start(self, sessions_dir: Path) -> str:
        """Open a per-session audit log file.

        All subsequent ``log()`` calls will also be written to this file
        until ``session_end()`` is called.

        Args:
            sessions_dir: Directory where session logs are stored (e.g.
                          ``~/.wireseal/sessions/``).

        Returns:
            The session id string (embedded in the filename).
        """
        import secrets as _secrets
        import time as _time
        ts = _time.strftime("%Y%m%d-%H%M%S", _time.gmtime())
        sid = _secrets.token_hex(4)  # 8 hex chars
        sessions_dir.mkdir(parents=True, exist_ok=True)
        path = sessions_dir / f"session-{ts}-{sid}.log"
        self._session_path = path
        self._session_file = open(path, "a", encoding="utf-8")
        self._session_file.write(
            f"{{\"event\": \"session-start\", \"session_id\": \"{sid}\", "
            f"\"timestamp\": \"{_time.strftime('%Y-%m-%dT%H:%M:%S', _time.gmtime())}Z\"}}\n"
        )
        self._session_file.flush()
        self._session_active = True
        return sid

    def session_end(self) -> None:
        """Close the per-session audit log file."""
        if self._session_file:
            import time as _time
            try:
                self._session_file.write(
                    f"{{\"event\": \"session-end\", "
                    f"\"timestamp\": \"{_time.strftime('%Y-%m-%dT%H:%M:%S', _time.gmtime())}Z\"}}\n"
                )
                self._session_file.flush()
                self._session_file.close()
            except Exception:
                pass
        self._session_active = False
        self._session_path = None
        self._session_file = None

    @classmethod
    def list_session_logs(cls, sessions_dir: Path) -> list[dict]:
        """List all session log files with their metadata.

        Returns a list of dicts with keys: name, path, size, created.
        Sorted newest first.
        """
        import time as _time
        results = []
        if not sessions_dir.is_dir():
            return results
        for f in sorted(sessions_dir.glob("session-*.log"), reverse=True):
            try:
                stat = f.stat()
                results.append({
                    "name": f.name,
                    "path": str(f),
                    "size": stat.st_size,
                    "created": _time.strftime(
                        "%Y-%m-%dT%H:%M:%S", _time.localtime(stat.st_mtime)
                    ),
                })
            except OSError:
                continue
        return results

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
            set_file_permissions(self._log_path, mode=0o600)

    # ------------------------------------------------------------------
    # Log rotation
    # ------------------------------------------------------------------

    def _rotate(self) -> None:
        """Rotate the log file when it exceeds MAX_LOG_SIZE.

        Renames audit.log → audit.log.1, shifts .1→.2, etc.
        Deletes the oldest file if count exceeds MAX_ROTATED.
        Applies 0o600 permissions to rotated files on Unix.
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
                os.chmod(dst1, 0o600)
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

        SEC-025: each entry now carries ``prev_hash`` (the previous entry's
        ``chain_hash``, or the genesis sentinel for the first entry) and its
        own ``chain_hash = sha256(prev_hash + canonical_body_json)``. An
        attacker who truncates, edits, or re-orders entries on disk will
        break the chain, which ``verify_chain`` can detect.
        """
        import datetime  # deferred: no side effects at module import

        meta_with_actor = dict(metadata)
        if actor is not None and "actor" not in meta_with_actor:
            meta_with_actor["actor"] = actor
        scrubbed = _scrub_secrets(meta_with_actor)
        scrubbed_error = str(_scrub_secrets(error)) if error else error
        # SEC-025: Strip all non-printable control characters from action and
        # error strings before embedding them in the JSON audit record.
        # Allowlist: printable ASCII/Unicode (ord >= 0x20, != 0x7F).
        # Newlines (\n) are excluded here because audit entries are JSON-lines
        # (one record per line) — an embedded newline would corrupt the format.
        def _sanitize_ctrl(s: str) -> str:
            return "".join(c for c in s if ord(c) >= 0x20 and c != "\x7f")

        safe_action = _sanitize_ctrl(action) if action else action
        safe_error = _sanitize_ctrl(scrubbed_error) if scrubbed_error else scrubbed_error
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

                # SEC-025: read the last on-disk chain hash under the same
                # lock so concurrent writers can't race on the chain head.
                prev_hash = self._read_last_chain_hash()
                entry.prev_hash = prev_hash
                body = {
                    "timestamp": entry.timestamp,
                    "action": entry.action,
                    "metadata": entry.metadata,
                    "success": entry.success,
                    "error": entry.error,
                    "prev_hash": prev_hash,
                }
                body_json = json.dumps(body, sort_keys=True, separators=(",", ":"))
                entry.chain_hash = hashlib.sha256(
                    (prev_hash + body_json).encode("utf-8")
                ).hexdigest()

                is_new = not self._log_path.exists()
                with open(self._log_path, mode="a", encoding="utf-8", newline="\n", buffering=1) as fh:
                    fh.write(json.dumps(entry.to_dict()) + "\n")
                # Also write to the per-session log if active
                if self._session_active and self._session_file:
                    try:
                        self._session_file.write(json.dumps(entry.to_dict()) + "\n")
                        self._session_file.flush()
                    except Exception:
                        pass  # session log write failure must never break audit logging
                if is_new:
                    self._apply_permissions()
            except OSError as exc:
                raise AuditError(f"SEC-AU-03: Failed to write audit log entry: {exc}") from exc
            except Exception as exc:
                raise AuditError(f"SEC-AU-03: Unexpected error writing audit log: {exc}") from exc

        return entry

    # ------------------------------------------------------------------
    # Hash-chain helpers (SEC-025)
    # ------------------------------------------------------------------

    def _read_last_chain_hash(self) -> str:
        """Return the chain_hash of the most recent on-disk entry.

        Walks the current log backwards to find the last JSON line that
        carries a ``chain_hash`` field, falling back to rotated files if
        the current log is empty. Returns ``_AUDIT_GENESIS_HASH`` when no
        prior entry exists. Caller must hold ``_class_lock`` to avoid
        racing writers. All I/O errors degrade to the genesis hash; the
        log must remain writable even when the chain head is temporarily
        unreadable (e.g., during rotation).
        """
        def _last_hash_in(path: Path) -> str | None:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                return None
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                ch = d.get("chain_hash")
                if isinstance(ch, str) and ch:
                    return ch
            return None

        if self._log_path.exists():
            h = _last_hash_in(self._log_path)
            if h is not None:
                return h
        for i in range(1, MAX_ROTATED + 1):
            rotated = self._log_path.parent / f"{self._log_path.name}.{i}"
            if not rotated.exists():
                continue
            h = _last_hash_in(rotated)
            if h is not None:
                return h
        return _AUDIT_GENESIS_HASH

    def verify_chain(self) -> tuple[bool, int, str | None]:
        """Verify the hash chain of every entry currently on disk.

        Checks rotated files (audit.log.1, .2, ...) in order and threads
        the expected chain hash across file boundaries.

        Returns ``(ok, verified_count, error)``. ``ok`` is True when every
        entry's ``chain_hash`` equals ``sha256(prev_hash + canonical_body)``
        and the chain starts at the genesis hash. Entries that predate the
        SEC-025 fix (no ``chain_hash`` field) are counted but skipped —
        this lets operators run ``verify_chain`` on a log that was started
        before the upgrade without flagging every legacy entry as tampered.
        """
        # Collect all log files in chronological order (oldest first)
        file_paths: list[Path] = []
        for i in range(MAX_ROTATED, 0, -1):
            f = self._log_path.parent / f"{self._log_path.name}.{i}"
            if f.exists():
                file_paths.append(f)
        if self._log_path.exists():
            file_paths.append(self._log_path)

        if not file_paths:
            return True, 0, None

        expected_prev = _AUDIT_GENESIS_HASH
        count = 0
        global_line = -1

        for file_path in file_paths:
            try:
                lines = file_path.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                return False, count, f"cannot read {file_path.name}: {exc}"

            for line in lines:
                global_line += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception as exc:
                    return False, count, (
                        f"line {global_line} ({file_path.name}): "
                        f"not valid JSON ({exc})"
                    )
                chain_hash = d.get("chain_hash")
                prev_hash = d.get("prev_hash")
                if chain_hash is None or prev_hash is None:
                    count += 1
                    continue
                if prev_hash != expected_prev:
                    return False, count, (
                        f"line {global_line} ({file_path.name}): "
                        f"prev_hash mismatch (got {prev_hash!r}, "
                        f"expected {expected_prev!r})"
                    )
                body = {
                    "timestamp": d["timestamp"],
                    "action": d["action"],
                    "metadata": d.get("metadata", {}),
                    "success": d["success"],
                    "error": d.get("error"),
                    "prev_hash": prev_hash,
                }
                body_json = json.dumps(body, sort_keys=True, separators=(",", ":"))
                expected = hashlib.sha256(
                    (prev_hash + body_json).encode("utf-8")
                ).hexdigest()
                if expected != chain_hash:
                    return False, count, (
                        f"line {global_line} ({file_path.name}): "
                        f"chain_hash mismatch"
                    )
                expected_prev = chain_hash
                count += 1
        return True, count, None

    # ------------------------------------------------------------------
    # Read API (AUDIT-03)
    # ------------------------------------------------------------------

    def get_recent_entries(self, n: int = 50) -> list[AuditEntry]:
        """Return the last *n* log entries, oldest first.

        Reads from rotated files (.1, .2, ...) when the current log doesn't
        have enough entries. AUDIT-03.

        Reads newest-first (current log, then audit.log.1, .2, ... up to
        MAX_ROTATED) and stops as soon as *n* lines have been collected.
        This ensures the returned entries are always the freshest available,
        even if older rotated archives still exist on disk.
        """
        with self._class_lock:
            newest_first: list[str] = []

            # 1) Current log file first — it holds the newest entries.
            if self._log_path.exists():
                try:
                    cur = self._log_path.read_text(encoding="utf-8").splitlines()
                    newest_first.extend(reversed(cur))
                except OSError:
                    pass

            # 2) Then walk rotated files from newest (.1) to oldest (.MAX_ROTATED).
            for i in range(1, MAX_ROTATED + 1):
                if len(newest_first) >= n:
                    break
                rotated = self._log_path.parent / f"{self._log_path.name}.{i}"
                if not rotated.exists():
                    continue
                try:
                    rot = rotated.read_text(encoding="utf-8").splitlines()
                    newest_first.extend(reversed(rot))
                except OSError:
                    continue

        if not newest_first:
            return []

        # Take the n freshest (still in newest-first order), then reverse to
        # oldest-first for the caller.
        recent_lines = list(reversed(newest_first[:n]))

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
