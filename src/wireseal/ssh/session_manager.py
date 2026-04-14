"""SSH session manager: one-time tokens, audit logging, session state.

Flow:
  1. REST API issues a one-time token tied to host/port/user/auth (POST /api/ssh/token).
  2. Frontend opens WebSocket to ws://localhost:8081/ssh?token=<token>.
  3. WS bridge consumes the token (single-use) and resolves connection params.
  4. asyncssh connects; terminal I/O flows through the WebSocket.
  5. Session recording writes timestamped input/output to the audit log.

Tokens expire after 60 seconds if unused, and are consumed on first use.
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

TOKEN_TTL_SECONDS = 60
TOKEN_BYTES = 32  # 256-bit tokens


@dataclass
class SshTicket:
    """One-time authentication ticket for a pending SSH connection.

    Stores resolved connection parameters so the WebSocket bridge can
    connect without re-authenticating against the vault.
    """
    token: str
    host: str
    port: int
    username: str
    password: Optional[str]  # Plaintext here is acceptable — ticket is single-use + short-lived
    profile_name: str
    actor_id: str
    created_at: float
    term: str = "xterm-256color"

    def expired(self) -> bool:
        return time.monotonic() - self.created_at > TOKEN_TTL_SECONDS


class SshSessionManager:
    """Thread-safe registry for pending SSH tickets and active sessions.

    Tickets are consumed on first fetch (single-use). Active sessions are
    tracked for status queries and cleanup on shutdown.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tickets: dict[str, SshTicket] = {}
        self._active_sessions: dict[str, dict] = {}  # session_id -> metadata

    def issue_ticket(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        profile_name: str,
        actor_id: str,
        term: str = "xterm-256color",
    ) -> str:
        """Create a one-time ticket and return its token.

        The caller is responsible for validating that the target host/port
        are reachable through the active WireGuard tunnel.
        """
        token = secrets.token_urlsafe(TOKEN_BYTES)
        ticket = SshTicket(
            token=token,
            host=host,
            port=port,
            username=username,
            password=password,
            profile_name=profile_name,
            actor_id=actor_id,
            created_at=time.monotonic(),
            term=term,
        )
        with self._lock:
            self._prune_expired()
            self._tickets[token] = ticket
        return token

    def consume_ticket(self, token: str) -> Optional[SshTicket]:
        """Fetch and remove a ticket by token. Returns None if missing or expired."""
        with self._lock:
            self._prune_expired()
            ticket = self._tickets.pop(token, None)
        if ticket is None:
            return None
        if ticket.expired():
            return None
        return ticket

    def _prune_expired(self) -> None:
        """Drop expired tickets. Caller must hold _lock."""
        stale = [t for t, ticket in self._tickets.items() if ticket.expired()]
        for t in stale:
            del self._tickets[t]

    def register_session(self, session_id: str, metadata: dict) -> None:
        """Mark an SSH session as active."""
        with self._lock:
            self._active_sessions[session_id] = {
                **metadata,
                "started_at": time.time(),
            }

    def unregister_session(self, session_id: str) -> None:
        """Remove a session from the active registry."""
        with self._lock:
            self._active_sessions.pop(session_id, None)

    def list_active(self) -> list[dict]:
        """Return metadata for all active sessions (safe to expose via API)."""
        with self._lock:
            return [
                {"session_id": sid, **meta}
                for sid, meta in self._active_sessions.items()
            ]


class SessionRecorder:
    """Append-only recorder for SSH session output.

    Writes to ``<vault_dir>/ssh-sessions/<session_id>.log`` with timestamped
    lines. Never records passwords (those are pre-consumed by the ticket).
    """

    def __init__(self, log_dir: Path, session_id: str) -> None:
        self.log_dir = log_dir
        self.session_id = session_id
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = log_dir / f"{session_id}.log"
        self._fh = open(self.path, "ab", buffering=0)  # Unbuffered for crash safety
        if os.name != "nt":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        self._lock = threading.Lock()

    def record_meta(self, event: str, detail: str = "") -> None:
        """Write a metadata event (session start/end, resize, etc.)."""
        line = f"[{time.time():.3f}] META {event}"
        if detail:
            line += f" {detail}"
        line += "\n"
        with self._lock:
            try:
                self._fh.write(line.encode("utf-8", errors="replace"))
            except (OSError, ValueError):
                pass

    def record_output(self, data: bytes) -> None:
        """Append server output (what the user sees)."""
        # Prefix each chunk with a timestamp; keep binary data for replay fidelity.
        header = f"[{time.time():.3f}] OUT {len(data)}\n".encode("ascii")
        with self._lock:
            try:
                self._fh.write(header)
                self._fh.write(data)
                self._fh.write(b"\n")
            except (OSError, ValueError):
                pass

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except OSError:
                pass


# Module-level singleton — initialized by api.py during server startup
_manager: Optional[SshSessionManager] = None


def get_manager() -> SshSessionManager:
    global _manager
    if _manager is None:
        _manager = SshSessionManager()
    return _manager
