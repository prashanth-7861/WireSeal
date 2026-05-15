"""SFTP session manager — caches SSH connections for the file browser.

Each ``connect()`` call opens an asyncssh connection and stores the
SFTP client in an in-memory dict keyed by a random session token.
Subsequent operations (list/read/write/delete/mkdir) reuse the same
connection via the token, avoiding per-operation SSH handshake overhead.

Connections are auto-closed after ``_IDLE_TIMEOUT`` seconds of inactivity.
Thread-safe via a reentrant lock.
"""

from __future__ import annotations

import asyncio
import secrets
import threading
import time

import asyncssh

_IDLE_TIMEOUT = 900  # 15 minutes


class SftpSession:
    """An active SFTP session wrapping an asyncssh connection."""

    def __init__(self, conn: asyncssh.SSHClientConnection,
                 sftp: asyncssh.SFTPClient,
                 host: str, port: int, username: str) -> None:
        self.conn = conn
        self.sftp = sftp
        self.host = host
        self.port = port
        self.username = username
        self.last_used = time.monotonic()

    def touch(self) -> None:
        """Update the last-used timestamp."""
        self.last_used = time.monotonic()

    async def close(self) -> None:
        """Close the SFTP client and the underlying SSH connection."""
        try:
            self.sftp.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass


class SftpSessionManager:
    """Manages SFTP sessions keyed by random token.

    Thread-safe: all mutation is under ``_lock``.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SftpSession] = {}
        self._lock = threading.RLock()
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, token: str, coro, timeout: float | None = None) -> object:
        """Run an async SFTP operation on this session's event loop.

        All ``_h_sftp_*`` API handlers should call this instead of
        ``asyncio.run()`` so the SFTP client runs on the SAME event
        loop that created it.  Using ``asyncio.run()`` creates a new
        loop each time, causing "Event loop is closed" errors and
        silent connection drops.

        Returns the coroutine result, or raises ``LookupError`` if
        the session token is not found.
        """
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                raise LookupError("Session not found or expired")
            session.touch()
        loop = self._get_loop()
        return loop.run_until_complete(coro)

    def connect(self, host: str, port: int = 22,
                username: str = "root", password: str = "") -> str:
        """Open an SSH connection, start SFTP, return a session token.

        Blocks the calling thread until the async operation completes.
        Raises ``OSError`` on connection/auth failure.
        """
        token = secrets.token_urlsafe(32)
        loop = self._get_loop()

        async def _open() -> SftpSession:
            conn = await asyncssh.connect(
                host, port=port, username=username, password=password,
                known_hosts=None,
            )
            sftp = await conn.start_sftp_client()
            return SftpSession(conn, sftp, host, port, username)

        session = loop.run_until_complete(_open())

        with self._lock:
            # Close any existing session for the same host/user
            for tok, sess in list(self._sessions.items()):
                if sess.host == host and sess.username == username:
                    self._close_session(tok, sess)
            self._sessions[token] = session

        return token

    def disconnect(self, token: str) -> None:
        """Close and remove a session by token."""
        with self._lock:
            session = self._sessions.pop(token, None)
        if session:
            self._close_session_async(session)

    def get(self, token: str) -> SftpSession | None:
        """Return the session for *token*, or None if not found.
        Updates the last-used timestamp.
        """
        with self._lock:
            session = self._sessions.get(token)
            if session:
                session.touch()
            return session

    def disconnect_all(self) -> None:
        """Close every session (called during server shutdown)."""
        with self._lock:
            tokens = list(self._sessions.keys())
            for t in tokens:
                sess = self._sessions.pop(t, None)
                if sess:
                    self._close_session_async(sess)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Return or create the asyncio event loop."""
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
        return self._loop

    def _close_session(self, token: str, session: SftpSession) -> None:
        """Synchronously close a session from a non-async context."""
        loop = self._get_loop()
        try:
            loop.run_until_complete(session.close())
        except Exception:
            pass

    def _close_session_async(self, session: SftpSession) -> None:
        """Close a session in the background (fire-and-forget)."""
        loop = self._get_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(session.close(), loop)
        else:
            try:
                loop.run_until_complete(session.close())
            except Exception:
                pass

    def reap_stale(self) -> None:
        """Close sessions idle longer than ``_IDLE_TIMEOUT``.
        Intended to be called periodically by a background timer.
        """
        now = time.monotonic()
        with self._lock:
            stale = [
                (t, s) for t, s in self._sessions.items()
                if now - s.last_used > _IDLE_TIMEOUT
            ]
            for token, session in stale:
                del self._sessions[token]
                self._close_session_async(session)


# Module-level singleton
_manager = SftpSessionManager()


def get_manager() -> SftpSessionManager:
    return _manager
