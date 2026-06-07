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
import os
import secrets
import threading
import time
from pathlib import Path

import asyncssh

import logging

log = logging.getLogger(__name__)

_IDLE_TIMEOUT = 900  # 15 minutes


class SftpTofuRequired(Exception):
    """Raised when SFTP connection hits an unknown host key.

    The API handler should surface ``fingerprint`` and ``key_export``
    to the frontend so the user can explicitly accept.
    """

    def __init__(self, host: str, port: int, fingerprint: str, key_export: str) -> None:
        self.host = host
        self.port = port
        self.fingerprint = fingerprint
        self.key_export = key_export
        super().__init__(f"Unknown host key for {host}:{port}: {fingerprint}")


class _TofuCapturingClient(asyncssh.SSHClient):
    """Captures an unknown server host key for TOFU verification."""

    def __init__(self) -> None:
        super().__init__()
        self._captured_key: object = None

    def validate_host_public_key(self, host: str, addr: str, port: int, key: object) -> bool:
        self._captured_key = key
        return False

    def fingerprint(self) -> str:
        if self._captured_key is None:
            return "<unknown fingerprint>"
        try:
            return self._captured_key.get_fingerprint()  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return "<unknown fingerprint>"

    def key_export(self) -> str:
        if self._captured_key is None:
            return ""
        try:
            raw: bytes = self._captured_key.export_public_key()  # type: ignore[attr-defined]
            return raw.decode("utf-8").strip()
        except (AttributeError, UnicodeDecodeError, OSError):
            return ""


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
                username: str = "root", password: str = "",
                key_name: str = "", key_pem: str = "") -> str:
        """Open an SSH connection, start SFTP, return a session token.

        Blocks the calling thread until the async operation completes.
        Raises ``OSError`` on connection/auth failure.
        """
        token = secrets.token_urlsafe(32)
        loop = self._get_loop()

        _known_hosts_path = (
            Path.home() / ".wireseal" / "ssh-sessions" / "ssh_known_hosts"
        )
        _known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        if not _known_hosts_path.exists():
            _known_hosts_path.touch()

        async def _open() -> SftpSession:
            connect_kwargs: dict = {
                "host": host,
                "port": port,
                "username": username,
                "known_hosts": str(_known_hosts_path),
                # Restrict to modern algorithms
                "encryption_algs": [
                    "aes256-gcm@openssh.com",
                    "chacha20-poly1305@openssh.com",
                    "aes128-gcm@openssh.com",
                    "aes256-ctr",
                    "aes128-ctr",
                ],
                "kex_algs": [
                    "curve25519-sha256",
                    "curve25519-sha256@libssh.org",
                    "ecdh-sha2-nistp256",
                    "ecdh-sha2-nistp384",
                ],
                "server_host_key_algs": [
                    "ssh-ed25519",
                    "ecdsa-sha2-nistp256",
                    "ecdsa-sha2-nistp384",
                    "rsa-sha2-512",
                    "rsa-sha2-256",
                ],
            }
            if password:
                connect_kwargs["password"] = password
            if key_pem:
                try:
                    key = asyncssh.import_private_key(key_pem.encode("utf-8"))
                    connect_kwargs["client_keys"] = [key]
                except Exception:
                    pass

            try:
                conn = await asyncssh.connect(**connect_kwargs)
            except asyncssh.HostKeyNotVerifiable:
                # TOFU: host key not in known_hosts. Capture fingerprint
                # and raise so the API layer can surface it to the user.
                tofu_client = _TofuCapturingClient()
                try:
                    await asyncssh.connect(
                        **{**connect_kwargs, "client_factory": lambda: tofu_client}
                    )
                except asyncssh.HostKeyNotVerifiable:
                    pass
                fp = tofu_client.fingerprint()
                key_export = tofu_client.key_export()
                raise SftpTofuRequired(host, port, fp, key_export)
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
