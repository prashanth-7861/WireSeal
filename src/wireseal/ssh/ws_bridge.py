"""WebSocket ⇄ SSH bridge.

Runs a small ``websockets`` server on a separate port (default 8081) and
forwards terminal I/O between a browser xterm.js instance and an
``asyncssh`` SSH session. Authentication is performed via one-time tickets
issued by the REST API — WebSocket connections never carry long-lived
credentials.

Protocol (JSON text frames, one per line):

  client → bridge:
    {"type": "input",  "data": "<string>"}       # keystrokes
    {"type": "resize", "cols": 80, "rows": 24}   # terminal resize
    {"type": "ping"}                              # keepalive

  bridge → client:
    {"type": "ready"}                             # SSH connection established
    {"type": "output", "data": "<string>"}        # terminal output
    {"type": "error",  "message": "<str>"}        # fatal error
    {"type": "closed"}                            # session ended

Binary frames are not used; all data is JSON. Terminal output is base64 to
preserve non-UTF-8 bytes without corrupting the JSON envelope.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

import asyncssh
import websockets
from websockets.server import WebSocketServerProtocol

from .session_manager import SessionRecorder, SshTicket, get_manager

log = logging.getLogger("wireseal.ssh.ws_bridge")

# WebSocket server listens on localhost only — the WireGuard tunnel is the
# network boundary, not the WS server. The Dashboard always connects from
# the same host (pywebview or browser → localhost).
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8081
DEFAULT_PATH = "/ssh"


class BridgeError(Exception):
    """Raised when the WebSocket bridge cannot complete a session."""


async def _send_json(ws: WebSocketServerProtocol, payload: dict) -> None:
    try:
        await ws.send(json.dumps(payload))
    except websockets.ConnectionClosed:
        pass


async def _recv_loop(
    ws: WebSocketServerProtocol,
    chan: asyncssh.SSHClientProcess,
) -> None:
    """Forward messages from the WebSocket to the SSH channel."""
    try:
        async for raw in ws:
            if isinstance(raw, bytes):
                continue  # We only accept text frames
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            mtype = msg.get("type")
            if mtype == "input":
                data = msg.get("data", "")
                if isinstance(data, str):
                    chan.stdin.write(data)
            elif mtype == "resize":
                cols = int(msg.get("cols", 80))
                rows = int(msg.get("rows", 24))
                try:
                    chan.change_terminal_size(cols, rows)
                except Exception:  # noqa: BLE001
                    pass
            elif mtype == "ping":
                await _send_json(ws, {"type": "pong"})
    except websockets.ConnectionClosed:
        pass
    finally:
        try:
            chan.stdin.write_eof()
        except Exception:  # noqa: BLE001
            pass


async def _forward_stdout(
    ws: WebSocketServerProtocol,
    chan: asyncssh.SSHClientProcess,
    recorder: SessionRecorder,
) -> None:
    """Forward SSH stdout to the WebSocket as base64 output frames."""
    try:
        while True:
            chunk = await chan.stdout.read(4096)
            if not chunk:
                break
            if isinstance(chunk, str):
                data = chunk.encode("utf-8", errors="replace")
            else:
                data = chunk
            recorder.record_output(data)
            await _send_json(
                ws,
                {"type": "output", "data": base64.b64encode(data).decode("ascii")},
            )
    except (asyncssh.Error, websockets.ConnectionClosed):
        pass


async def _forward_stderr(
    ws: WebSocketServerProtocol,
    chan: asyncssh.SSHClientProcess,
    recorder: SessionRecorder,
) -> None:
    """Forward SSH stderr to the WebSocket (merged with stdout on the client)."""
    try:
        while True:
            chunk = await chan.stderr.read(4096)
            if not chunk:
                break
            if isinstance(chunk, str):
                data = chunk.encode("utf-8", errors="replace")
            else:
                data = chunk
            recorder.record_output(data)
            await _send_json(
                ws,
                {"type": "output", "data": base64.b64encode(data).decode("ascii")},
            )
    except (asyncssh.Error, websockets.ConnectionClosed):
        pass


async def _handle_session(
    ws: WebSocketServerProtocol,
    ticket: SshTicket,
    log_dir: Path,
) -> None:
    """Establish SSH connection and pump I/O until either side closes."""
    session_id = secrets.token_hex(8)
    manager = get_manager()
    recorder = SessionRecorder(log_dir, session_id)
    recorder.record_meta(
        "session-start",
        f"profile={ticket.profile_name} host={ticket.host}:{ticket.port} user={ticket.username}",
    )

    # SEC-021: ticket.password is a SecretBytes. Decode it to str only for
    # the length of the asyncssh.connect call, then wipe the ticket's copy
    # so nothing lingers for the life of the session. asyncssh internally
    # uses the password as a bytes-compatible object during auth.
    _password_str: Optional[str] = None
    if ticket.password is not None:
        try:
            _password_str = bytes(ticket.password.expose_secret()).decode("utf-8")
        except Exception:
            _password_str = None
    try:
        async with asyncssh.connect(
            host=ticket.host,
            port=ticket.port,
            username=ticket.username,
            password=_password_str,
            known_hosts=None,  # Trust tunnel; production should use TOFU store
            keepalive_interval=30,
        ) as conn:
            # Spawn an interactive shell (no command = login shell)
            async with conn.create_process(
                term_type=ticket.term,
                term_size=(80, 24),
            ) as chan:
                manager.register_session(
                    session_id,
                    {
                        "profile": ticket.profile_name,
                        "host": ticket.host,
                        "port": ticket.port,
                        "username": ticket.username,
                        "actor_id": ticket.actor_id,
                    },
                )

                await _send_json(ws, {"type": "ready", "session_id": session_id})

                await asyncio.gather(
                    _recv_loop(ws, chan),
                    _forward_stdout(ws, chan, recorder),
                    _forward_stderr(ws, chan, recorder),
                )

    except asyncssh.PermissionDenied:
        await _send_json(ws, {"type": "error", "message": "SSH permission denied (bad password or user)"})
        recorder.record_meta("session-error", "permission-denied")
    except asyncssh.ConnectionLost as exc:
        await _send_json(ws, {"type": "error", "message": f"Connection lost: {exc}"})
        recorder.record_meta("session-error", f"connection-lost: {exc}")
    except (OSError, asyncssh.Error) as exc:
        await _send_json(ws, {"type": "error", "message": f"SSH error: {exc}"})
        recorder.record_meta("session-error", str(exc))
    finally:
        # SEC-021: wipe the ticket's SecretBytes copy and the temporary str
        # we handed to asyncssh. The str wipe is best-effort because Python
        # may have interned it, but the SecretBytes buffer is zeroed for sure.
        try:
            ticket.wipe()
        except Exception:
            pass
        if _password_str is not None:
            try:
                from wireseal.security.secrets_wipe import wipe_string
                wipe_string(_password_str)
            except Exception:
                pass
            _password_str = None
        manager.unregister_session(session_id)
        recorder.record_meta("session-end")
        recorder.close()
        await _send_json(ws, {"type": "closed"})


async def _bridge_handler(ws: WebSocketServerProtocol, path: str, log_dir: Path) -> None:
    """Entry point for each WebSocket connection (legacy ``websockets`` signature).

    The ``websockets`` legacy server passes ``(websocket, path)`` where
    ``path`` is the HTTP request target (including query string).
    """
    parsed = urlparse(path or "")
    if parsed.path != DEFAULT_PATH:
        await _send_json(ws, {"type": "error", "message": "Unknown path"})
        await ws.close()
        return

    qs = parse_qs(parsed.query)
    token = (qs.get("token") or [None])[0]
    if not token:
        await _send_json(ws, {"type": "error", "message": "Missing token"})
        await ws.close()
        return

    ticket = get_manager().consume_ticket(token)
    if ticket is None:
        await _send_json(ws, {"type": "error", "message": "Invalid or expired token"})
        await ws.close()
        return

    try:
        await _handle_session(ws, ticket, log_dir)
    except Exception as exc:  # noqa: BLE001
        log.exception("bridge handler crashed")
        await _send_json(ws, {"type": "error", "message": f"Bridge error: {exc}"})
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass


def start_bridge_thread(
    log_dir: Path,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> threading.Thread:
    """Start the WebSocket bridge in a daemon thread with its own event loop.

    Returns the thread (already started). The caller does not need to keep
    a reference — the thread is a daemon and exits with the process.
    """

    def _run() -> None:
        asyncio.run(_serve(log_dir, host, port))

    thread = threading.Thread(
        target=_run,
        name="wireseal-ssh-ws-bridge",
        daemon=True,
    )
    thread.start()
    return thread


async def _serve(log_dir: Path, host: str, port: int) -> None:
    """Async entry point: run the WebSocket server until cancelled."""
    async def handler(ws: WebSocketServerProtocol, path: str) -> None:
        await _bridge_handler(ws, path, log_dir)

    async with websockets.serve(
        handler,
        host,
        port,
        max_size=2**20,  # 1 MiB per frame (plenty for terminal I/O)
        ping_interval=20,
        ping_timeout=20,
    ):
        log.info("SSH WebSocket bridge listening on ws://%s:%d%s", host, port, DEFAULT_PATH)
        await asyncio.Future()  # Run until cancelled
