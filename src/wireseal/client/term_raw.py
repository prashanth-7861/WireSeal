"""Cross-platform raw terminal mode for interactive SSH sessions.

Provides ``run_interactive_ssh()`` used by the ``wireseal client ssh`` CLI
command. Manages raw-mode terminal I/O, TOFU host key verification, and
window resize forwarding.
"""

from __future__ import annotations

import asyncio
import os
import platform
import signal
import sys
from pathlib import Path
from typing import Any

import asyncssh

from wireseal.client.cli import DEFAULT_VAULT_DIR
from wireseal.ssh.ws_bridge import _get_known_hosts_path, append_known_host


def _set_raw_mode() -> Any:
    """Switch terminal to raw mode. Returns a restore function."""
    if sys.platform == "win32":
        return _set_raw_mode_win()
    return _set_raw_mode_unix()


def _set_raw_mode_unix() -> Any:
    """Unix raw mode via termios / tty."""
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    tty.setraw(fd)
    return lambda: termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _set_raw_mode_win() -> Any:
    """Windows raw mode via msvcrt.getch() reader thread."""
    import msvcrt

    # On Windows, we can't truly set raw mode on the terminal,
    # but we disable line buffering via a reader thread approach.
    # Save the original console mode and restore on exit.
    mode = None
    try:
        import ctypes
        from ctypes import wintypes

        STD_INPUT_HANDLE = -10
        ENABLE_LINE_INPUT = 0x0002
        ENABLE_ECHO_INPUT = 0x0004
        ENABLE_PROCESSED_INPUT = 0x0001

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)

        # Get current console mode
        mode = wintypes.DWORD()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))

        # Disable line input and echo for raw-like mode
        new_mode = mode.value & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)
        kernel32.SetConsoleMode(handle, new_mode)
    except Exception:
        pass

    if mode is not None:
        def _restore() -> None:
            try:
                kernel32.SetConsoleMode(handle, mode.value)
            except Exception:
                pass
        return _restore
    return lambda: None


async def _ssh_session(
    host: str,
    port: int,
    username: str,
    password: str,
    known_hosts_path: Path,
) -> None:
    """Connect and run an interactive SSH session with raw terminal."""

    connect_kwargs: dict[str, Any] = {
        "host": host,
        "port": port,
        "username": username,
        "known_hosts": str(known_hosts_path),
    }
    if password:
        connect_kwargs["password"] = password

    try:
        conn = await asyncssh.connect(**connect_kwargs)
    except asyncssh.HostKeyNotVerifiable as exc:
        print(f"\nUnknown host key for {host}:{port}")
        print(f"  Fingerprint: {exc.key.get_fingerprint()}")
        resp = input("Accept and continue? [y/N] ").strip().lower()
        if resp in ("y", "yes"):
            append_known_host(
                known_hosts_path, host, port,
                exc.key.export_public_key("openssh").decode(),
            )
            connect_kwargs["known_hosts"] = str(known_hosts_path)
            conn = await asyncssh.connect(**connect_kwargs)
        else:
            raise RuntimeError("Connection rejected by user.")
    except asyncssh.PermissionDenied as exc:
        raise RuntimeError("Authentication failed.") from exc
    except OSError as exc:
        raise RuntimeError(f"Connection failed: {exc}") from exc

    async with conn:
        # Get terminal size
        cols, rows = _get_terminal_size()

        async with conn.create_process(
            term_type=os.environ.get("TERM", "xterm-256color"),
            term_size=(cols, rows),
        ) as chan:

            restore = _set_raw_mode()
            try:
                await asyncio.gather(
                    _forward_stdin(chan),
                    _forward_stdout(chan),
                    _handle_resize(chan),
                )
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass
            finally:
                restore()


def _get_terminal_size() -> tuple[int, int]:
    """Return (columns, rows) of the terminal."""
    try:
        import shutil
        size = shutil.get_terminal_size()
        return size.columns, size.lines
    except Exception:
        return 80, 24


async def _forward_stdin(chan: asyncssh.SSHClientProcess) -> None:
    """Forward local stdin to the SSH channel."""
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    try:
        while True:
            data = await reader.read(1024)
            if not data:
                break
            chan.stdin.write(data)
            await chan.stdin.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            chan.stdin.write_eof()
        except Exception:
            pass


async def _forward_stdout(chan: asyncssh.SSHClientProcess) -> None:
    """Forward SSH stdout to local stdout."""
    try:
        while True:
            chunk = await chan.stdout.read(65536)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
    except (ConnectionResetError, BrokenPipeError):
        pass


async def _handle_resize(chan: asyncssh.SSHClientProcess) -> None:
    """Forward SIGWINCH to SSH channel resize."""
    if sys.platform == "win32":
        return  # No SIGWINCH on Windows

    loop = asyncio.get_event_loop()
    future = loop.create_future()

    def _on_sigwinch() -> None:
        cols, rows = _get_terminal_size()
        try:
            chan.change_terminal_size(cols, rows)
        except Exception:
            pass

    try:
        loop.add_signal_handler(signal.SIGWINCH, _on_sigwinch)
        await future
    except NotImplementedError:
        pass


def run_interactive_ssh(host: str, port: int, username: str, password: str) -> None:
    """Entry point: run an interactive SSH session in raw terminal mode.

    Sets up TOFU host key verification, raw terminal I/O, and window
    resize forwarding. Blocks until the session ends.
    """
    log_dir = DEFAULT_VAULT_DIR / "ssh-sessions"
    log_dir.mkdir(parents=True, exist_ok=True)
    known_hosts_path = _get_known_hosts_path(log_dir)

    try:
        asyncio.run(
            _ssh_session(host, port, username, password, known_hosts_path)
        )
    except RuntimeError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
