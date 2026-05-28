"""Client mode CLI commands.

Provides `wireseal client` subgroup with tunnel management,
config import/export, interactive SSH, and interactive SFTP.
"""

from __future__ import annotations

import asyncio
import cmd
import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Any

import click

# ---------------------------------------------------------------------------
# Constants (mirrored from main.py)
# ---------------------------------------------------------------------------

DEFAULT_VAULT_DIR = Path.home() / ".wireseal"
DEFAULT_VAULT_PATH = DEFAULT_VAULT_DIR / "vault.enc"


# ---------------------------------------------------------------------------
# Vault helpers
# ---------------------------------------------------------------------------


def _open_vault():
    """Prompt for passphrase and return (vault, state, passphrase).

    Caller is responsible for calling vault.save(state, passphrase) if needed,
    and passphrase.wipe() in a finally block.
    """
    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.vault import Vault

    if not DEFAULT_VAULT_PATH.exists():
        raise click.ClickException(
            "No vault found. Run 'wireseal init' first."
        )

    vault = Vault(DEFAULT_VAULT_PATH)
    passphrase_str = click.prompt("Vault passphrase", hide_input=True)
    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        state = vault.open(passphrase)
    except Exception as exc:
        passphrase.wipe()
        raise click.ClickException(f"Failed to unlock vault: {exc}") from exc

    return vault, state, passphrase


def _get_client_settings(state_data: dict[str, Any]) -> dict[str, Any]:
    """Get client settings with defaults."""
    defaults = {
        "auto_connect_profile": None,
        "auto_lock_minutes": 15,
        "kill_switch": False,
        "dns_override": "",
        "ssh_saved_hosts": [],
    }
    settings = state_data.get("client_settings", {})
    return {**defaults, **settings}


# ---------------------------------------------------------------------------
# Client command group
# ---------------------------------------------------------------------------


@click.group("client")
def client():
    """Client mode: manage VPN tunnels and remote access.

    \b
    Subcommands:
      connect     Connect to a VPN profile
      disconnect  Disconnect the active tunnel
      status      Show tunnel status and stats
      import      Import a WireGuard .conf file
      list        List imported profiles
      delete      Delete an imported profile
      ssh         Interactive SSH session
      sftp        Interactive SFTP file transfer
      keys        Manage SSH keys
    """
    pass


# ===========================================================================
# Tunnel commands
# ===========================================================================


@client.command("connect")
@click.argument("profile")
def client_connect(profile: str) -> None:
    """Connect to a VPN tunnel using an imported profile."""
    from wireseal.client.config_store import get_config_revealed
    from wireseal.client.tunnel import apply_dns_override, tunnel_up

    vault, state, passphrase = _open_vault()
    try:
        state_data = state._data
        settings = _get_client_settings(state_data)

        config_text = get_config_revealed(state_data, profile)

        # Apply DNS override if configured
        dns = settings.get("dns_override", "")
        if dns:
            config_text = apply_dns_override(config_text, dns)

        enable_ks = settings.get("kill_switch", False)
        result = tunnel_up(config_text, profile, enable_kill_switch=enable_ks)

        status = result.get("status", "connected")
        if status == "already-connected":
            click.echo(f"Already connected to '{profile}'.")
        else:
            click.echo(f"Connected to '{profile}' on {result['interface']}.")
            if result.get("kill_switch") == "active":
                click.echo("  Kill switch: active")
    except (RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()


@client.command("disconnect")
def client_disconnect() -> None:
    """Disconnect the active VPN tunnel."""
    from wireseal.client.tunnel import tunnel_down

    try:
        result = tunnel_down()
        click.echo(
            f"Disconnected from '{result.get('profile', 'unknown')}' "
            f"on {result['interface']}."
        )
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


@client.command("status")
def client_status() -> None:
    """Show current tunnel status and transfer stats."""
    from wireseal.client.tunnel import tunnel_status

    result = tunnel_status()

    if not result["connected"]:
        click.echo("Status: disconnected")
        if result.get("kill_switch"):
            click.echo("  Kill switch: active (traffic blocked!)")
        return

    click.echo(f"Status: connected")
    click.echo(f"  Profile:     {result.get('profile', '?')}")
    click.echo(f"  Interface:   {result.get('interface', '?')}")
    click.echo(f"  Kill switch: {'active' if result.get('kill_switch') else 'off'}")

    stats = result.get("stats", {})
    peer = stats.get("peer", {})
    if peer:
        click.echo(f"  Endpoint:    {peer.get('endpoint', '?')}")
        click.echo(f"  Handshake:   {peer.get('latest_handshake', 'never')}")
        click.echo(f"  Transfer:    {peer.get('transfer', '?')}")

    handshake_ok = result.get("handshake_ok")
    if handshake_ok is False:
        click.secho(
            "  Warning: No recent handshake — tunnel may be unreachable.",
            fg="yellow",
        )


# ===========================================================================
# Config management commands
# ===========================================================================


@client.command("import")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--name", "-n", prompt="Profile name",
              help="Name for this profile (alphanumeric, max 32 chars).")
def client_import(file: str, name: str) -> None:
    """Import a WireGuard .conf file into the vault."""
    from wireseal.client.config_store import import_config

    config_text = Path(file).read_text(encoding="utf-8")

    vault, state, passphrase = _open_vault()
    try:
        meta = import_config(state._data, name, config_text)
        vault.save(state, passphrase)
        click.echo(f"Imported '{name}':")
        click.echo(f"  Endpoint: {meta.get('server_endpoint', '?')}")
        click.echo(f"  Address:  {meta.get('interface_ip', '?')}")
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()


@client.command("list")
def client_list() -> None:
    """List all imported VPN profiles."""
    from wireseal.client.config_store import list_configs

    vault, state, passphrase = _open_vault()
    try:
        configs = list_configs(state._data)
    finally:
        passphrase.wipe()

    if not configs:
        click.echo("No profiles imported. Use 'wireseal client import' to add one.")
        return

    click.echo(f"{'Name':<20} {'Endpoint':<28} {'Address':<18} {'Imported'}")
    click.echo("-" * 80)
    for c in configs:
        click.echo(
            f"{c.get('name', '?'):<20} "
            f"{c.get('server_endpoint', '?'):<28} "
            f"{c.get('interface_ip', '?'):<18} "
            f"{c.get('imported_at', '?')[:10]}"
        )


@client.command("delete")
@click.argument("profile")
@click.confirmation_option(prompt="Delete this profile?")
def client_delete(profile: str) -> None:
    """Delete an imported VPN profile from the vault."""
    from wireseal.client.config_store import delete_config

    vault, state, passphrase = _open_vault()
    try:
        delete_config(state._data, profile)
        vault.save(state, passphrase)
        click.echo(f"Deleted profile '{profile}'.")
    except (KeyError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()


# ===========================================================================
# Enroll — fetch config from server
# ===========================================================================


@client.command("enroll")
@click.option("--server", required=True, help="WireSeal server address (host:port)")
@click.option("--name", "-n", required=True, help="Client name on the server")
@click.option("--connect", is_flag=True, help="Auto-connect after enrollment")
def client_enroll(server: str, name: str, connect: bool) -> None:
    """Fetch config from a WireSeal server and import it into the local vault.

    Uses the heartbeat token to authenticate (prompted via hidden input).
    The server must be running
    \b
    Examples:
      wireseal client enroll --server vpn.example.com:8080 --name my-laptop
      wireseal client enroll -s 10.0.0.1:8080 -n laptop --connect
    """
    token: str = click.prompt("Heartbeat token", hide_input=True)

    import json
    import urllib.request as _req
    import urllib.error as _err
    import ssl as _ssl

    url = f"https://{server}/api/client/self/config"
    click.echo(f"Enrolling with server at {url} ...")

    ctx = _ssl.create_default_context()
    try:
        r = _req.Request(url, method="GET", headers={"X-WireSeal-Heartbeat": token})
        with _req.urlopen(r, timeout=15, context=ctx) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except _err.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(exc)
        raise click.ClickException(f"Server returned {exc.code}: {detail}") from exc
    except (_err.URLError, OSError) as exc:
        raise click.ClickException(f"Failed to reach server: {exc}") from exc

    config_text = body.get("config", "")
    server_name = body.get("name", name)
    if not config_text:
        raise click.ClickException("Server returned empty config.")

    # Validate and import
    from wireseal.client.config_store import import_config

    vault, state, passphrase = _open_vault()
    try:
        meta = import_config(state._data, name, config_text)
        vault.save(state, passphrase)
        click.echo(f"Enrolled as '{name}' (server name: {server_name})")
        click.echo(f"  Endpoint: {meta.get('server_endpoint', '?')}")
        click.echo(f"  Address:  {meta.get('interface_ip', '?')}")
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()

    # Save server info in client settings for later use
    vault, state, passphrase = _open_vault()
    try:
        settings = _get_client_settings(state._data)
        enrolled = settings.get("enrolled_servers", [])
        existing = [s for s in enrolled if s.get("name") != name]
        existing.append({
            "name": name,
            "server": server,
            "token_hash": hashlib.sha256(token.encode()).hexdigest()[:16],
        })
        settings["enrolled_servers"] = existing
        state._data["client_settings"] = settings
        vault.save(state, passphrase)
    except Exception:
        pass  # non-critical
    finally:
        passphrase.wipe()

    if connect:
        click.echo("Auto-connecting ...")
        from wireseal.client.tunnel import apply_dns_override, tunnel_up
        vault, state, passphrase = _open_vault()
        try:
            from wireseal.client.config_store import get_config_revealed
            cfg = get_config_revealed(state._data, name)
            text = cfg["config_text"]
            settings = _get_client_settings(state._data)
            dns = settings.get("dns_override", "")
            if dns:
                text = apply_dns_override(text, dns)
            ks = settings.get("kill_switch", False)
            result = tunnel_up(text, name, enable_kill_switch=ks)
            click.echo(f"Connected to '{name}' on {result['interface']}.")
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc
        finally:
            passphrase.wipe()


# ===========================================================================
# Interactive SSH
# ===========================================================================


@client.command("ssh")
@click.argument("host")
@click.option("-u", "--user", "username", prompt="Username",
              help="SSH username.")
@click.option("-p", "--port", default=22, type=int, show_default=True,
              help="SSH port.")
def client_ssh(host: str, username: str, port: int) -> None:
    """Open an interactive SSH session to a remote host.

    Requires an active VPN tunnel. Uses TOFU (Trust On First Use) for
    host key verification.
    """
    password = click.prompt("Password", hide_input=True, default="", show_default=False)

    from wireseal.client.term_raw import run_interactive_ssh

    try:
        run_interactive_ssh(host, port, username, password)
    except KeyboardInterrupt:
        click.echo("\nSession closed.")
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


# ===========================================================================
# Interactive SFTP
# ===========================================================================


@client.command("sftp")
@click.argument("host")
@click.option("-u", "--user", "username", prompt="Username",
              help="SSH username.")
@click.option("-p", "--port", default=22, type=int, show_default=True,
              help="SSH port.")
def client_sftp(host: str, username: str, port: int) -> None:
    """Open an interactive SFTP session for file transfer.

    Supports commands: ls, cd, pwd, get, put, rm, mkdir, rmdir, exit.
    """
    password = click.prompt("Password", hide_input=True, default="", show_default=False)

    try:
        asyncio.run(_sftp_session(host, port, username, password))
    except KeyboardInterrupt:
        click.echo("\nSession closed.")
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


async def _sftp_session(host: str, port: int, username: str, password: str) -> None:
    """Run an interactive SFTP session."""
    import asyncssh

    from wireseal.ssh.ws_bridge import _get_known_hosts_path, append_known_host

    log_dir = DEFAULT_VAULT_DIR / "ssh-sessions"
    log_dir.mkdir(parents=True, exist_ok=True)
    known_hosts_path = _get_known_hosts_path(log_dir)

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
        # TOFU flow: show fingerprint and ask
        click.secho(f"\nUnknown host key for {host}:{port}", fg="yellow")
        click.echo(f"  Fingerprint: {exc.key.get_fingerprint()}")
        if click.confirm("Accept and continue?"):
            append_known_host(
                known_hosts_path, host, port,
                exc.key.export_public_key("openssh").decode()
            )
            conn = await asyncssh.connect(**connect_kwargs)
        else:
            raise click.ClickException("Connection rejected by user.") from exc
    except asyncssh.PermissionDenied as exc:
        raise click.ClickException("Authentication failed.") from exc

    async with conn:
        sftp = await conn.start_sftp_client()
        shell = SftpShell(sftp, host, username)
        shell.cmdloop()


class SftpShell(cmd.Cmd):
    """Interactive SFTP command shell."""

    intro = "SFTP session ready. Type 'help' for commands, 'exit' to quit."

    def __init__(self, sftp, host: str, username: str):
        super().__init__()
        self._sftp = sftp
        self._cwd = "/"
        self._host = host
        self._username = username
        self.prompt = f"sftp {username}@{host}:{self._cwd}> "

    def _update_prompt(self):
        self.prompt = f"sftp {self._username}@{self._host}:{self._cwd}> "

    def _resolve(self, path: str) -> str:
        """Resolve a path relative to cwd."""
        if not path:
            return self._cwd
        if path.startswith("/"):
            return path
        import posixpath
        return posixpath.normpath(posixpath.join(self._cwd, path))

    def _run(self, coro):
        """Run an async coroutine synchronously."""
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(coro)

    def do_ls(self, args: str) -> None:
        """List directory contents. Usage: ls [path]"""
        path = self._resolve(args.strip() or self._cwd)
        try:
            entries = self._run(self._sftp.readdir(path))
            dirs = []
            files = []
            for entry in sorted(entries, key=lambda e: e.filename):
                name = entry.filename
                if name in (".", ".."):
                    continue
                attrs = entry.attrs
                is_dir = bool(
                    attrs.permissions and attrs.permissions & 0o40000
                )
                if is_dir:
                    dirs.append(f"  {name}/")
                else:
                    size = attrs.size if attrs.size else 0
                    files.append(f"  {name}  ({_fmt_size(size)})")

            for d in dirs:
                click.secho(d, fg="blue")
            for f in files:
                click.echo(f)

            total = len(dirs) + len(files)
            click.echo(f"\n{len(dirs)} dirs, {len(files)} files")
        except Exception as exc:
            click.secho(f"Error: {exc}", fg="red")

    def do_cd(self, args: str) -> None:
        """Change directory. Usage: cd <path>"""
        path = self._resolve(args.strip() or "/")
        try:
            # Verify it exists and is a directory
            attrs = self._run(self._sftp.stat(path))
            if not (attrs.permissions and attrs.permissions & 0o40000):
                click.secho(f"Not a directory: {path}", fg="red")
                return
            self._cwd = path
            self._update_prompt()
        except Exception as exc:
            click.secho(f"Error: {exc}", fg="red")

    def do_pwd(self, args: str) -> None:
        """Print working directory."""
        click.echo(self._cwd)

    def do_get(self, args: str) -> None:
        """Download a file. Usage: get <remote_path> [local_path]"""
        parts = args.strip().split(None, 1)
        if not parts:
            click.echo("Usage: get <remote_path> [local_path]")
            return

        remote = self._resolve(parts[0])
        local = parts[1] if len(parts) > 1 else os.path.basename(remote)

        try:
            click.echo(f"Downloading {remote} -> {local} ...")
            self._run(self._sftp.get(remote, local))
            size = os.path.getsize(local)
            click.echo(f"Done ({_fmt_size(size)})")
        except Exception as exc:
            click.secho(f"Error: {exc}", fg="red")

    def do_put(self, args: str) -> None:
        """Upload a file. Usage: put <local_path> [remote_path]"""
        parts = args.strip().split(None, 1)
        if not parts:
            click.echo("Usage: put <local_path> [remote_path]")
            return

        local = parts[0]
        if not os.path.isfile(local):
            click.secho(f"Local file not found: {local}", fg="red")
            return

        remote = self._resolve(
            parts[1] if len(parts) > 1 else os.path.basename(local)
        )

        try:
            size = os.path.getsize(local)
            click.echo(f"Uploading {local} ({_fmt_size(size)}) -> {remote} ...")
            self._run(self._sftp.put(local, remote))
            click.echo("Done.")
        except Exception as exc:
            click.secho(f"Error: {exc}", fg="red")

    def do_rm(self, args: str) -> None:
        """Delete a file. Usage: rm <path>"""
        path = self._resolve(args.strip())
        if not path or path == "/":
            click.secho("Refusing to delete root.", fg="red")
            return
        try:
            self._run(self._sftp.remove(path))
            click.echo(f"Deleted: {path}")
        except Exception as exc:
            click.secho(f"Error: {exc}", fg="red")

    def do_rmdir(self, args: str) -> None:
        """Remove a directory. Usage: rmdir <path>"""
        path = self._resolve(args.strip())
        if not path or path == "/":
            click.secho("Refusing to delete root.", fg="red")
            return
        try:
            self._run(self._sftp.rmdir(path))
            click.echo(f"Removed directory: {path}")
        except Exception as exc:
            click.secho(f"Error: {exc}", fg="red")

    def do_mkdir(self, args: str) -> None:
        """Create a directory. Usage: mkdir <path>"""
        path = self._resolve(args.strip())
        if not path:
            click.echo("Usage: mkdir <path>")
            return
        try:
            self._run(self._sftp.mkdir(path))
            click.echo(f"Created: {path}")
        except Exception as exc:
            click.secho(f"Error: {exc}", fg="red")

    def do_exit(self, args: str) -> bool:
        """Exit the SFTP session."""
        click.echo("Bye.")
        return True

    def do_quit(self, args: str) -> bool:
        """Exit the SFTP session."""
        return self.do_exit(args)

    do_EOF = do_exit

    def emptyline(self) -> None:
        pass


# ===========================================================================
# SSH key management (Phase 2 stub — filled in later)
# ===========================================================================


@client.group("keys")
def keys():
    """Manage SSH keys stored in the vault.

    \b
    Subcommands:
      generate  Generate a new SSH keypair
      list      List stored keys
      import    Import an existing private key
      export    Export the public key
      delete    Delete a stored key
    """
    pass


@keys.command("generate")
@click.option("--name", "-n", required=True, help="Key name")
@click.option(
    "--type", "key_type",
    default="ed25519",
    show_default=True,
    type=click.Choice(["ed25519", "rsa-2048", "rsa-4096"]),
)
@click.option("--comment", default="", help="Optional comment for the public key")
def keys_generate(name: str, key_type: str, comment: str) -> None:
    """Generate a new SSH keypair and store it in the vault."""
    from wireseal.client.ssh_keys import generate_keypair

    vault, state, passphrase = _open_vault()
    try:
        entry = generate_keypair(state._data, name, key_type=key_type, comment=comment)
        vault.save(state, passphrase)
        click.echo(f"Generated {key_type} key '{name}'")
        click.echo(f"  Fingerprint: {entry['fingerprint']}")
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()


@keys.command("list")
def keys_list() -> None:
    """List stored SSH keys."""
    from wireseal.client.ssh_keys import list_keys

    vault, state, passphrase = _open_vault()
    try:
        keys = list_keys(state._data)
    finally:
        passphrase.wipe()

    if not keys:
        click.echo(
            "No SSH keys stored. "
            "Use 'wireseal client keys generate' to create one."
        )
        return

    click.echo(f"{'Name':<20} {'Type':<15} {'Fingerprint':<50} {'Created'}")
    click.echo("-" * 95)
    for k in keys:
        click.echo(
            f"{k['name']:<20} "
            f"{k['type']:<15} "
            f"{k['fingerprint']:<50} "
            f"{k.get('created_at', '?')[:10]}"
        )


@keys.command("import")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--name", "-n", required=True, help="Key name")
def keys_import(file: str, name: str) -> None:
    """Import an existing private key file."""
    from wireseal.client.ssh_keys import import_key

    pem_text = Path(file).read_text(encoding="utf-8")

    vault, state, passphrase = _open_vault()
    try:
        entry = import_key(state._data, name, pem_text)
        vault.save(state, passphrase)
        click.echo(f"Imported key '{name}'")
        click.echo(f"  Fingerprint: {entry['fingerprint']}")
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()


@keys.command("export")
@click.argument("name")
@click.option("--public", is_flag=True, help="Export public key instead")
def keys_export(name: str, public: bool) -> None:
    """Export a stored SSH key."""
    from wireseal.client.ssh_keys import export_public_key

    vault, state, passphrase = _open_vault()
    try:
        if public:
            pub = export_public_key(state._data, name)
            click.echo(pub)
        else:
            keys = state._data.get("ssh_keys", {})
            if name not in keys:
                raise click.ClickException(f"SSH key '{name}' not found")
            click.secho(
                "WARNING: Exporting private keys is a security risk. "
                "Consider using '--public' instead.",
                fg="red",
            )
            click.echo(keys[name]["private_key_pem"])
    except KeyError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()


@keys.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="Delete this key?")
def keys_delete(name: str) -> None:
    """Delete a stored SSH key from the vault."""
    from wireseal.client.ssh_keys import delete_key

    vault, state, passphrase = _open_vault()
    try:
        delete_key(state._data, name)
        vault.save(state, passphrase)
        click.echo(f"Deleted key '{name}'.")
    except KeyError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()


# ===========================================================================
# Utilities
# ===========================================================================


def _fmt_size(size: int) -> str:
    """Format byte size to human-readable string."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.1f} GB"
