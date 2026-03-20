"""wg-automate: zero-secrets WireGuard server automation.

CLI entry point using Click. All 14 commands are registered on the ``cli``
group. Vault-lifecycle commands (init, status, verify, lock, change-passphrase)
are implemented here. Client commands (add-client, remove-client, list-clients,
show-qr, export, update-dns) are implemented in plans 04-02. Rotation commands
(rotate-keys, rotate-server-keys, audit-log) remain stubs for plan 04-03.

Security invariants:
  CLI-02: Every passphrase input uses click.prompt(hide_input=True).
          Never --passphrase option, never environment variable.
  AUDIT-01: No passphrase or key material passed to audit.log() calls.
"""

import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import click

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_VAULT_DIR = Path.home() / ".wg-automate"
DEFAULT_VAULT_PATH = DEFAULT_VAULT_DIR / "vault.enc"
DEFAULT_AUDIT_LOG_PATH = DEFAULT_VAULT_DIR / "audit.log"

# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option()
def cli() -> None:
    """wg-automate: zero-secrets WireGuard server automation."""


# ===========================================================================
# Vault-lifecycle commands (implemented in this plan: 04-01)
# ===========================================================================

# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--subnet", default="10.0.0.0/24", show_default=True,
              help="VPN subnet (RFC 1918)")
@click.option("--port", default=51820, type=int, show_default=True,
              help="WireGuard listen port")
@click.option("--duckdns-domain", default=None,
              help="DuckDNS subdomain (optional)")
def init(subnet: str, port: int, duckdns_domain: str | None) -> None:
    """Initialise the vault, generate server keys, and install WireGuard."""
    # Step 1: Collect and confirm passphrase — CLI-02
    passphrase_str: str = click.prompt(
        "Vault passphrase",
        hide_input=True,
        confirmation_prompt=True,
    )
    if len(passphrase_str) < 12:
        raise click.ClickException(
            "Passphrase must be at least 12 characters."
        )

    # Convert to SecretBytes immediately; wipe the raw string best-effort later
    from wg_automate.security.secret_types import SecretBytes
    from wg_automate.security.secrets_wipe import wipe_string

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        # Step 2: Vault must not already exist
        from wg_automate.security.vault import Vault

        if DEFAULT_VAULT_PATH.exists():
            raise click.ClickException(
                "Vault already exists. Run verify to check integrity."
            )

        # Step 3: Privilege check
        from wg_automate.platform.detect import get_adapter, get_platform_info

        adapter = get_adapter()
        adapter.check_privileges()

        # Step 4: Generate server keypair
        from wg_automate.core.keygen import generate_keypair

        private_key_secret, public_key_bytes = generate_keypair()
        public_key_str = public_key_bytes.decode("ascii")

        # Step 5: Allocate server IP from the subnet
        from wg_automate.core.ip_pool import IPPool

        pool = IPPool(subnet)
        server_ip = pool.server_ip

        # Build initial vault state
        initial_state: dict = {
            "schema_version": 1,
            "server": {
                "private_key": private_key_secret.expose_secret().decode("ascii"),
                "public_key": public_key_str,
                "ip": server_ip,
                "subnet": pool.subnet_str,
                "port": port,
            },
            "clients": {},
            "ip_pool": {
                "subnet": pool.subnet_str,
                "allocated": pool.get_allocated(),
            },
            "integrity": {},
        }

        # Create vault (also enforces minimum passphrase length via Vault.create)
        vault = Vault.create(DEFAULT_VAULT_PATH, passphrase, initial_state)

        # Step 6: Build and deploy server config
        from wg_automate.core.config_builder import ConfigBuilder

        builder = ConfigBuilder()
        config_content = builder.render_server_config(
            server_private_key=private_key_secret.expose_secret().decode("ascii"),
            server_ip=server_ip,
            prefix_length=int(pool.subnet_str.split("/")[1]),
            server_port=port,
            clients=[],
        )
        config_path = adapter.deploy_config(config_content)

        # Store config hash in vault for integrity tracking
        import hashlib
        config_hash = hashlib.sha256(config_content.encode("utf-8")).hexdigest()

        # Re-open vault to store the config hash
        with vault.open(passphrase) as state:
            state.integrity["server"] = config_hash
            vault.save(state, passphrase)

        # Step 7: Install WireGuard and start the service
        adapter.install_wireguard()
        adapter.apply_firewall_rules(port, "wg0", pool.subnet_str)
        adapter.enable_tunnel_service("wg0")

        # Step 8: Optional DuckDNS setup
        if duckdns_domain is not None:
            token_str: str = click.prompt(
                "DuckDNS token", hide_input=True
            )
            duckdns_token = SecretBytes(
                bytearray(token_str.encode("utf-8"))
            )
            # Store DuckDNS info in vault
            with vault.open(passphrase) as state:
                state.server["duckdns_domain"] = duckdns_domain
                state.server["duckdns_token"] = duckdns_token
                vault.save(state, passphrase)
            duckdns_token.wipe()
            wipe_string(token_str)

        # Step 9: Audit log
        from wg_automate.security.audit import AuditLog

        platform_info = get_platform_info()
        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(
            action="init",
            metadata={
                "subnet": subnet,
                "port": port,
                "platform": platform_info["os"],
            },
        )

        # Step 10: Print success summary
        click.echo("\nInitialisation complete.")
        click.echo(f"  Subnet:      {pool.subnet_str}")
        click.echo(f"  Server IP:   {server_ip}")
        click.echo(f"  Public key:  {public_key_str}")
        click.echo(f"  Port:        {port}")
        if duckdns_domain:
            click.echo(f"  DuckDNS:     {duckdns_domain}.duckdns.org")

    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        # Wipe passphrase from memory
        passphrase.wipe()
        wipe_string(passphrase_str)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@cli.command()
def status() -> None:
    """Show connected peers, transfer stats, and last handshake times."""
    import subprocess

    # Step 1: Collect passphrase — CLI-02
    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wg_automate.security.secret_types import SecretBytes
    from wg_automate.security.secrets_wipe import wipe_string
    from wg_automate.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        # Step 2: Open vault to confirm auth, then close immediately
        from wg_automate.security.vault import Vault

        vault = Vault(DEFAULT_VAULT_PATH)
        with vault.open(passphrase) as _state:
            pass  # Auth confirmed; decrypted state wiped immediately on exit

        # Step 3: Run wg show
        result = subprocess.run(
            ["wg", "show"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            click.echo("WireGuard interface not running.")
            sys.exit(1)

        output = result.stdout

        # Security guard: wg show must never include private keys
        assert "PrivateKey" not in output, (
            "SECURITY: 'wg show' output unexpectedly contains 'PrivateKey'. Aborting."
        )

        # Step 4: Parse and display
        _display_wg_status(output)

        # Step 6: Audit log
        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(action="status", metadata={})

    except click.ClickException:
        raise
    except AssertionError as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)


def _display_wg_status(output: str) -> None:
    """Parse and pretty-print wg show output. No key material is displayed."""
    lines = output.strip().splitlines()
    interface = None
    peers: list[dict] = []
    current_peer: dict | None = None

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("interface:"):
            interface = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("peer:"):
            if current_peer is not None:
                peers.append(current_peer)
            raw_key = stripped.split(":", 1)[1].strip()
            # Truncate public key: show first 8 chars only
            current_peer = {"public_key": raw_key[:8] + "...", "allowed_ips": "-",
                            "handshake": "never", "transfer": "-"}
        elif current_peer is not None:
            if stripped.startswith("allowed ips:"):
                current_peer["allowed_ips"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("latest handshake:"):
                current_peer["handshake"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("transfer:"):
                current_peer["transfer"] = stripped.split(":", 1)[1].strip()

    if current_peer is not None:
        peers.append(current_peer)

    click.echo(f"\nInterface: {interface or 'unknown'}")
    if not peers:
        click.echo("No clients configured.")
        return

    click.echo(f"\n{'Peer':12}  {'Allowed IPs':20}  {'Last Handshake':25}  {'Transfer'}")
    click.echo("-" * 80)
    for peer in peers:
        click.echo(
            f"{peer['public_key']:12}  {peer['allowed_ips']:20}  "
            f"{peer['handshake']:25}  {peer['transfer']}"
        )


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@cli.command()
def verify() -> None:
    """Check SHA-256 of deployed config files against vault records."""
    # Step 1: Collect passphrase — CLI-02
    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wg_automate.security.secret_types import SecretBytes
    from wg_automate.security.secrets_wipe import wipe_string
    from wg_automate.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        # Step 2: Open vault
        from wg_automate.security.vault import Vault
        from wg_automate.security.integrity import verify_config_integrity

        vault = Vault(DEFAULT_VAULT_PATH)
        tampered_count = 0
        all_paths_checked = 0

        with vault.open(passphrase) as state:
            integrity_records = dict(state.integrity)

        # Step 4: Check each config path recorded in the integrity section
        # The integrity dict stores {name: hash_hex, name_verified: timestamp}
        # We only check entries that don't end with "_verified"
        for config_name, stored_hash in integrity_records.items():
            if config_name.endswith("_verified"):
                continue
            if not isinstance(stored_hash, str):
                continue

            # Derive the config path from the name
            config_path = _resolve_config_path(config_name)
            if config_path is None:
                click.echo(
                    click.style(f"[SKIP] {config_name}: path not resolvable", fg="yellow")
                )
                continue

            all_paths_checked += 1
            try:
                ok = verify_config_integrity(config_path, stored_hash)
            except FileNotFoundError:
                click.echo(
                    click.style(f"[MISSING] {config_path}", fg="red")
                )
                tampered_count += 1
                continue
            except OSError as exc:
                click.echo(
                    click.style(f"[ERROR] {config_path}: {exc}", fg="red")
                )
                tampered_count += 1
                continue

            if ok:
                click.echo(click.style(f"[OK] {config_path}", fg="green"))
            else:
                click.echo(click.style(f"[TAMPERED] {config_path}", fg="red"))
                tampered_count += 1

        # Step 7: Audit log
        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        result_label = "ok" if tampered_count == 0 else "tampered"
        audit.log(
            action="verify",
            metadata={"result": result_label, "tampered_count": tampered_count},
        )

        # Step 5 / 6: Exit code and summary
        if tampered_count > 0:
            click.echo(
                click.style(
                    f"\nALERT: {tampered_count} config file(s) have been tampered with.",
                    fg="red",
                )
            )
            sys.exit(1)
        else:
            if all_paths_checked == 0:
                click.echo("No config files tracked yet.")
            else:
                click.echo("All config files verified. No tampering detected.")

    except click.ClickException:
        raise
    except SystemExit:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)


def _resolve_config_path(config_name: str) -> Path | None:
    """Map a vault integrity config name to its filesystem path.

    Returns None if the path cannot be resolved.
    """
    try:
        from wg_automate.platform.detect import get_adapter

        adapter = get_adapter()
        if config_name == "server":
            return adapter.get_config_path("wg0")
        # Client configs: stored as "client-<name>"
        if config_name.startswith("client-"):
            interface = config_name[len("client-"):]
            return adapter.get_config_path(interface)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# lock
# ---------------------------------------------------------------------------


@cli.command()
def lock() -> None:
    """Wipe all decrypted state and signal end of session."""
    # Step 1: Explicitly NO passphrase needed — the lock command must never fail

    # Step 2: Scan for and remove any temp decrypted artifacts
    # Decrypted state only ever lives in Python memory (VaultState context manager
    # wipes in finally). The lock command removes any unexpected temp files that
    # might exist under ~/.wg-automate/ other than vault.enc / vault.hint / audit.log.
    _wipe_temp_artifacts()

    # Step 3: Confirmation message
    click.echo("Vault locked. All decrypted state wiped.")

    # Step 4: Attempt audit log — skip if inaccessible (lock must never fail)
    try:
        from wg_automate.security.audit import AuditLog

        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(action="lock", metadata={})
    except Exception:
        pass  # Lock must never fail due to audit log issues

    # Step 5: Exit cleanly
    sys.exit(0)


def _wipe_temp_artifacts() -> None:
    """Remove unexpected temp files from the vault directory.

    Only keeps vault.enc, vault.hint, and audit.log.
    All other files in ~/.wg-automate/ are treated as decrypted state artifacts
    and removed.
    """
    _keep = {"vault.enc", "vault.hint", "audit.log"}
    try:
        if not DEFAULT_VAULT_DIR.exists():
            return
        for item in DEFAULT_VAULT_DIR.iterdir():
            if item.is_file() and item.name not in _keep:
                try:
                    item.unlink()
                except OSError:
                    pass
    except OSError:
        pass  # Best-effort; lock must never fail


# ---------------------------------------------------------------------------
# change-passphrase
# ---------------------------------------------------------------------------


@cli.command("change-passphrase")
def change_passphrase() -> None:
    """Re-encrypt the vault with a new passphrase."""
    # Step 1: Collect current passphrase — CLI-02
    old_str: str = click.prompt("Current passphrase", hide_input=True)

    # Step 2: Collect and confirm new passphrase — CLI-02
    new_str: str = click.prompt(
        "New passphrase",
        hide_input=True,
        confirmation_prompt=True,
    )
    if len(new_str) < 12:
        raise click.ClickException(
            "New passphrase must be at least 12 characters."
        )

    from wg_automate.security.secret_types import SecretBytes
    from wg_automate.security.secrets_wipe import wipe_string
    from wg_automate.security.audit import AuditLog

    old_passphrase = SecretBytes(bytearray(old_str.encode("utf-8")))
    new_passphrase = SecretBytes(bytearray(new_str.encode("utf-8")))

    try:
        # Step 3: Delegate to Vault.change_passphrase
        from wg_automate.security.vault import Vault

        vault = Vault(DEFAULT_VAULT_PATH)
        vault.change_passphrase(old_passphrase, new_passphrase)

        # Step 5: Confirmation
        click.echo("Passphrase changed successfully.")

        # Step 6: Audit log
        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(action="change-passphrase", metadata={})

    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        # Step 4: Wipe both passphrases
        old_passphrase.wipe()
        new_passphrase.wipe()
        wipe_string(old_str)
        wipe_string(new_str)


# ===========================================================================
# Stub commands (plans 04-02 / 04-03 will fill in these bodies)
# ===========================================================================

def _not_implemented(name: str) -> None:
    raise click.ClickException(f"Not yet implemented: {name}")


@cli.command("add-client")
@click.argument("name")
def add_client(name: str) -> None:
    """Add a new WireGuard client and generate its config."""
    _not_implemented("add-client")


@cli.command("remove-client")
@click.argument("name")
def remove_client(name: str) -> None:
    """Remove a client and revoke its WireGuard access."""
    _not_implemented("remove-client")


@cli.command("list-clients")
def list_clients() -> None:
    """List all registered WireGuard clients."""
    _not_implemented("list-clients")


@cli.command("show-qr")
@click.argument("name")
def show_qr(name: str) -> None:
    """Display the QR code for a client config."""
    _not_implemented("show-qr")


@cli.command("rotate-keys")
@click.argument("name")
def rotate_keys(name: str) -> None:
    """Rotate the keypair and PSK for a specific client."""
    import hashlib
    import subprocess

    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wg_automate.security.secret_types import SecretBytes
    from wg_automate.security.secrets_wipe import wipe_bytes, wipe_string
    from wg_automate.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        from wg_automate.security.vault import Vault

        vault = Vault(DEFAULT_VAULT_PATH)
        with vault.open(passphrase) as state:
            # Step 3: Verify client exists
            if name not in state.clients:
                raise click.ClickException(f"Client '{name}' not found in vault.")

            client_data = state.clients[name]

            # Step 4: Generate new material BEFORE touching old keys
            from wg_automate.core.keygen import generate_keypair
            from wg_automate.core.psk import generate_psk

            new_keypair_priv, new_keypair_pub = generate_keypair()
            new_psk = generate_psk()

            new_pub_str = new_keypair_pub.decode("ascii")
            new_priv_str = new_keypair_priv.expose_secret().decode("ascii")
            new_psk_str = new_psk.expose_secret().decode("ascii")

            # Step 5: Build and validate new configs
            from wg_automate.core.config_builder import ConfigBuilder
            from wg_automate.security.validator import validate_client_config, validate_server_config

            server_data = state.server
            server_pub_key = server_data["public_key"] if isinstance(server_data["public_key"], str) else server_data["public_key"].decode("ascii")
            client_ip = client_data["ip"]
            server_port = server_data["port"]
            server_ip_raw = server_data["ip"]
            subnet = state.ip_pool.get("subnet", "10.0.0.0/24")
            dns_server = client_data.get("dns_server", "1.1.1.1")
            server_endpoint = client_data.get("endpoint", f"{server_ip_raw}:{server_port}")

            new_client_config_str = ConfigBuilder().render_client_config(
                client_private_key=new_priv_str,
                client_ip=client_ip,
                dns_server=dns_server,
                server_public_key=server_pub_key,
                psk=new_psk_str,
                server_endpoint=server_endpoint,
            )

            # Build updated server config with new client public key
            clients_for_render = []
            for cname, cdata in state.clients.items():
                if cname == name:
                    # Use new public key and new PSK for the rotated client
                    cpub = new_pub_str
                    cpsk = new_psk_str
                else:
                    cpub_raw = cdata.get("public_key", "")
                    cpub = cpub_raw if isinstance(cpub_raw, str) else cpub_raw.decode("ascii")
                    cpsk_raw = cdata.get("psk", "")
                    cpsk = cpsk_raw if isinstance(cpsk_raw, str) else cpsk_raw.expose_secret().decode("ascii")
                clients_for_render.append({
                    "name": cname,
                    "public_key": cpub,
                    "psk": cpsk,
                    "ip": cdata["ip"],
                })

            server_priv_raw = server_data.get("private_key", "")
            server_priv_str = server_priv_raw if isinstance(server_priv_raw, str) else server_priv_raw.expose_secret().decode("ascii")
            prefix_length = int(subnet.split("/")[1])

            new_server_config_str = ConfigBuilder().render_server_config(
                server_private_key=server_priv_str,
                server_ip=server_ip_raw,
                prefix_length=prefix_length,
                server_port=server_port,
                clients=clients_for_render,
            )

            # Validate both configs
            try:
                validate_client_config({
                    "private_key": new_priv_str,
                    "psk": new_psk_str,
                    "ip": client_ip,
                    "dns_server": dns_server,
                    "server_public_key": server_pub_key,
                    "endpoint": server_endpoint,
                })
            except ValueError as exc:
                new_keypair_priv.wipe()
                new_psk.wipe()
                raise click.ClickException(f"New client config validation failed: {exc}") from exc

            try:
                validate_server_config({
                    "private_key": server_priv_str,
                    "public_key": "",
                    "port": server_port,
                    "subnet": subnet,
                    "clients": clients_for_render,
                })
            except ValueError as exc:
                new_keypair_priv.wipe()
                new_psk.wipe()
                raise click.ClickException(f"New server config validation failed: {exc}") from exc

            # Step 6: Write new configs atomically
            from wg_automate.security.atomic import atomic_write
            from wg_automate.platform.detect import get_adapter

            adapter = get_adapter()
            clients_dir = DEFAULT_VAULT_DIR / "clients"
            clients_dir.mkdir(parents=True, exist_ok=True)
            client_conf_path = clients_dir / f"{name}.conf"

            client_encoded = new_client_config_str.encode("utf-8")
            atomic_write(client_conf_path, client_encoded, mode=0o600)
            new_client_hash = hashlib.sha256(client_encoded).hexdigest()

            server_conf_path = adapter.get_config_path("wg0")
            server_encoded = new_server_config_str.encode("utf-8")
            atomic_write(server_conf_path, server_encoded, mode=0o600)
            new_server_hash = hashlib.sha256(server_encoded).hexdigest()

            # Step 7: Reload WireGuard
            try:
                subprocess.run(
                    ["wg", "syncconf", "wg0",
                     f"<(wg-quick strip {server_conf_path})"],
                    shell=True,
                    capture_output=True,
                    check=True,
                )
            except subprocess.CalledProcessError:
                click.echo(
                    "WARNING: WireGuard reload failed. Config on disk is updated but "
                    "service may be stale. "
                    f"Run: wg syncconf wg0 <(wg-quick strip {server_conf_path})"
                )
                # Do NOT abort — files on disk are already correct

            # Step 8: Wipe old keys and update vault state
            old_priv = state.clients[name].get("private_key")
            if isinstance(old_priv, SecretBytes):
                old_priv_bytes = bytearray(old_priv.expose_secret())
                wipe_bytes(old_priv_bytes)
                old_priv.wipe()

            old_psk_val = state.clients[name].get("psk")
            if isinstance(old_psk_val, SecretBytes):
                old_psk_bytes = bytearray(old_psk_val.expose_secret())
                wipe_bytes(old_psk_bytes)
                old_psk_val.wipe()

            # Update vault state with new keys and hashes
            state.clients[name]["private_key"] = new_keypair_priv
            state.clients[name]["public_key"] = new_pub_str
            state.clients[name]["psk"] = new_psk
            state.integrity[f"client-{name}"] = new_client_hash
            state.integrity["server"] = new_server_hash

            # Step 9: Audit log (no key material)
            audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
            audit.log(action="rotate-keys", metadata={"name": name})

            # Commit vault: state is saved when context manager exits
            vault.save(state, passphrase)

        # Step 10: Show new QR from new config
        from wg_automate.core.qr_generator import generate_qr_terminal
        import time

        qr_output = generate_qr_terminal(new_client_config_str)
        click.echo(qr_output)
        click.echo("QR will clear in 60 seconds...")
        time.sleep(60)
        click.clear()

        # Wipe config string from memory best-effort
        wipe_string(new_client_config_str)

        # Step 11: Confirm
        click.echo(f"Keys rotated for client '{name}'. New QR displayed above.")

    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)


@cli.command("rotate-server-keys")
def rotate_server_keys() -> None:
    """Rotate the server keypair and update all client configs."""
    import hashlib
    import subprocess

    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)
    click.echo(
        "WARNING: This will regenerate the server keypair and update ALL client configs. "
        "All clients must reconnect."
    )
    if not click.confirm("Proceed?", default=False):
        click.echo("Aborted.")
        return

    from wg_automate.security.secret_types import SecretBytes
    from wg_automate.security.secrets_wipe import wipe_bytes, wipe_string
    from wg_automate.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        from wg_automate.security.vault import Vault

        vault = Vault(DEFAULT_VAULT_PATH)
        with vault.open(passphrase) as state:
            clients = list(state.clients.keys())
            client_count = len(clients)

            # Step 4: Generate new server keypair
            from wg_automate.core.keygen import generate_keypair

            new_server_priv, new_server_pub = generate_keypair()
            new_server_pub_str = new_server_pub.decode("ascii")
            new_server_priv_str = new_server_priv.expose_secret().decode("ascii")

            server_data = state.server
            server_port = server_data["port"]
            server_ip_raw = server_data["ip"]
            subnet = state.ip_pool.get("subnet", "10.0.0.0/24")
            prefix_length = int(subnet.split("/")[1])

            from wg_automate.core.config_builder import ConfigBuilder
            from wg_automate.security.validator import validate_client_config, validate_server_config
            from wg_automate.security.atomic import atomic_write
            from wg_automate.platform.detect import get_adapter

            adapter = get_adapter()
            clients_dir = DEFAULT_VAULT_DIR / "clients"
            clients_dir.mkdir(parents=True, exist_ok=True)

            # Step 5: Update all client configs with new server public key
            new_client_hashes: dict = {}
            for cname in clients:
                cdata = state.clients[cname]
                client_ip = cdata["ip"]
                dns_server = cdata.get("dns_server", "1.1.1.1")
                server_endpoint = cdata.get("endpoint", f"{server_ip_raw}:{server_port}")

                cpriv_raw = cdata.get("private_key", "")
                cpriv_str = cpriv_raw if isinstance(cpriv_raw, str) else cpriv_raw.expose_secret().decode("ascii")
                cpsk_raw = cdata.get("psk", "")
                cpsk_str = cpsk_raw if isinstance(cpsk_raw, str) else cpsk_raw.expose_secret().decode("ascii")
                cpub_raw = cdata.get("public_key", "")
                cpub_str = cpub_raw if isinstance(cpub_raw, str) else cpub_raw.decode("ascii")

                updated_client_config = ConfigBuilder().render_client_config(
                    client_private_key=cpriv_str,
                    client_ip=client_ip,
                    dns_server=dns_server,
                    server_public_key=new_server_pub_str,
                    psk=cpsk_str,
                    server_endpoint=server_endpoint,
                )

                try:
                    validate_client_config({
                        "private_key": cpriv_str,
                        "psk": cpsk_str,
                        "ip": client_ip,
                        "dns_server": dns_server,
                        "server_public_key": new_server_pub_str,
                        "endpoint": server_endpoint,
                    })
                except ValueError as exc:
                    new_server_priv.wipe()
                    raise click.ClickException(
                        f"Client config validation failed for '{cname}': {exc}"
                    ) from exc

                client_conf_path = clients_dir / f"{cname}.conf"
                client_encoded = updated_client_config.encode("utf-8")
                atomic_write(client_conf_path, client_encoded, mode=0o600)
                new_client_hashes[cname] = hashlib.sha256(client_encoded).hexdigest()

            # Step 6: Update server config with new server private key
            clients_for_render = []
            for cname in clients:
                cdata = state.clients[cname]
                cpub_raw = cdata.get("public_key", "")
                cpub_str = cpub_raw if isinstance(cpub_raw, str) else cpub_raw.decode("ascii")
                cpsk_raw = cdata.get("psk", "")
                cpsk_str = cpsk_raw if isinstance(cpsk_raw, str) else cpsk_raw.expose_secret().decode("ascii")
                clients_for_render.append({
                    "name": cname,
                    "public_key": cpub_str,
                    "psk": cpsk_str,
                    "ip": cdata["ip"],
                })

            try:
                validate_server_config({
                    "private_key": new_server_priv_str,
                    "public_key": "",
                    "port": server_port,
                    "subnet": subnet,
                    "clients": clients_for_render,
                })
            except ValueError as exc:
                new_server_priv.wipe()
                raise click.ClickException(f"New server config validation failed: {exc}") from exc

            new_server_config_str = ConfigBuilder().render_server_config(
                server_private_key=new_server_priv_str,
                server_ip=server_ip_raw,
                prefix_length=prefix_length,
                server_port=server_port,
                clients=clients_for_render,
            )

            server_conf_path = adapter.get_config_path("wg0")
            server_encoded = new_server_config_str.encode("utf-8")
            atomic_write(server_conf_path, server_encoded, mode=0o600)
            new_server_hash = hashlib.sha256(server_encoded).hexdigest()

            # Step 7: Reload WireGuard
            try:
                subprocess.run(
                    ["wg", "syncconf", "wg0",
                     f"<(wg-quick strip {server_conf_path})"],
                    shell=True,
                    capture_output=True,
                    check=True,
                )
            except subprocess.CalledProcessError:
                click.echo(
                    "WARNING: WireGuard reload failed. Config on disk is updated but "
                    "service may be stale. "
                    f"Run: wg syncconf wg0 <(wg-quick strip {server_conf_path})"
                )

            # Step 8: Wipe old server private key and update vault state
            old_server_priv = state.server.get("private_key")
            if isinstance(old_server_priv, SecretBytes):
                old_bytes = bytearray(old_server_priv.expose_secret())
                wipe_bytes(old_bytes)
                old_server_priv.wipe()

            state.server["private_key"] = new_server_priv
            state.server["public_key"] = new_server_pub_str
            state.integrity["server"] = new_server_hash
            for cname, chash in new_client_hashes.items():
                state.integrity[f"client-{cname}"] = chash

            # Step 9: Audit log (no key material)
            audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
            audit.log(
                action="rotate-server-keys",
                metadata={"client_count": client_count},
            )

            vault.save(state, passphrase)

        # Step 10: Confirm
        click.echo(
            f"Server keypair rotated. {client_count} client config(s) updated. "
            "All clients must reconnect."
        )

    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)


@cli.command("update-dns")
def update_dns() -> None:
    """Push the current public IP to DuckDNS."""
    _not_implemented("update-dns")


@cli.command("export")
@click.argument("name")
def export(name: str) -> None:
    """Export a client config as a file."""
    _not_implemented("export")


@cli.command("audit-log")
@click.option("--lines", default=50, type=int, show_default=True,
              help="Number of recent entries to display")
def audit_log(lines: int) -> None:
    """Display recent audit log entries (no vault passphrase required)."""
    # Step 1: No vault unlock needed — audit log contains no secrets (AUDIT-01)

    # Step 2: Retrieve entries via AuditLog API
    from wg_automate.security.audit import AuditLog

    audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
    entries = audit.get_recent_entries(lines)

    # Step 3: Empty log case
    if not entries:
        click.echo("Audit log is empty.")
        return

    # SECURITY INVARIANT: verify no entry contains key material field names
    _SECRET_FIELD_NAMES = {"PrivateKey", "psk", "passphrase", "token"}

    # Step 4: Format and print each entry
    for entry in entries:
        # Check for secret field names in this entry's metadata
        secret_fields_found = _SECRET_FIELD_NAMES & set(entry.metadata.keys())
        if secret_fields_found:
            click.echo(
                f"CRITICAL: Audit log entry contains secret field name(s): "
                f"{secret_fields_found}. AUDIT-01 invariant violated at write time."
            )

        # Build metadata display string (skip error=None)
        meta_pairs = []
        for k, v in entry.metadata.items():
            meta_pairs.append(f"{k}={v}")
        if entry.error is not None:
            meta_pairs.append(f"error={entry.error}")

        meta_str = "  ".join(meta_pairs) if meta_pairs else ""
        action_label = entry.action
        status_label = "" if entry.success else " [FAILED]"

        click.echo(f"{entry.timestamp}  [{action_label}{status_label}]  {meta_str}")

    # Step 5: Divider and total count
    click.echo(f"-- {len(entries)} entries shown --")


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    cli()
