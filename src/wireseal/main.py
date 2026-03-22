"""wireseal: zero-secrets WireGuard server automation.

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

DEFAULT_VAULT_DIR = Path.home() / ".wireseal"
DEFAULT_VAULT_PATH = DEFAULT_VAULT_DIR / "vault.enc"
DEFAULT_AUDIT_LOG_PATH = DEFAULT_VAULT_DIR / "audit.log"

# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option()
def cli() -> None:
    """wireseal: zero-secrets WireGuard server automation."""


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
@click.option("--endpoint", default=None,
              help="Public IP or hostname clients use to reach this server. "
                   "Auto-detected from the internet if not provided.")
@click.option("--duckdns-domain", default=None,
              help="DuckDNS subdomain (optional, overrides --endpoint for clients)")
def init(subnet: str, port: int, endpoint: str | None, duckdns_domain: str | None) -> None:
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
    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        # Step 2: Vault must not already exist
        from wireseal.security.vault import Vault

        if DEFAULT_VAULT_PATH.exists():
            raise click.ClickException(
                "Vault already exists. Run verify to check integrity."
            )

        # Step 3: Privilege check
        from wireseal.platform.detect import get_adapter, get_platform_info

        adapter = get_adapter()
        adapter.check_privileges()

        # Step 3b: Resolve public endpoint (IP clients outside LAN connect to)
        if endpoint:
            public_endpoint = endpoint
            click.echo(f"Using provided endpoint: {public_endpoint}")
        else:
            click.echo("Auto-detecting public IP...")
            try:
                from wireseal.dns.ip_resolver import resolve_public_ip
                public_endpoint = str(resolve_public_ip())
                click.echo(f"Detected public IP: {public_endpoint}")
            except Exception:
                public_endpoint = None
                click.echo(
                    "Warning: Could not auto-detect public IP. "
                    "Client configs will use VPN IP (10.x.x.x) as endpoint — "
                    "only usable on the local network. "
                    "Run 'wireseal update-endpoint <IP>' after init to fix."
                )

        # Step 4: Generate server keypair
        from wireseal.core.keygen import generate_keypair

        private_key_secret, public_key_bytes = generate_keypair()
        public_key_str = public_key_bytes.decode("ascii")

        # Step 5: Allocate server IP from the subnet
        from wireseal.core.ip_pool import IPPool

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
                "endpoint": public_endpoint,  # public IP/hostname for client configs
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
        from wireseal.core.config_builder import ConfigBuilder

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
        from wireseal.security.audit import AuditLog

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
        click.echo(f"  Endpoint:    {public_endpoint or 'not set (run update-endpoint <your-public-ip>)'}")
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

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string
    from wireseal.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        # Step 2: Open vault to confirm auth, then close immediately
        from wireseal.security.vault import Vault

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

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string
    from wireseal.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        # Step 2: Open vault
        from wireseal.security.vault import Vault
        from wireseal.security.integrity import verify_config_integrity

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
        from wireseal.platform.detect import get_adapter

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
    # might exist under ~/.wireseal/ other than vault.enc / vault.hint / audit.log.
    _wipe_temp_artifacts()

    # Step 3: Confirmation message
    click.echo("Vault locked. All decrypted state wiped.")

    # Step 4: Attempt audit log — skip if inaccessible (lock must never fail)
    try:
        from wireseal.security.audit import AuditLog

        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(action="lock", metadata={})
    except Exception:
        pass  # Lock must never fail due to audit log issues

    # Step 5: Exit cleanly
    sys.exit(0)


def _wipe_temp_artifacts() -> None:
    """Remove unexpected temp files from the vault directory.

    Only keeps vault.enc, vault.hint, and audit.log.
    All other files in ~/.wireseal/ are treated as decrypted state artifacts
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

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string
    from wireseal.security.audit import AuditLog

    old_passphrase = SecretBytes(bytearray(old_str.encode("utf-8")))
    new_passphrase = SecretBytes(bytearray(new_str.encode("utf-8")))

    try:
        # Step 3: Delegate to Vault.change_passphrase
        from wireseal.security.vault import Vault

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
# Client lifecycle commands (plan 04-02)
# ===========================================================================


def _interface_is_up(interface: str) -> bool:
    """Return True if the WireGuard interface exists and is active."""
    try:
        result = subprocess.run(
            ["wg", "show", interface],
            capture_output=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def _reload_wireguard(interface: str = "wg0") -> None:
    """Reload WireGuard interface via wg syncconf (preserves active sessions).

    If the interface is not yet running, falls back to wg-quick up so that
    add-client works even when the tunnel was never started or was terminated.

    On Linux/macOS uses a two-step pipeline (wg-quick strip | wg syncconf)
    to avoid shell=True (CRIT-01).  On Windows uses wg-quick down/up.

    Raises subprocess.CalledProcessError on failure so the vault context
    manager can abort and discard the pending state change.
    """
    if sys.platform == "win32":
        subprocess.run(["wg-quick", "down", interface], check=False, capture_output=True)
        subprocess.run(["wg-quick", "up", interface], check=True, capture_output=True)
        return

    # If the interface is not running, bring it up instead of syncconf
    if not _interface_is_up(interface):
        subprocess.run(
            ["wg-quick", "up", interface],
            shell=False,
            check=True,
            capture_output=True,
        )
        return

    from wireseal.platform.detect import get_adapter
    import tempfile
    adapter = get_adapter()
    config_path = adapter.get_config_path(interface)
    # Strip PostUp/PostDown lines that wg syncconf rejects
    strip_result = subprocess.run(
        ["wg-quick", "strip", str(config_path)],
        shell=False,
        check=True,
        capture_output=True,
    )
    # wg syncconf requires a filename argument — write stripped config to a
    # temp file (mode 600) then pass its path.  Using /dev/stdin is unreliable
    # when capture_output=True closes the fd before wg reads it.
    with tempfile.NamedTemporaryFile(
        suffix=".conf", mode="wb", delete=False
    ) as tmp:
        tmp.write(strip_result.stdout)
        tmp_path = tmp.name
    try:
        os.chmod(tmp_path, 0o600)
        subprocess.run(
            ["wg", "syncconf", interface, tmp_path],
            shell=False,
            check=True,
            capture_output=True,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _not_implemented(name: str) -> None:
    raise click.ClickException(f"Not yet implemented: {name}")


def _resolve_client_endpoint(server_state: dict) -> str:
    """Return the endpoint string clients use to reach the server.

    Priority order:
      1. DuckDNS domain (if configured)
      2. Stored public endpoint/IP (set during init or update-endpoint)
      3. VPN server IP (fallback — only works on local network)
    """
    port = server_state["port"]
    duckdns_domain = server_state.get("duckdns_domain")
    if duckdns_domain:
        return f"{duckdns_domain}.duckdns.org:{port}"
    stored_endpoint = server_state.get("endpoint")
    if stored_endpoint:
        return f"{stored_endpoint}:{port}"
    # Last resort: VPN IP — only reachable from inside the VPN
    return f"{server_state['ip']}:{port}"


def _extract_secret_str(value: object) -> str:
    """Extract a plain string from either a str or SecretBytes value."""
    from wireseal.security.secret_types import SecretBytes
    if isinstance(value, SecretBytes):
        return value.expose_secret().decode("utf-8")
    return str(value)


@cli.command("add-client")
@click.argument("name")
def add_client(name: str) -> None:
    """Add a new WireGuard client and generate its config."""
    # Step 1: Validate name — alphanumeric + hyphens, max 32 chars (CONFIG-06)
    if not re.fullmatch(r'^[a-zA-Z0-9-]{1,32}$', name):
        raise click.BadParameter(
            "Name must be alphanumeric with hyphens only, max 32 characters.",
            param_hint="'NAME'",
        )

    # Step 2: Collect passphrase — CLI-02
    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))
    client_config_str: str | None = None

    try:
        from wireseal.security.vault import Vault
        from wireseal.security.audit import AuditLog
        from wireseal.core.keygen import generate_keypair
        from wireseal.core.psk import generate_psk
        from wireseal.core.ip_pool import IPPool
        from wireseal.core.config_builder import ConfigBuilder
        from wireseal.security.atomic import atomic_write
        from wireseal.core.qr_generator import generate_qr_terminal, QR_DISPLAY_TIMEOUT
        from wireseal.platform.detect import get_adapter

        vault = Vault(DEFAULT_VAULT_PATH)

        # Steps 3-14: Keep vault open for the entire operation.
        # Vault is committed (vault.save) only AFTER wg syncconf succeeds.
        with vault.open(passphrase) as state:
            # Step 4: Check for duplicate client name
            if name in state.clients:
                raise click.ClickException(f"Client '{name}' already exists.")

            # Step 5: Generate client keypair
            private_key_secret, public_key_bytes = generate_keypair()
            public_key_str = public_key_bytes.decode("ascii")
            private_key_str = private_key_secret.expose_secret().decode("ascii")

            # Step 6: Generate PSK
            psk_secret = generate_psk()
            psk_str = psk_secret.expose_secret().decode("ascii")

            # Step 7: Allocate next available IP from pool
            pool = IPPool(state.ip_pool["subnet"])
            pool.load_state(state.ip_pool.get("allocated", {}))
            allocated_ip = pool.allocate(name)

            # Step 8: Build client config (stays in memory)
            server_pub_key = _extract_secret_str(state.server["public_key"])
            server_port = state.server["port"]
            server_ip = state.server["ip"]

            server_endpoint = _resolve_client_endpoint(state.server)

            builder = ConfigBuilder()
            # Validation is performed inside render_client_config (CONFIG-02)
            client_config_str = builder.render_client_config(
                client_private_key=private_key_str,
                client_ip=allocated_ip,
                dns_server=server_ip,  # use server VPN IP as DNS
                server_public_key=server_pub_key,
                psk=psk_str,
                server_endpoint=server_endpoint,
            )

            # Step 10: Write client config atomically with 600 permissions
            clients_dir = DEFAULT_VAULT_DIR / "clients"
            clients_dir.mkdir(parents=True, exist_ok=True)
            client_conf_path = clients_dir / f"{name}.conf"
            atomic_write(client_conf_path, client_config_str.encode("utf-8"), mode=0o600)

            # Step 11: Compute SHA-256 of written file
            config_hash = hashlib.sha256(client_config_str.encode("utf-8")).hexdigest()

            # Step 12: Rebuild server config with all existing + new peer
            peers = []
            for cname, cdata in state.clients.items():
                peers.append({
                    "name": cname,
                    "public_key": _extract_secret_str(cdata["public_key"]),
                    "psk": _extract_secret_str(cdata["psk"]),
                    "ip": cdata["ip"],
                })
            peers.append({
                "name": name,
                "public_key": public_key_str,
                "psk": psk_str,
                "ip": allocated_ip,
            })

            server_private_key_str = _extract_secret_str(state.server["private_key"])
            server_config_content = builder.render_server_config(
                server_private_key=server_private_key_str,
                server_ip=server_ip,
                prefix_length=int(state.ip_pool["subnet"].split("/")[1]),
                server_port=server_port,
                clients=peers,
            )

            adapter = get_adapter()
            adapter.deploy_config(server_config_content)

            # Step 13: Reload WireGuard — CLIENT-01 atomic revocation boundary
            _reload_wireguard()

            # Persist client in vault AFTER successful syncconf
            state.clients[name] = {
                "private_key": private_key_str,
                "public_key": public_key_str,
                "psk": psk_str,
                "ip": allocated_ip,
                "config_hash": config_hash,
            }
            state.ip_pool["allocated"] = pool.get_allocated()
            state.integrity[f"client-{name}"] = config_hash
            vault.save(state, passphrase)

            # Step 14: Audit log — no key material
            audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
            audit.log(
                action="add-client",
                metadata={"name": name, "ip": allocated_ip},
            )

        # Step 15: Display QR — vault context already wiped
        click.echo(f"\nClient '{name}' added successfully.")
        click.echo(f"  IP: {allocated_ip}")
        click.echo("\nScan the QR code below with your WireGuard app:\n")
        click.echo(generate_qr_terminal(client_config_str))
        click.echo(f"QR will clear in {QR_DISPLAY_TIMEOUT} seconds...")
        time.sleep(QR_DISPLAY_TIMEOUT)
        click.clear()

    except (click.ClickException, click.BadParameter):
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)
        # Step 16: Wipe client config string from memory (best-effort for str)
        if client_config_str is not None:
            del client_config_str


@cli.command("remove-client")
@click.argument("name")
def remove_client(name: str) -> None:
    """Remove a client and revoke its WireGuard access immediately."""
    # Step 1: Collect passphrase — CLI-02
    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        from wireseal.security.vault import Vault
        from wireseal.security.audit import AuditLog
        from wireseal.core.ip_pool import IPPool
        from wireseal.core.config_builder import ConfigBuilder
        from wireseal.platform.detect import get_adapter

        vault = Vault(DEFAULT_VAULT_PATH)

        with vault.open(passphrase) as state:
            # Step 3: Verify client exists
            if name not in state.clients:
                raise click.ClickException(f"Client '{name}' not found.")

            client_data = state.clients[name]
            revoked_ip = client_data["ip"]

            # Step 4: Rebuild server config WITHOUT the removed peer
            peers = []
            for cname, cdata in state.clients.items():
                if cname == name:
                    continue  # omit the client being revoked
                peers.append({
                    "name": cname,
                    "public_key": _extract_secret_str(cdata["public_key"]),
                    "psk": _extract_secret_str(cdata["psk"]),
                    "ip": cdata["ip"],
                })

            server_private_key_str = _extract_secret_str(state.server["private_key"])
            builder = ConfigBuilder()
            server_config_content = builder.render_server_config(
                server_private_key=server_private_key_str,
                server_ip=state.server["ip"],
                prefix_length=int(state.ip_pool["subnet"].split("/")[1]),
                server_port=state.server["port"],
                clients=peers,
            )

            adapter = get_adapter()
            adapter.deploy_config(server_config_content)

            # Step 5: Reload WireGuard — revocation moment (CLIENT-02: no grace period)
            _reload_wireguard()

            # Step 6: Release IP in pool
            pool = IPPool(state.ip_pool["subnet"])
            pool.load_state(state.ip_pool.get("allocated", {}))
            pool.release(revoked_ip)
            state.ip_pool["allocated"] = pool.get_allocated()

            # Step 7: Purge client from vault (private key, PSK, IP, config hash)
            del state.clients[name]
            state.integrity.pop(f"client-{name}", None)
            state.integrity.pop(f"client-{name}_verified", None)

            # Step 8: Delete client config file if it exists
            client_conf_path = DEFAULT_VAULT_DIR / "clients" / f"{name}.conf"
            if client_conf_path.exists():
                try:
                    client_conf_path.unlink()
                except OSError:
                    pass

            vault.save(state, passphrase)

            # Step 9: Audit log — no key material
            audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
            audit.log(
                action="remove-client",
                metadata={"name": name},
            )

        # Step 10: Confirmation
        click.echo(f"Client '{name}' removed and revoked.")

    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)


@cli.command("list-clients")
def list_clients() -> None:
    """List all registered WireGuard clients (name, IP, last handshake)."""
    # Step 1: Collect passphrase — CLI-02
    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        from wireseal.security.vault import Vault
        from wireseal.security.audit import AuditLog

        vault = Vault(DEFAULT_VAULT_PATH)

        with vault.open(passphrase) as state:
            clients_snapshot: dict = {}
            for cname, cdata in state.clients.items():
                clients_snapshot[cname] = {
                    "public_key": _extract_secret_str(cdata["public_key"]),
                    "ip": cdata["ip"],
                }

        if not clients_snapshot:
            click.echo("No clients configured.")
        else:
            # Step 3: Run wg show dump to get latest-handshake per peer
            handshake_by_pubkey: dict[str, str] = {}
            try:
                result = subprocess.run(
                    ["wg", "show", "wg0", "dump"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                # wg show dump format (tab-separated per line):
                # peer: public_key  psk_hash  endpoint  allowed_ips  latest_handshake  rx  tx  keepalive
                for line in result.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 6:
                        # First line is the interface (5 fields), skip it
                        pubkey = parts[0].strip()
                        latest_handshake_epoch = parts[4].strip()
                        if pubkey and latest_handshake_epoch != "0":
                            try:
                                import datetime as _dt
                                ts = int(latest_handshake_epoch)
                                handshake_str = _dt.datetime.fromtimestamp(
                                    ts, tz=_dt.timezone.utc
                                ).strftime("%Y-%m-%d %H:%M:%S UTC")
                            except (ValueError, OSError):
                                handshake_str = latest_handshake_epoch
                            handshake_by_pubkey[pubkey] = handshake_str
            except (subprocess.CalledProcessError, FileNotFoundError):
                click.echo("WARNING: WireGuard not running or no active peers.")

            # Step 4: Print table — CLIENT-03: no private keys or PSKs
            click.echo(f"\n{'Name':20}  {'IP':15}  {'Last Handshake'}")
            click.echo("-" * 65)
            for cname, cinfo in clients_snapshot.items():
                pubkey = cinfo["public_key"]
                ip = cinfo["ip"]
                handshake = handshake_by_pubkey.get(pubkey, "never")
                click.echo(f"{cname:20}  {ip:15}  {handshake}")

        # Step 6: Audit log
        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(action="list-clients", metadata={})

    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)


@cli.command("show-qr")
@click.argument("name")
@click.option("--save-qr", "save_path", default=None, type=click.Path(),
              help="Save QR to file (600 permissions)")
@click.option("--auto-delete", is_flag=True, default=False,
              help="Auto-delete saved QR file after 5 minutes")
def show_qr(name: str, save_path: str | None, auto_delete: bool) -> None:
    """Display the QR code for a client config (clears after 60 seconds)."""
    # Step 1: Collect passphrase — CLI-02
    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))
    config_str: str | None = None

    try:
        from wireseal.security.vault import Vault
        from wireseal.security.audit import AuditLog
        from wireseal.core.config_builder import ConfigBuilder
        from wireseal.core.qr_generator import generate_qr_terminal, save_qr

        vault = Vault(DEFAULT_VAULT_PATH)

        with vault.open(passphrase) as state:
            # Step 2: Retrieve client config — abort if not found
            if name not in state.clients:
                raise click.ClickException(f"Client '{name}' not found.")

            cdata = state.clients[name]
            server_pub_key = _extract_secret_str(state.server["public_key"])
            server_port = state.server["port"]
            server_ip = state.server["ip"]

            server_endpoint = _resolve_client_endpoint(state.server)

            # Step 3: Reconstruct client config from vault state (in memory only)
            builder = ConfigBuilder()
            config_str = builder.render_client_config(
                client_private_key=_extract_secret_str(cdata["private_key"]),
                client_ip=cdata["ip"],
                dns_server=server_ip,
                server_public_key=server_pub_key,
                psk=_extract_secret_str(cdata["psk"]),
                server_endpoint=server_endpoint,
            )

        # Steps 4-8 outside vault context (state already wiped)
        # Step 5: Print QR to terminal (CLIENT-04: ASCII only)
        click.echo(generate_qr_terminal(config_str))

        # Step 6: Optionally save to file (CLIENT-08)
        if save_path is not None:
            save_qr(config_str, Path(save_path), auto_delete=auto_delete)

        # Step 7: 60-second auto-clear (CLIENT-04)
        click.echo("Terminal will clear in 60 seconds...")
        time.sleep(60)
        click.clear()

        # Audit log — no key material
        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(action="show-qr", metadata={"name": name})

    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)
        # Step 8: Wipe config string from memory (best-effort for str)
        if config_str is not None:
            del config_str


@cli.command("rotate-keys")
@click.argument("name")
def rotate_keys(name: str) -> None:
    """Rotate the keypair and PSK for a specific client."""
    import hashlib
    import subprocess

    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_bytes, wipe_string
    from wireseal.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        from wireseal.security.vault import Vault

        vault = Vault(DEFAULT_VAULT_PATH)
        with vault.open(passphrase) as state:
            # Step 3: Verify client exists
            if name not in state.clients:
                raise click.ClickException(f"Client '{name}' not found in vault.")

            client_data = state.clients[name]

            # Step 4: Generate new material BEFORE touching old keys
            from wireseal.core.keygen import generate_keypair
            from wireseal.core.psk import generate_psk

            new_keypair_priv, new_keypair_pub = generate_keypair()
            new_psk = generate_psk()

            new_pub_str = new_keypair_pub.decode("ascii")
            new_priv_str = new_keypair_priv.expose_secret().decode("ascii")
            new_psk_str = new_psk.expose_secret().decode("ascii")

            # Step 5: Build and validate new configs
            from wireseal.core.config_builder import ConfigBuilder
            from wireseal.security.validator import validate_client_config, validate_server_config

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
            from wireseal.security.atomic import atomic_write
            from wireseal.platform.detect import get_adapter

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

            # Step 7: Reload WireGuard (no shell=True — CRIT-01 fix)
            try:
                strip_result = subprocess.run(
                    ["wg-quick", "strip", str(server_conf_path)],
                    shell=False,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["wg", "syncconf", "wg0"],
                    shell=False,
                    check=True,
                    input=strip_result.stdout,
                    capture_output=True,
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
        from wireseal.core.qr_generator import generate_qr_terminal
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

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_bytes, wipe_string
    from wireseal.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        from wireseal.security.vault import Vault

        vault = Vault(DEFAULT_VAULT_PATH)
        with vault.open(passphrase) as state:
            clients = list(state.clients.keys())
            client_count = len(clients)

            # Step 4: Generate new server keypair
            from wireseal.core.keygen import generate_keypair

            new_server_priv, new_server_pub = generate_keypair()
            new_server_pub_str = new_server_pub.decode("ascii")
            new_server_priv_str = new_server_priv.expose_secret().decode("ascii")

            server_data = state.server
            server_port = server_data["port"]
            server_ip_raw = server_data["ip"]
            subnet = state.ip_pool.get("subnet", "10.0.0.0/24")
            prefix_length = int(subnet.split("/")[1])

            from wireseal.core.config_builder import ConfigBuilder
            from wireseal.security.validator import validate_client_config, validate_server_config
            from wireseal.security.atomic import atomic_write
            from wireseal.platform.detect import get_adapter

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

            # Step 7: Reload WireGuard (no shell=True — CRIT-01 fix)
            try:
                strip_result = subprocess.run(
                    ["wg-quick", "strip", str(server_conf_path)],
                    shell=False,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["wg", "syncconf", "wg0"],
                    shell=False,
                    check=True,
                    input=strip_result.stdout,
                    capture_output=True,
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
    """Push the current public IP to DuckDNS (2-of-3 consensus)."""
    # Step 1: Collect passphrase — CLI-02
    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        from wireseal.security.vault import Vault
        from wireseal.security.audit import AuditLog

        vault = Vault(DEFAULT_VAULT_PATH)

        # Step 2: Read DuckDNS domain and token from vault
        with vault.open(passphrase) as state:
            duckdns_domain = state.server.get("duckdns_domain")
            if not duckdns_domain:
                raise click.ClickException(
                    "DuckDNS not configured. Run init with --duckdns-domain."
                )

            duckdns_token_raw = state.server.get("duckdns_token")
            if duckdns_token_raw is None:
                raise click.ClickException(
                    "DuckDNS token not found in vault. Re-run init with --duckdns-domain."
                )

            # Keep token as SecretBytes; expose only for the HTTP call inside update_dns
            from wireseal.security.secret_types import SecretBytes as SB
            if isinstance(duckdns_token_raw, SB):
                token_secret = duckdns_token_raw
            else:
                token_secret = SB(bytearray(str(duckdns_token_raw).encode("utf-8")))

            # Step 3: Resolve public IP with 2-of-3 consensus (DNS-01)
            from wireseal.dns.ip_resolver import resolve_public_ip, IPConsensusError

            try:
                public_ip = resolve_public_ip()
            except IPConsensusError as exc:
                raise click.ClickException(str(exc)) from exc

            # Step 4: Update DuckDNS — token stays in SecretBytes (DNS-03)
            from wireseal.dns.duckdns import update_dns as _update_dns, DuckDNSError

            try:
                result = _update_dns(duckdns_domain, token_secret, str(public_ip))
            except DuckDNSError as exc:
                result = {
                    "success": False,
                    "domain": duckdns_domain,
                    "ip": str(public_ip),
                    "error": str(exc),
                }

        # Step 5: Audit log — result dict has success/domain/ip, no token
        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(
            action="update-dns",
            metadata={
                "domain": result.get("domain"),
                "ip": result.get("ip"),
                "success": result.get("success"),
            },
        )

        # Step 6: Report outcome
        if result.get("success"):
            click.echo(f"DNS updated: {result['domain']}.duckdns.org -> {result['ip']}")
        else:
            click.echo(f"DNS update failed: {result.get('error', 'unknown error')}")
            sys.exit(1)

    except click.ClickException:
        raise
    except SystemExit:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)


@cli.command("export")
@click.argument("name")
@click.argument("path", type=click.Path())
def export(name: str, path: str) -> None:
    """Export a client config to a file (600 permissions, private key warning)."""
    # Step 1: Collect passphrase — CLI-02
    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))
    config_str: str | None = None

    try:
        from wireseal.security.vault import Vault
        from wireseal.security.audit import AuditLog
        from wireseal.core.config_builder import ConfigBuilder
        from wireseal.security.atomic import atomic_write

        vault = Vault(DEFAULT_VAULT_PATH)

        with vault.open(passphrase) as state:
            # Step 2: Retrieve client config — abort if not found
            if name not in state.clients:
                raise click.ClickException(f"Client '{name}' not found.")

            cdata = state.clients[name]
            server_pub_key = _extract_secret_str(state.server["public_key"])
            server_port = state.server["port"]
            server_ip = state.server["ip"]

            server_endpoint = _resolve_client_endpoint(state.server)

            # Step 3: Reconstruct full client config from vault state
            builder = ConfigBuilder()
            config_str = builder.render_client_config(
                client_private_key=_extract_secret_str(cdata["private_key"]),
                client_ip=cdata["ip"],
                dns_server=server_ip,
                server_public_key=server_pub_key,
                psk=_extract_secret_str(cdata["psk"]),
                server_endpoint=server_endpoint,
            )

        # Step 4: Write to path atomically with 600 permissions (CLIENT-07)
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(dest, config_str.encode("utf-8"), mode=0o600)

        # On Windows: also apply ACL-based permissions
        if sys.platform == "win32":
            from wireseal.security.permissions import set_file_permissions
            set_file_permissions(dest, mode=0o600)

        # Step 5: Print path and private-key warning (CLIENT-07)
        click.echo(f"Client config written to: {path}")
        click.echo("WARNING: This file contains a private key. Delete it after use.")
        if sys.platform == "linux":
            click.echo(f"Recommended: wipe with 'shred -u {path}' (Linux) or 'sdelete' (Windows).")
        elif sys.platform == "win32":
            click.echo(f"Recommended: wipe with 'sdelete {path}' (Windows).")
        else:
            click.echo(f"Recommended: securely delete '{path}' after use.")

        # Step 6: Audit log — no key material
        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(
            action="export",
            metadata={"name": name, "path": path},
        )

    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)
        if config_str is not None:
            del config_str


@cli.command("audit-log")
@click.option("--lines", default=50, type=int, show_default=True,
              help="Number of recent entries to display")
def audit_log(lines: int) -> None:
    """Display recent audit log entries (no vault passphrase required)."""
    # Step 1: No vault unlock needed — audit log contains no secrets (AUDIT-01)

    # Step 2: Retrieve entries via AuditLog API
    from wireseal.security.audit import AuditLog

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
# terminate
# ===========================================================================


@cli.command("terminate")
@click.option("--interface", default="wg0", show_default=True,
              help="WireGuard interface to bring down")
def terminate(interface: str) -> None:
    """Bring down the WireGuard interface and disconnect all peers.

    Does NOT delete the vault or any config files. Run 'init' or
    'wg-quick up <interface>' to restart the tunnel.
    No vault passphrase is required.
    """
    from wireseal.security.audit import AuditLog

    click.echo(f"Bringing down WireGuard interface '{interface}'...")

    try:
        result = subprocess.run(
            ["wg-quick", "down", interface],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            click.echo(f"Interface '{interface}' is down. All peers disconnected.")
        else:
            stderr = result.stderr.strip()
            # wg-quick returns non-zero if the interface was already down
            if "does not exist" in stderr or "is not a WireGuard interface" in stderr:
                click.echo(f"Interface '{interface}' was already down.")
            else:
                raise click.ClickException(
                    f"wg-quick down failed: {stderr or result.stdout.strip()}"
                )
    except FileNotFoundError:
        raise click.ClickException(
            "wg-quick not found. Install wireguard-tools and try again."
        )

    try:
        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(action="terminate", metadata={"interface": interface})
    except Exception:
        pass  # Audit failure must not prevent terminate


# ===========================================================================
# fresh-start
# ===========================================================================


@cli.command("fresh-start")
@click.option("--interface", default="wg0", show_default=True,
              help="WireGuard interface to tear down")
@click.option("--reinit", is_flag=True, default=False,
              help="Immediately re-initialise after wiping (prompts for new passphrase)")
@click.option("--subnet", default="10.0.0.0/24", show_default=True,
              help="Subnet to use when --reinit is set")
@click.option("--port", default=51820, type=int, show_default=True,
              help="Listen port to use when --reinit is set")
def fresh_start(interface: str, reinit: bool, subnet: str, port: int) -> None:
    """Wipe all WireSeal data and start from scratch.

    \b
    This command:
      1. Brings down the WireGuard interface (disconnects all peers)
      2. Deletes the vault and audit log (~/.wireseal/ or /root/.wireseal/)
      3. Removes /etc/wireguard/<interface>.conf and all client configs
      4. Optionally re-initialises immediately (--reinit)

    ALL KEYS AND CLIENT CONFIGURATIONS ARE PERMANENTLY DESTROYED.
    There is no undo. Type CONFIRM when prompted.
    """
    click.echo("")
    click.secho("  WARNING: DESTRUCTIVE OPERATION", fg="red", bold=True)
    click.echo("  This will permanently destroy:")
    click.echo(f"    - Vault and all encrypted key material  ({DEFAULT_VAULT_DIR})")
    click.echo(f"    - WireGuard server config               (/etc/wireguard/{interface}.conf)")
    click.echo(f"    - All client configs                    (/etc/wireguard/clients/)")
    click.echo(f"    - Audit log")
    click.echo("")

    confirm = click.prompt('Type CONFIRM to proceed (anything else aborts)')
    if confirm != "CONFIRM":
        click.echo("Aborted. Nothing was changed.")
        return

    errors: list[str] = []

    # Step 1: Bring down the interface
    click.echo(f"\nStep 1/3  Bringing down '{interface}'...")
    try:
        subprocess.run(
            ["wg-quick", "down", interface],
            capture_output=True,
            text=True,
        )
        click.echo(f"          Interface '{interface}' down.")
    except FileNotFoundError:
        click.echo("          wg-quick not found — skipping interface teardown.")
    except Exception as exc:
        errors.append(f"Interface teardown: {exc}")
        click.echo(f"          Warning: {exc}")

    # Step 2: Delete vault directory
    click.echo(f"Step 2/3  Removing vault directory {DEFAULT_VAULT_DIR} ...")
    import shutil
    try:
        if DEFAULT_VAULT_DIR.exists():
            shutil.rmtree(DEFAULT_VAULT_DIR)
            click.echo(f"          Removed {DEFAULT_VAULT_DIR}")
        else:
            click.echo(f"          {DEFAULT_VAULT_DIR} does not exist — skipping.")
    except Exception as exc:
        errors.append(f"Vault removal: {exc}")
        click.echo(f"          Warning: {exc}")

    # Step 3: Remove WireGuard config files
    click.echo(f"Step 3/3  Removing WireGuard config files...")
    wg_conf_dirs = [
        Path("/etc/wireguard"),
        Path(f"C:/Program Files/WireGuard") if sys.platform == "win32" else None,
    ]
    for wg_dir in wg_conf_dirs:
        if wg_dir is None or not wg_dir.exists():
            continue
        server_conf = wg_dir / f"{interface}.conf"
        clients_dir = wg_dir / "clients"
        for target in [server_conf, clients_dir]:
            try:
                if target.is_file():
                    target.unlink()
                    click.echo(f"          Removed {target}")
                elif target.is_dir():
                    shutil.rmtree(target)
                    click.echo(f"          Removed {target}/")
            except PermissionError:
                msg = f"Permission denied removing {target} — run with sudo"
                errors.append(msg)
                click.echo(f"          Warning: {msg}")
            except Exception as exc:
                errors.append(str(exc))
                click.echo(f"          Warning: {exc}")

    click.echo("")
    if errors:
        click.secho("Fresh start completed with warnings:", fg="yellow")
        for e in errors:
            click.echo(f"  - {e}")
    else:
        click.secho("Fresh start complete. All data wiped.", fg="green")

    # Step 4: Optional re-init
    if reinit:
        click.echo("")
        click.echo("Re-initialising server...")
        from click.testing import CliRunner
        # Invoke init directly via the CLI group (inherits passphrase prompt)
        ctx = click.get_current_context()
        ctx.invoke(init, subnet=subnet, port=port, duckdns_domain=None)


# ===========================================================================
# update-endpoint
# ===========================================================================


@cli.command("update-endpoint")
@click.argument("ip_or_host", required=False, default=None,
                metavar="[IP_OR_HOSTNAME]")
def update_endpoint(ip_or_host: str | None) -> None:
    """Update the public IP/hostname stored in the vault for client configs.

    \b
    If IP_OR_HOSTNAME is not given, auto-detects your current public IP.
    After updating, re-run 'show-qr' or 'export' for each client and
    re-import the new config on their devices.

    \b
    Examples:
      wireseal update-endpoint                  # auto-detect
      wireseal update-endpoint 203.0.113.45     # set manually
      wireseal update-endpoint myhome.duckdns.org
    """
    passphrase_str: str = click.prompt("Vault passphrase", hide_input=True)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string
    from wireseal.security.audit import AuditLog
    from wireseal.security.vault import Vault

    passphrase = SecretBytes(bytearray(passphrase_str.encode("utf-8")))

    try:
        if ip_or_host:
            new_endpoint = ip_or_host
        else:
            click.echo("Auto-detecting public IP...")
            from wireseal.dns.ip_resolver import resolve_public_ip
            new_endpoint = str(resolve_public_ip())

        vault = Vault(DEFAULT_VAULT_PATH)
        with vault.open(passphrase) as state:
            old_endpoint = state.server.get("endpoint", "not set")
            state.server["endpoint"] = new_endpoint
            vault.save(state, passphrase)

        click.echo(f"Endpoint updated: {old_endpoint}  →  {new_endpoint}")
        click.echo("")
        click.echo("IMPORTANT: Re-generate client configs so devices use the new endpoint:")
        click.echo("  sudo wireseal show-qr <client>   — re-scan on each device")
        click.echo("  sudo wireseal export <client>    — for file-based import")

        audit = AuditLog(DEFAULT_AUDIT_LOG_PATH)
        audit.log(action="update-endpoint", metadata={"endpoint": new_endpoint})

    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        passphrase.wipe()
        wipe_string(passphrase_str)


# ===========================================================================
# Entry point
# ===========================================================================

# ---------------------------------------------------------------------------
# serve  — web dashboard + REST API
# ---------------------------------------------------------------------------


@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Address to bind (use 0.0.0.0 for LAN access)")
@click.option("--port", default=8080, type=int, show_default=True,
              help="Port for the web dashboard")
def serve(host: str, port: int) -> None:
    """Start the WireSeal web dashboard and REST API server."""
    from wireseal.api import serve as _serve
    _serve(host=host, port=port)


if __name__ == "__main__":
    cli()
