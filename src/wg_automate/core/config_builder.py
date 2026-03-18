"""WireGuard config file builder using Jinja2 templates.

Renders server and client WireGuard config files from templates, with:
  - Pre-render validation (raises ValueError on invalid input -- never renders partial config)
  - Atomic writes with 600 permissions and FileLock to prevent TOCTOU races
  - SHA-256 hash computed after write for integrity tracking
  - StrictUndefined: missing template variables fail immediately (not silently empty)
  - autoescape=False: plain text output -- autoescape=True would corrupt base64 '=' chars

CONFIG-01: StrictUndefined + autoescape=False
CONFIG-02: Validation before render (invalid input raises ValueError)
CONFIG-03: Atomic write with 600 permissions
CONFIG-04: SHA-256 hash returned after write
CONFIG-05: FileLock (not SoftFileLock) -- prevents TOCTOU during write-apply cycle
"""

import hashlib
from pathlib import Path

from filelock import FileLock
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from wg_automate.security.atomic import atomic_write


class ConfigBuilder:
    """Renders WireGuard config files from Jinja2 templates with pre-render validation.

    Usage::

        builder = ConfigBuilder()
        content = builder.render_server_config(
            server_private_key="...",
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=[{"name": "alice", "public_key": "...", "psk": "...", "ip": "10.0.0.2"}],
        )
        hash_hex = builder.write_config(Path("/etc/wireguard/wg0.conf"), content)
    """

    def __init__(self, template_dir: Path | None = None) -> None:
        """Initialize the config builder with Jinja2 environment.

        Args:
            template_dir: Directory containing .j2 templates. Defaults to the
                          package's built-in templates/ directory.
        """
        if template_dir is None:
            template_dir = Path(__file__).parent.parent / "templates"

        # CONFIG-01: StrictUndefined causes immediate TemplateError on missing vars.
        # autoescape=False is REQUIRED for plain text WireGuard configs: autoescape=True
        # would HTML-escape base64 '=' to '&#61;', corrupting cryptographic keys.
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            undefined=StrictUndefined,
            autoescape=False,  # CORRECT: plain text, not HTML
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render_server_config(
        self,
        server_private_key: str,
        server_ip: str,
        prefix_length: int,
        server_port: int,
        clients: list[dict],
        post_up: str = "",
        post_down: str = "",
    ) -> str:
        """Render a WireGuard server config file.

        Validates all inputs before rendering. If validation fails, raises
        ValueError without producing any output (no partial configs).

        Args:
            server_private_key: 44-char base64 WireGuard private key.
            server_ip:          Server VPN IP address (e.g., "10.0.0.1").
            prefix_length:      Subnet prefix length (e.g., 24).
            server_port:        WireGuard listen port (1024-65535).
            clients:            List of client dicts with keys: name, public_key, psk, ip.
            post_up:            PostUp firewall command (empty = omit from config).
            post_down:          PostDown firewall command (empty = omit from config).

        Returns:
            Rendered config file content as a string.

        Raises:
            ValueError: If any field fails validation (no rendering performed).
        """
        from wg_automate.security.validator import validate_server_config

        # CONFIG-02: validate BEFORE rendering -- invalid input never produces output
        validate_server_config({
            "private_key": server_private_key,
            "public_key": "",  # server pubkey not available at render time -- skip
            "port": server_port,
            "subnet": f"{server_ip}/{prefix_length}",
            "clients": clients,
        })

        template = self.env.get_template("server.conf.j2")
        return template.render(
            server_private_key=server_private_key,
            server_ip=server_ip,
            prefix_length=prefix_length,
            server_port=server_port,
            clients=clients,
            post_up=post_up,
            post_down=post_down,
        )

    def render_client_config(
        self,
        client_private_key: str,
        client_ip: str,
        dns_server: str,
        server_public_key: str,
        psk: str,
        server_endpoint: str,
    ) -> str:
        """Render a WireGuard client config file.

        Validates all inputs before rendering. If validation fails, raises
        ValueError without producing any output (no partial configs).

        Args:
            client_private_key: 44-char base64 WireGuard private key.
            client_ip:          Client VPN IP address (e.g., "10.0.0.2").
            dns_server:         DNS server IP for the client.
            server_public_key:  44-char base64 server public key.
            psk:                44-char base64 pre-shared key.
            server_endpoint:    Server endpoint (host:port).

        Returns:
            Rendered config file content as a string.

        Raises:
            ValueError: If any field fails validation (no rendering performed).
        """
        from wg_automate.security.validator import validate_client_config

        # CONFIG-02: validate BEFORE rendering -- invalid input never produces output
        validate_client_config({
            "private_key": client_private_key,
            "psk": psk,
            "ip": client_ip,
            "dns_server": dns_server,
            "server_public_key": server_public_key,
            "endpoint": server_endpoint,
        })

        template = self.env.get_template("client.conf.j2")
        return template.render(
            client_private_key=client_private_key,
            client_ip=client_ip,
            dns_server=dns_server,
            server_public_key=server_public_key,
            psk=psk,
            server_endpoint=server_endpoint,
        )

    def write_config(
        self,
        path: Path,
        content: str,
        lock_path: Path | None = None,
    ) -> str:
        """Write a rendered config to disk atomically with 600 permissions.

        CONFIG-03: Atomic write with 600 permissions (via atomic_write).
        CONFIG-04: Returns SHA-256 hex digest of written content.
        CONFIG-05: FileLock (not SoftFileLock) prevents TOCTOU races.

        Args:
            path:      Destination path for the config file.
            content:   Rendered config file content (string).
            lock_path: If provided, acquire FileLock at this path before writing.
                       Must be a lock file path (e.g., path.with_suffix(".lock")).

        Returns:
            SHA-256 hex digest of the written content (for integrity tracking).
        """
        encoded = content.encode("utf-8")

        if lock_path is not None:
            # CONFIG-05: FileLock not SoftFileLock -- hard lock, no silent fallback
            with FileLock(lock_path, timeout=30):
                atomic_write(path, encoded, mode=0o600)
        else:
            atomic_write(path, encoded, mode=0o600)

        # CONFIG-04: compute and return SHA-256 hash of the written content
        return hashlib.sha256(encoded).hexdigest()
