"""Unit tests for WireGuard config builder.

Tests verify:
  - Server config contains Interface section, PrivateKey, ListenPort, and at least one Peer
  - Missing template variable raises jinja2.UndefinedError (StrictUndefined)
  - write_config() returns SHA-256 hex digest matching hashlib.sha256(content).hexdigest()
  - Client config contains server public key
  - Validation before render: invalid input raises ValueError without partial output

NOTE: autoescape=False is correct for WireGuard INI configs. autoescape=True would
HTML-escape base64 '=' to '&#61;', corrupting cryptographic keys. Tests verify
that base64 key material is NOT HTML-escaped in the rendered output.
"""

import base64
import hashlib

import jinja2
import pytest

from wg_automate.core.config_builder import ConfigBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_key() -> str:
    """Return a valid 44-char base64-encoded 32-byte key."""
    raw = b"\x01" * 32
    return base64.b64encode(raw).decode("ascii")


def _valid_client_key() -> str:
    """Return a distinct valid key for client use."""
    raw = b"\x02" * 32
    return base64.b64encode(raw).decode("ascii")


def _valid_psk() -> str:
    """Return a valid 44-char PSK."""
    raw = b"\x03" * 32
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# Server config rendering tests
# ---------------------------------------------------------------------------

class TestServerConfigRendering:
    """Tests for ConfigBuilder.render_server_config()."""

    def test_all_required_fields_rendered(self):
        """Complete server config contains [Interface], PrivateKey, ListenPort, and [Peer]."""
        builder = ConfigBuilder()
        client = {
            "name": "alice",
            "public_key": _valid_client_key(),
            "psk": _valid_psk(),
            "ip": "10.0.0.2",
        }
        content = builder.render_server_config(
            server_private_key=_valid_key(),
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=[client],
        )
        assert "[Interface]" in content
        assert "PrivateKey" in content
        assert "ListenPort" in content
        assert "[Peer]" in content

    def test_server_private_key_appears_in_output(self):
        """The server private key value is present in the rendered config."""
        builder = ConfigBuilder()
        priv_key = _valid_key()
        content = builder.render_server_config(
            server_private_key=priv_key,
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=[],
        )
        assert priv_key in content

    def test_listen_port_appears_in_output(self):
        """The listen port value is present in the rendered config."""
        builder = ConfigBuilder()
        content = builder.render_server_config(
            server_private_key=_valid_key(),
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=[],
        )
        assert "51820" in content

    def test_client_peer_block_appears_for_each_client(self):
        """Each client generates a [Peer] block in the server config."""
        builder = ConfigBuilder()
        clients = [
            {"name": "alice", "public_key": _valid_client_key(), "psk": _valid_psk(), "ip": "10.0.0.2"},
            {"name": "bob", "public_key": _valid_key(), "psk": _valid_psk(), "ip": "10.0.0.3"},
        ]
        content = builder.render_server_config(
            server_private_key=_valid_key(),
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=clients,
        )
        assert content.count("[Peer]") == 2

    def test_base64_keys_not_html_escaped(self):
        """autoescape=False must NOT convert base64 '=' to '&#61;' in output."""
        builder = ConfigBuilder()
        priv_key = _valid_key()  # Contains trailing '=' in base64
        assert "=" in priv_key  # Sanity check -- key has padding
        content = builder.render_server_config(
            server_private_key=priv_key,
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=[],
        )
        assert "&#61;" not in content, "autoescape corrupted base64 '=' characters"
        assert priv_key in content  # Full unescaped key must be present

    def test_missing_variable_raises_undefined_error(self):
        """Calling render_server_config triggers StrictUndefined.

        We test this by directly accessing the Jinja2 template with a missing
        variable rather than through render_server_config (which validates first).
        """
        builder = ConfigBuilder()
        template = builder.env.get_template("server.conf.j2")
        # Render with an incomplete context -- missing server_private_key etc.
        with pytest.raises(jinja2.UndefinedError):
            template.render(
                server_ip="10.0.0.1",
                prefix_length=24,
                server_port=51820,
                clients=[],
                post_up="",
                post_down="",
                # server_private_key intentionally omitted
            )

    def test_validation_rejects_invalid_port_before_render(self):
        """render_server_config with invalid port raises ValueError (no partial render)."""
        builder = ConfigBuilder()
        with pytest.raises(ValueError):
            builder.render_server_config(
                server_private_key=_valid_key(),
                server_ip="10.0.0.1",
                prefix_length=24,
                server_port=80,  # Below 1024 -- invalid
                clients=[],
            )

    def test_ini_injection_in_client_name_raises_before_render(self):
        """Client name with '[' raises ValueError via validation (not via template)."""
        builder = ConfigBuilder()
        bad_client = {
            "name": "bad[client",
            "public_key": _valid_client_key(),
            "psk": _valid_psk(),
            "ip": "10.0.0.2",
        }
        with pytest.raises(ValueError):
            builder.render_server_config(
                server_private_key=_valid_key(),
                server_ip="10.0.0.1",
                prefix_length=24,
                server_port=51820,
                clients=[bad_client],
            )


# ---------------------------------------------------------------------------
# Client config rendering tests
# ---------------------------------------------------------------------------

class TestClientConfigRendering:
    """Tests for ConfigBuilder.render_client_config()."""

    def test_client_config_contains_server_public_key(self):
        """Server public key must appear in the client config output."""
        builder = ConfigBuilder()
        server_pub_key = _valid_key()
        content = builder.render_client_config(
            client_private_key=_valid_client_key(),
            client_ip="10.0.0.2",
            dns_server="1.1.1.1",
            server_public_key=server_pub_key,
            psk=_valid_psk(),
            server_endpoint="203.0.113.1:51820",
        )
        assert server_pub_key in content

    def test_client_config_contains_interface_section(self):
        builder = ConfigBuilder()
        content = builder.render_client_config(
            client_private_key=_valid_client_key(),
            client_ip="10.0.0.2",
            dns_server="1.1.1.1",
            server_public_key=_valid_key(),
            psk=_valid_psk(),
            server_endpoint="203.0.113.1:51820",
        )
        assert "[Interface]" in content

    def test_client_config_contains_peer_section(self):
        builder = ConfigBuilder()
        content = builder.render_client_config(
            client_private_key=_valid_client_key(),
            client_ip="10.0.0.2",
            dns_server="1.1.1.1",
            server_public_key=_valid_key(),
            psk=_valid_psk(),
            server_endpoint="203.0.113.1:51820",
        )
        assert "[Peer]" in content

    def test_client_base64_keys_not_html_escaped(self):
        """autoescape=False: base64 '=' must NOT become '&#61;'."""
        builder = ConfigBuilder()
        client_key = _valid_client_key()  # Contains trailing '='
        assert "=" in client_key
        content = builder.render_client_config(
            client_private_key=client_key,
            client_ip="10.0.0.2",
            dns_server="1.1.1.1",
            server_public_key=_valid_key(),
            psk=_valid_psk(),
            server_endpoint="203.0.113.1:51820",
        )
        assert "&#61;" not in content
        assert client_key in content


# ---------------------------------------------------------------------------
# write_config and SHA-256 return value tests
# ---------------------------------------------------------------------------

class TestWriteConfigSha256:
    """Tests for ConfigBuilder.write_config() and SHA-256 return value."""

    def test_returns_sha256_of_rendered_config(self, tmp_path):
        """write_config returns SHA-256 hex digest matching hashlib computation."""
        builder = ConfigBuilder()
        content = builder.render_server_config(
            server_private_key=_valid_key(),
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=[],
        )
        dest = tmp_path / "wg0.conf"
        sha256_hex = builder.write_config(dest, content)

        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert sha256_hex == expected

    def test_write_config_creates_file(self, tmp_path):
        """write_config creates the config file at the given path."""
        builder = ConfigBuilder()
        content = builder.render_server_config(
            server_private_key=_valid_key(),
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=[],
        )
        dest = tmp_path / "wg0.conf"
        assert not dest.exists()
        builder.write_config(dest, content)
        assert dest.exists()

    def test_write_config_file_content_matches(self, tmp_path):
        """File written by write_config has the correct content."""
        builder = ConfigBuilder()
        content = builder.render_server_config(
            server_private_key=_valid_key(),
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=[],
        )
        dest = tmp_path / "wg0.conf"
        builder.write_config(dest, content)
        assert dest.read_text(encoding="utf-8") == content

    def test_sha256_return_is_64_char_hex(self, tmp_path):
        """write_config return value is a 64-character lowercase hex string."""
        builder = ConfigBuilder()
        content = builder.render_server_config(
            server_private_key=_valid_key(),
            server_ip="10.0.0.1",
            prefix_length=24,
            server_port=51820,
            clients=[],
        )
        dest = tmp_path / "wg0.conf"
        sha256_hex = builder.write_config(dest, content)
        assert len(sha256_hex) == 64
        assert sha256_hex == sha256_hex.lower()
        assert all(c in "0123456789abcdef" for c in sha256_hex)
