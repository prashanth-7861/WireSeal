"""Shared pytest fixtures for wg-automate unit tests.

All fixtures use function scope (default) to prevent state leaking between tests.
No passphrases are sourced from os.environ -- they are constructed directly
as SecretBytes to avoid credential exposure via environment variables.
"""

import sys
import pytest

from wg_automate.security.secret_types import SecretBytes


@pytest.fixture()
def vault_path(tmp_path):
    """Return a fresh vault path inside a per-test temp directory.

    Each test gets an isolated path -- never reused across tests (prevents
    state leakage, Research Pitfall 3). The file does not exist yet; callers
    create it via Vault.create().
    """
    return tmp_path / "vault.enc"


@pytest.fixture()
def passphrase():
    """Return a valid passphrase as SecretBytes.

    Never sourced from os.environ -- see Research anti-patterns.
    Length >= 12 to satisfy VAULT-03 minimum passphrase length.
    """
    return SecretBytes(bytearray(b"correct-horse-battery-staple"))


@pytest.fixture()
def wrong_passphrase():
    """Return a different, wrong passphrase as SecretBytes."""
    return SecretBytes(bytearray(b"wrong-passphrase-12345"))


@pytest.fixture()
def initial_vault_state():
    """Return the canonical minimal vault state dict.

    Matches the schema used by Vault.create() and VaultState.__init__().
    """
    return {
        "schema_version": 1,
        "server": {},
        "clients": {},
        "ip_pool": {},
        "integrity": {},
    }


@pytest.fixture()
def mock_platform(mocker):
    """Patch sys.platform to 'linux' so permission tests exercise the Unix code path."""
    mocker.patch.object(sys, "platform", "linux")
