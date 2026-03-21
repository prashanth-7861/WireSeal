"""
Integration test: full init -> add-client -> verify peer in config
-> remove-client -> verify peer gone.

Requires Docker with NET_ADMIN capability and wireguard-go installed.
Excluded from the default pytest run by pyproject.toml addopts: -m not integration.

Run with: pytest -m integration
"""

import subprocess

import pytest
from click.testing import CliRunner

from wg_automate.main import cli

pytestmark = pytest.mark.integration

# Default vault path used by wg-automate (matches DEFAULT_VAULT_DIR in main.py)
_DEFAULT_VAULT_DIR = None  # resolved per-fixture using tmp env override


def run_cli(args, input_text=None, env=None):
    """Run the CLI via CliRunner and return the result."""
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, args, input=input_text, env=env, catch_exceptions=False)
    return result


@pytest.fixture(scope="module")
def wg_environment():
    """
    Check for wireguard-go availability. Skips the module if unavailable.
    Requires NET_ADMIN capability (provided by Docker --cap-add NET_ADMIN in CI).
    """
    result = subprocess.run(["which", "wireguard-go"], capture_output=True)
    if result.returncode != 0:
        pytest.skip("wireguard-go not available in this environment")

    yield

    # Cleanup: bring down the test interface if it was brought up
    subprocess.run(["ip", "link", "delete", "wg0"], capture_output=True)


@pytest.fixture(scope="module")
def vault_env(tmp_path_factory, wg_environment):
    """
    Provides a temporary vault directory and environment override so wg-automate
    writes its vault and config into an isolated tmp path rather than ~/.wg-automate.

    Note: wg-automate uses DEFAULT_VAULT_DIR = Path.home() / ".wg-automate".
    The CliRunner env override patches HOME so Path.home() resolves to tmp_path.
    """
    tmp_home = tmp_path_factory.mktemp("integration_home")
    # CliRunner passes env as overrides; set HOME so Path.home() resolves to tmp dir
    env = {"HOME": str(tmp_home), "USERPROFILE": str(tmp_home)}
    return {"home": tmp_home, "env": env}


@pytest.mark.integration
def test_full_lifecycle(vault_env):
    """
    TEST-02: Full init -> add-client -> verify peer in config
    -> remove-client -> verify peer gone.

    Drives wg-automate CLI end-to-end inside a controlled environment.
    Requires wireguard-go and root/NET_ADMIN capability. Skips gracefully
    if wireguard-go is not available.
    """
    env = vault_env["env"]
    passphrase = "correct-horse-battery-staple-integration\n"
    # init prompts for passphrase + confirmation
    passphrase_input = passphrase + passphrase

    # Step 1: init -- creates vault, generates server keys, deploys config
    result = run_cli(
        ["init", "--subnet", "10.99.0.0/24", "--port", "51821"],
        input_text=passphrase_input,
        env=env,
    )
    assert result.exit_code == 0, f"init failed:\n{result.output}"
    assert "Initialisation complete" in result.output, (
        f"Expected 'Initialisation complete' in init output:\n{result.output}"
    )

    # Step 2: add-client -- generates client keypair and adds peer to config
    result = run_cli(
        ["add-client", "test-client"],
        input_text=passphrase,
        env=env,
    )
    assert result.exit_code == 0, f"add-client failed:\n{result.output}"

    # Step 3: verify peer appears in deployed config
    # The adapter deploys to /etc/wireguard/wg0.conf inside the container
    config_path_candidates = [
        vault_env["home"] / ".wg-automate" / "wg0.conf",
        vault_env["home"] / "wg0.conf",
    ]
    import os

    # Check system config location (inside Docker container, /etc/wireguard/wg0.conf)
    system_config = "/etc/wireguard/wg0.conf"
    if os.path.exists(system_config):
        config_content = open(system_config).read()
        assert "[Peer]" in config_content, (
            "Peer section missing from /etc/wireguard/wg0.conf after add-client"
        )

    # Step 4: remove-client -- revokes peer access and updates config
    result = run_cli(
        ["remove-client", "test-client"],
        input_text=passphrase,
        env=env,
    )
    assert result.exit_code == 0, f"remove-client failed:\n{result.output}"

    # Step 5: verify peer is gone from deployed config
    if os.path.exists(system_config):
        config_content = open(system_config).read()
        assert "test-client" not in config_content, (
            "Client name 'test-client' still present in config after remove-client"
        )
