"""Tests for `wireseal backup-vault` / `wireseal restore-vault` (Hardening Phase 3).

Covers:
- backup-vault refuses when no vault exists
- backup-vault rejects wrong passphrase
- backup-vault produces a byte-identical copy on success
- restore-vault rejects wrong passphrase
- restore-vault round-trip: backup → corrupt original → restore → unlock succeeds
- restore-vault prompts before overwriting an existing vault
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from wireseal.main import cli
from wireseal.security import vault as vault_mod
from wireseal.security.secret_types import SecretBytes
from wireseal.security.vault import Vault


# ---------------------------------------------------------------------------
# Fixtures — an isolated DEFAULT_VAULT_DIR for every test
# ---------------------------------------------------------------------------


PASSPHRASE = "correct-horse-battery-staple"
WRONG_PP = "nope-nope-nope-nope-nope"


@pytest.fixture()
def vault_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point DEFAULT_VAULT_DIR at a temp location for the CLI commands."""
    tmp_vault_dir = tmp_path / "wireseal"
    tmp_vault_dir.mkdir()
    monkeypatch.setattr(vault_mod, "DEFAULT_VAULT_DIR", tmp_vault_dir)
    return tmp_vault_dir


@pytest.fixture()
def real_vault(vault_dir: Path) -> Path:
    """Create a real encrypted vault at DEFAULT_VAULT_DIR/vault.enc."""
    vault_path = vault_dir / "vault.enc"
    pp = SecretBytes(bytearray(PASSPHRASE.encode()))
    state = {
        "schema_version": 1,
        "server": {},
        "clients": {},
        "ip_pool": {},
        "integrity": {},
    }
    Vault.create(vault_path, pp, state)
    return vault_path


# ---------------------------------------------------------------------------
# backup-vault
# ---------------------------------------------------------------------------


def test_backup_vault_errors_when_no_vault(vault_dir: Path, tmp_path: Path) -> None:
    """backup-vault must refuse if the source vault does not exist."""
    runner = CliRunner()
    dest = tmp_path / "backup.enc"
    result = runner.invoke(cli, ["backup-vault", str(dest)], input=f"{PASSPHRASE}\n")
    assert result.exit_code != 0
    assert "No vault found" in result.output
    assert not dest.exists()


def test_backup_vault_rejects_wrong_passphrase(
    real_vault: Path, tmp_path: Path
) -> None:
    """Wrong passphrase should abort the backup with a clear error."""
    runner = CliRunner()
    dest = tmp_path / "backup.enc"
    result = runner.invoke(cli, ["backup-vault", str(dest)], input=f"{WRONG_PP}\n")
    assert result.exit_code != 0
    assert "Incorrect passphrase" in result.output
    assert not dest.exists()


def test_backup_vault_copies_bytes_exactly(
    real_vault: Path, tmp_path: Path
) -> None:
    """On success, the backup must be byte-identical to the source."""
    runner = CliRunner()
    dest = tmp_path / "backup.enc"
    result = runner.invoke(cli, ["backup-vault", str(dest)], input=f"{PASSPHRASE}\n")
    assert result.exit_code == 0, result.output
    assert dest.exists()
    assert dest.read_bytes() == real_vault.read_bytes()


# ---------------------------------------------------------------------------
# restore-vault
# ---------------------------------------------------------------------------


def test_restore_rejects_wrong_passphrase(
    real_vault: Path, tmp_path: Path
) -> None:
    """Restore must verify the backup decrypts before touching the live vault."""
    # Make a backup first
    runner = CliRunner()
    backup = tmp_path / "backup.enc"
    res1 = runner.invoke(cli, ["backup-vault", str(backup)], input=f"{PASSPHRASE}\n")
    assert res1.exit_code == 0

    # Try to restore with the wrong passphrase
    original_bytes = real_vault.read_bytes()
    res2 = runner.invoke(cli, ["restore-vault", str(backup)], input=f"{WRONG_PP}\n")
    assert res2.exit_code != 0
    assert "Incorrect passphrase" in res2.output
    # Live vault must be untouched
    assert real_vault.read_bytes() == original_bytes


def test_restore_round_trip_recovers_deleted_vault(
    real_vault: Path, tmp_path: Path, vault_dir: Path
) -> None:
    """Full scenario: backup → delete live vault → restore → unlock succeeds."""
    runner = CliRunner()
    backup = tmp_path / "backup.enc"

    # 1) Back up
    res1 = runner.invoke(cli, ["backup-vault", str(backup)], input=f"{PASSPHRASE}\n")
    assert res1.exit_code == 0

    # 2) Simulate disaster: delete the live vault
    real_vault.unlink()
    assert not real_vault.exists()

    # 3) Restore (no overwrite prompt needed since live vault is gone)
    res2 = runner.invoke(cli, ["restore-vault", str(backup)], input=f"{PASSPHRASE}\n")
    assert res2.exit_code == 0, res2.output
    assert "restored" in res2.output.lower()
    assert real_vault.exists()

    # 4) Unlock the restored vault directly to confirm it works
    pp = SecretBytes(bytearray(PASSPHRASE.encode()))
    vault = Vault(real_vault)
    with vault.open(pp) as state:
        assert state._data["schema_version"] == 1


def test_restore_prompts_before_overwrite(
    real_vault: Path, tmp_path: Path
) -> None:
    """If a live vault exists, restore must prompt before overwriting."""
    runner = CliRunner()
    backup = tmp_path / "backup.enc"
    runner.invoke(cli, ["backup-vault", str(backup)], input=f"{PASSPHRASE}\n")

    original_bytes = real_vault.read_bytes()

    # Decline the overwrite prompt
    result = runner.invoke(
        cli,
        ["restore-vault", str(backup)],
        input=f"{PASSPHRASE}\nn\n",  # passphrase, then "no" to confirm
    )
    assert result.exit_code == 0
    assert "Aborted" in result.output
    # Live vault must be untouched when user says no
    assert real_vault.read_bytes() == original_bytes
