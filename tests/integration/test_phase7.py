"""Integration tests for Phase 7 ZTNA Foundation features."""
import os
import pytest
from pathlib import Path
from wireseal.security.keyslot import _DEV_FAST_PARAMS
from wireseal.security.vault import Vault
from wireseal.security.exceptions import (
    AdminRoleError, KeyslotNotFoundError, VaultUnlockError,
)


@pytest.fixture
def owner_pass():
    return bytearray(b"integration-test-pass")


@pytest.fixture
def tmp_vault(tmp_path, owner_pass):
    vault_path = tmp_path / "test_vault.enc"
    Vault.create(vault_path, owner_pass)
    return vault_path


class TestMultiAdmin:
    def test_add_admin_and_unlock(self, tmp_vault, owner_pass):
        vault_path = tmp_vault
        alice_pass = bytearray(b"alice-secure-pass")

        # Add admin keyslot (upgrades v2 -> v3)
        vault = Vault(vault_path)
        with vault.open(owner_pass) as state:
            state.vault.add_keyslot("alice", alice_pass, role="admin",
                                    keyslot_params=_DEV_FAST_PARAMS)
            state.data["server"] = {"test": True}
        # Context-manager exit auto-saves v3 vault

        # Unlock as alice
        vault2 = Vault(vault_path)
        with vault2.open(alice_pass, admin_id="alice") as state:
            assert state.data["server"]["test"] is True
            slots = state.vault.list_keyslots()
            assert len(slots) == 2

    def test_cannot_remove_last_owner(self, tmp_vault, owner_pass):
        vault_path = tmp_vault
        # First upgrade to v3 by adding an admin, then try to remove last owner
        alice_pass = bytearray(b"alice-secure-pass-2")
        vault = Vault(vault_path)
        with vault.open(owner_pass) as state:
            state.vault.add_keyslot("alice", alice_pass, role="admin",
                                    keyslot_params=_DEV_FAST_PARAMS)

        vault2 = Vault(vault_path)
        with vault2.open(owner_pass) as state:
            with pytest.raises(AdminRoleError):
                state.vault.remove_keyslot("owner")

    def test_remove_non_owner_admin(self, tmp_vault, owner_pass):
        vault_path = tmp_vault
        bob_pass = bytearray(b"bob-secure-pass-123")

        # Add bob
        vault = Vault(vault_path)
        with vault.open(owner_pass) as state:
            state.vault.add_keyslot("bob", bob_pass, role="admin",
                                    keyslot_params=_DEV_FAST_PARAMS)

        # Remove bob
        vault2 = Vault(vault_path)
        with vault2.open(owner_pass) as state:
            state.vault.remove_keyslot("bob")

        # Bob can no longer unlock
        vault3 = Vault(vault_path)
        with pytest.raises((KeyslotNotFoundError, VaultUnlockError)):
            with vault3.open(bob_pass, admin_id="bob"):
                pass


class TestDnsMappings:
    def test_add_and_retrieve_dns_mapping(self, tmp_vault, owner_pass):
        vault_path = tmp_vault
        vault = Vault(vault_path)
        with vault.open(owner_pass) as state:
            state.data.setdefault("dns_mappings", {})["plex.home"] = "10.0.0.10"
            vault.save(state, owner_pass)

        vault2 = Vault(vault_path)
        with vault2.open(owner_pass) as state:
            assert state.data["dns_mappings"]["plex.home"] == "10.0.0.10"

    def test_remove_dns_mapping(self, tmp_vault, owner_pass):
        vault_path = tmp_vault
        vault = Vault(vault_path)
        with vault.open(owner_pass) as state:
            state.data.setdefault("dns_mappings", {})["app.home"] = "10.0.0.20"
            vault.save(state, owner_pass)

        vault2 = Vault(vault_path)
        with vault2.open(owner_pass) as state:
            del state.data["dns_mappings"]["app.home"]
            vault2.save(state, owner_pass)

        vault3 = Vault(vault_path)
        with vault3.open(owner_pass) as state:
            assert "app.home" not in state.data.get("dns_mappings", {})


class TestBackupRestore:
    def test_backup_and_restore_cycle(self, tmp_vault, tmp_path, owner_pass):
        vault_path = tmp_vault
        # Write some data
        vault = Vault(vault_path)
        with vault.open(owner_pass) as state:
            state.data["server"] = {"endpoint": "test.example.com"}
            vault.save(state, owner_pass)

        from wireseal.backup.manager import BackupManager
        mgr = BackupManager()
        backup_dir = tmp_path / "backups"
        config = {"destination": "local", "local_path": str(backup_dir)}

        entry = mgr.create_backup(vault_path, config)
        assert Path(entry.path).exists()

        # Corrupt the vault
        vault_path.write_bytes(b"CORRUPTED")

        # Restore
        mgr.restore_backup(entry.path, vault_path, owner_pass)

        # Verify restored vault decrypts
        vault2 = Vault(vault_path)
        with vault2.open(owner_pass) as state:
            assert state.data["server"]["endpoint"] == "test.example.com"

    def test_restore_wrong_passphrase_rejected(self, tmp_vault, tmp_path, owner_pass):
        vault_path = tmp_vault
        from wireseal.backup.manager import BackupManager
        mgr = BackupManager()
        backup_dir = tmp_path / "backups2"
        entry = mgr.create_backup(vault_path, {"destination": "local", "local_path": str(backup_dir)})
        with pytest.raises(VaultUnlockError):
            mgr.restore_backup(entry.path, vault_path, bytearray(b"wrong-pass"))
