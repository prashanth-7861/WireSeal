"""Regression tests for the MEDIUM / LOW severity security fixes.

Each test is tagged with the SEC-xxx id it exercises so failures point
straight back at the audit finding. These are pure-unit tests — they do
not require a running HTTP server or a real vault unless otherwise noted.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

from wireseal.security import vault as vault_mod
from wireseal.security.audit import AuditLog, _AUDIT_GENESIS_HASH
from wireseal.security.secret_types import SecretBytes
from wireseal.security.secrets_wipe import wipe_string
from wireseal.backup.manager import BackupManager, _reject_system_destination
from wireseal.ssh.session_manager import SshSessionManager, SshTicket


# --------------------------------------------------------------------------- #
# SEC-011: wipe_string refuses unsafe inputs                                  #
# --------------------------------------------------------------------------- #


class TestWipeStringSafety:
    def test_empty_string_refused(self):
        assert wipe_string("") is False

    def test_non_ascii_refused(self):
        # Non-ASCII uses a different CPython layout — memset would corrupt heap.
        assert wipe_string("caf\u00e9-password") is False

    def test_short_identifier_refused(self):
        # Likely interned; writing to the buffer would corrupt the interpreter.
        assert wipe_string("hello") is False
        assert wipe_string("abc") is False

    def test_very_short_refused(self):
        # All strings shorter than 8 chars are refused unconditionally.
        assert wipe_string("xy") is False
        assert wipe_string("1234567") is False


# --------------------------------------------------------------------------- #
# SEC-012: SecretBytes refuses implicit coercion to bytes()                   #
# --------------------------------------------------------------------------- #


class TestSecretBytesCoercion:
    def test_bytes_coercion_raises(self):
        sb = SecretBytes(bytearray(b"super-secret-passphrase"))
        try:
            with pytest.raises(TypeError, match="expose_secret"):
                bytes(sb)
        finally:
            sb.wipe()

    def test_expose_secret_still_works(self):
        sb = SecretBytes(bytearray(b"super-secret-passphrase"))
        try:
            # The sanctioned accessor still returns the buffer.
            buf = sb.expose_secret()
            assert bytes(buf) == b"super-secret-passphrase"
        finally:
            sb.wipe()

    def test_to_bytearray_still_works(self):
        sb = SecretBytes(bytearray(b"super-secret-passphrase"))
        try:
            copy = sb.to_bytearray()
            assert copy == bytearray(b"super-secret-passphrase")
            assert copy is not sb.expose_secret()
        finally:
            sb.wipe()


# --------------------------------------------------------------------------- #
# SEC-017: *_pass fields are wrapped in SecretBytes                           #
# --------------------------------------------------------------------------- #


class TestWebdavPassWrapping:
    def test_webdav_pass_wrapped(self):
        wrapped = vault_mod.VaultState._wrap_secrets(
            {
                "destination": "webdav",
                "webdav_url": "https://example.com/vault",
                "webdav_user": "alice",
                "webdav_pass": "correct horse battery staple",
            }
        )
        assert isinstance(wrapped["webdav_pass"], SecretBytes)
        # Non-secret fields unchanged
        assert wrapped["destination"] == "webdav"
        assert wrapped["webdav_user"] == "alice"
        # Round-trip: _unwrap_secrets restores the plaintext
        unwrapped = vault_mod.VaultState._unwrap_secrets(wrapped)
        assert unwrapped["webdav_pass"] == "correct horse battery staple"
        # Clean up
        wrapped["webdav_pass"].wipe()

    def test_generic_password_fields_wrapped(self):
        wrapped = vault_mod.VaultState._wrap_secrets(
            {"some_password": "hunter2", "public_value": "visible"}
        )
        assert isinstance(wrapped["some_password"], SecretBytes)
        assert wrapped["public_value"] == "visible"
        wrapped["some_password"].wipe()


# --------------------------------------------------------------------------- #
# SEC-019: Argon2 header params rejected if out of range                      #
# --------------------------------------------------------------------------- #


class TestArgon2ParamValidation:
    def test_default_params_accepted(self):
        # Must not raise — the default header from a fresh vault is valid.
        vault_mod._validate_argon2_params(
            vault_mod.ARGON2_MEMORY_COST_KIB,
            vault_mod.ARGON2_TIME_COST,
            vault_mod.ARGON2_PARALLELISM,
        )

    def test_weak_memory_rejected(self):
        # An attacker weakening the vault by editing the header
        with pytest.raises(vault_mod.VaultTamperedError, match="memory_cost"):
            vault_mod._validate_argon2_params(100, 13, 4)

    def test_gigantic_memory_rejected(self):
        # DoS via absurd RAM allocation claim
        with pytest.raises(vault_mod.VaultTamperedError, match="memory_cost"):
            vault_mod._validate_argon2_params(10 * 1024 * 1024, 13, 4)

    def test_time_cost_rejected(self):
        with pytest.raises(vault_mod.VaultTamperedError, match="time_cost"):
            vault_mod._validate_argon2_params(262144, 1, 4)
        with pytest.raises(vault_mod.VaultTamperedError, match="time_cost"):
            vault_mod._validate_argon2_params(262144, 999, 4)

    def test_parallelism_rejected(self):
        with pytest.raises(vault_mod.VaultTamperedError, match="parallelism"):
            vault_mod._validate_argon2_params(262144, 13, 0)
        with pytest.raises(vault_mod.VaultTamperedError, match="parallelism"):
            vault_mod._validate_argon2_params(262144, 13, 100)


# --------------------------------------------------------------------------- #
# SEC-021: SshTicket.password stored as SecretBytes                           #
# --------------------------------------------------------------------------- #


class TestSshTicketPasswordWrapping:
    def test_issued_ticket_wraps_password(self):
        mgr = SshSessionManager()
        token = mgr.issue_ticket(
            host="10.0.0.2",
            port=22,
            username="alice",
            password="rotate-me-please",
            profile_name="profile-a",
            actor_id="owner",
        )
        ticket = mgr.consume_ticket(token)
        assert ticket is not None
        assert isinstance(ticket.password, SecretBytes)
        # Contents preserved
        assert bytes(ticket.password.expose_secret()) == b"rotate-me-please"
        ticket.wipe()
        assert ticket.password.is_wiped

    def test_ticket_with_no_password_is_none(self):
        mgr = SshSessionManager()
        token = mgr.issue_ticket(
            host="10.0.0.2",
            port=22,
            username="alice",
            password=None,
            profile_name="profile-a",
            actor_id="owner",
        )
        ticket = mgr.consume_ticket(token)
        assert ticket is not None
        assert ticket.password is None
        ticket.wipe()  # must not raise


# --------------------------------------------------------------------------- #
# SEC-025: audit log hash chain                                               #
# --------------------------------------------------------------------------- #


class TestAuditLogChain:
    def test_first_entry_anchors_to_genesis(self, tmp_path):
        log = AuditLog(tmp_path / "audit.log")
        entry = log.log("first-action", {"k": "v"})
        assert entry.prev_hash == _AUDIT_GENESIS_HASH
        assert entry.chain_hash is not None
        assert len(entry.chain_hash) == 64  # sha256 hex

    def test_chain_links_consecutive_entries(self, tmp_path):
        log = AuditLog(tmp_path / "audit.log")
        e1 = log.log("a1", {})
        e2 = log.log("a2", {})
        e3 = log.log("a3", {})
        assert e2.prev_hash == e1.chain_hash
        assert e3.prev_hash == e2.chain_hash

    def test_verify_chain_passes_on_clean_log(self, tmp_path):
        log = AuditLog(tmp_path / "audit.log")
        for i in range(10):
            log.log(f"action-{i}", {"seq": i})
        ok, count, err = log.verify_chain()
        assert ok is True
        assert count == 10
        assert err is None

    def test_verify_chain_detects_tampered_entry(self, tmp_path):
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        log.log("a1", {"v": 1})
        log.log("a2", {"v": 2})
        log.log("a3", {"v": 3})
        # Tamper: flip a metadata value in the middle entry
        lines = log_path.read_text(encoding="utf-8").splitlines()
        middle = json.loads(lines[1])
        middle["metadata"]["v"] = 999
        lines[1] = json.dumps(middle)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, _, err = log.verify_chain()
        assert ok is False
        assert err is not None
        assert "chain_hash mismatch" in err or "prev_hash mismatch" in err

    def test_verify_chain_detects_truncation(self, tmp_path):
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        log.log("a1", {})
        log.log("a2", {})
        log.log("a3", {})
        # Delete the first entry (classic truncation attack)
        lines = log_path.read_text(encoding="utf-8").splitlines()
        log_path.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
        ok, _, err = log.verify_chain()
        assert ok is False
        assert err is not None
        assert "prev_hash mismatch" in err


# --------------------------------------------------------------------------- #
# SEC-027: backup destination blocklist                                       #
# --------------------------------------------------------------------------- #


class TestBackupDestinationBlocklist:
    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only system paths")
    def test_unix_system_dirs_rejected(self):
        for sys_dir in ("/etc", "/etc/foo", "/bin/x", "/usr/lib/y", "/boot/grub"):
            with pytest.raises(ValueError, match="system directory"):
                _reject_system_destination(Path(sys_dir))

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only system paths")
    def test_windows_system_dirs_rejected(self):
        for sys_dir in (
            r"C:\Windows",
            r"C:\Windows\System32",
            r"C:\Program Files\foo",
        ):
            with pytest.raises(ValueError, match="system directory"):
                _reject_system_destination(Path(sys_dir))

    def test_user_dir_accepted(self, tmp_path):
        # Must not raise for a normal user-owned path
        _reject_system_destination(tmp_path / "backups")

    def test_create_backup_refuses_system_dir(self, tmp_path):
        mgr = BackupManager()
        vault_file = tmp_path / "vault.enc"
        vault_file.write_bytes(b"ciphertext-placeholder")
        bad_dest = "/etc/wireseal-backups" if sys.platform != "win32" else r"C:\Windows\backups"
        with pytest.raises(ValueError, match="system directory"):
            mgr.create_backup(vault_file, {"destination": "local", "local_path": bad_dest})
