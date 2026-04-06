"""Encrypted vault backup manager for WireSeal.

Supports three destination types:
  - local: shutil.copy2 to a local path
  - ssh:   rsync over SSH (subprocess, rsync must be installed)
  - webdav: HTTP PUT to a WebDAV endpoint (urllib.request, self-hosted only)

Key safety invariant: restore_backup verifies the backup is decryptable in
memory BEFORE replacing the live vault. A failed or wrong-passphrase restore
never touches the live vault file.
"""
from __future__ import annotations

import shutil
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class BackupEntry:
    path: str
    created_at: float       # Unix timestamp
    size_bytes: int


def backup_filename(vault_path: Path) -> str:
    """Return a timestamped backup filename: vault_YYYYMMDD_HHMMSS.enc"""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = vault_path.stem  # e.g. "vault"
    return f"{stem}_{ts}.enc"


class BackupManager:
    """Create, list, restore, and prune vault backups."""

    # ------------------------------------------------------------------ #
    # Create                                                               #
    # ------------------------------------------------------------------ #

    def create_backup(self, vault_path: Path, dest_config: dict) -> BackupEntry:
        """Copy the vault file to the configured destination.

        Args:
            vault_path:  Path to the live vault file.
            dest_config: dict from state.data["backup_config"].

        Returns:
            BackupEntry with path, created_at, size_bytes.

        Raises:
            ValueError  if dest_config is missing required fields.
            RuntimeError on copy failure.
        """
        dest_type = dest_config.get("destination", "local")
        fname = backup_filename(vault_path)

        if dest_type == "local":
            return self._create_local(vault_path, dest_config, fname)
        elif dest_type == "ssh":
            return self._create_ssh(vault_path, dest_config, fname)
        elif dest_type == "webdav":
            return self._create_webdav(vault_path, dest_config, fname)
        else:
            raise ValueError(f"Unknown destination type: {dest_type!r}")

    def _create_local(self, vault_path: Path, cfg: dict, fname: str) -> BackupEntry:
        local_path = cfg.get("local_path")
        if not local_path:
            raise ValueError("backup_config.local_path is required for local destination")
        dest_dir = Path(local_path)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / fname
        shutil.copy2(vault_path, dest_file)
        stat = dest_file.stat()
        return BackupEntry(
            path=str(dest_file),
            created_at=stat.st_mtime,
            size_bytes=stat.st_size,
        )

    def _create_ssh(self, vault_path: Path, cfg: dict, fname: str) -> BackupEntry:
        host = cfg.get("ssh_host")
        user = cfg.get("ssh_user")
        remote_path = cfg.get("ssh_path")
        if not host or not remote_path:
            raise ValueError("backup_config.ssh_host and ssh_path required for SSH destination")
        target = f"{user}@{host}:{remote_path}/{fname}" if user else f"{host}:{remote_path}/{fname}"
        result = subprocess.run(
            ["rsync", "-az", str(vault_path), target],
            capture_output=True, timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"rsync failed: {result.stderr.decode(errors='replace')}")
        size = vault_path.stat().st_size
        import time
        return BackupEntry(path=target, created_at=time.time(), size_bytes=size)

    def _create_webdav(self, vault_path: Path, cfg: dict, fname: str) -> BackupEntry:
        webdav_url = cfg.get("webdav_url")
        if not webdav_url:
            raise ValueError("backup_config.webdav_url required for WebDAV destination")
        webdav_user = cfg.get("webdav_user", "")
        webdav_pass = cfg.get("webdav_pass", "")
        url = webdav_url.rstrip("/") + "/" + urllib.parse.quote(fname)
        data = vault_path.read_bytes()
        req = urllib.request.Request(url, data=data, method="PUT")
        req.add_header("Content-Type", "application/octet-stream")
        if webdav_user:
            import base64
            creds = base64.b64encode(f"{webdav_user}:{webdav_pass}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
        try:
            urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"WebDAV PUT failed: HTTP {exc.code}") from exc
        import time
        return BackupEntry(path=url, created_at=time.time(), size_bytes=len(data))

    # ------------------------------------------------------------------ #
    # Restore — two-phase safety                                          #
    # ------------------------------------------------------------------ #

    def restore_backup(
        self,
        src_path: str,
        vault_path: Path,
        passphrase: bytearray,
        admin_id: str = "owner",
    ) -> None:
        """Restore a backup vault file.

        Phase 1: Attempt to open the backup with the supplied passphrase in
                 memory. Raises VaultUnlockError if decryption fails.
        Phase 2: Only on success, atomically replace the live vault file.

        Args:
            src_path:   Local filesystem path to the backup file.
            vault_path: Path to the live vault to replace.
            passphrase: Caller's passphrase (verified against backup, not live vault).
            admin_id:   Admin slot to try (default "owner").

        Raises:
            FileNotFoundError  if src_path does not exist.
            VaultUnlockError   if passphrase cannot decrypt the backup (live vault unchanged).
            RuntimeError       on unexpected I/O error during replace.
        """
        from wireseal.security.vault import Vault
        backup_vault_path = Path(src_path)
        if not backup_vault_path.exists():
            raise FileNotFoundError(f"Backup file not found: {src_path}")

        # Phase 1: verify decryptable (raises if wrong passphrase)
        test_vault = Vault(backup_vault_path)
        with test_vault.open(passphrase, admin_id=admin_id):
            pass  # success = decryptable

        # Phase 2: atomic replace of live vault
        import os
        tmp = vault_path.with_suffix(".restore_tmp")
        shutil.copy2(backup_vault_path, tmp)
        os.replace(tmp, vault_path)

    # ------------------------------------------------------------------ #
    # List                                                                 #
    # ------------------------------------------------------------------ #

    def list_backups(self, dest_config: dict) -> list[BackupEntry]:
        """List existing backups at the configured destination, newest first.

        Only supports local destination for listing (SSH/WebDAV have no
        standardised directory listing; local is the canonical use case).
        """
        dest_type = dest_config.get("destination", "local")
        if dest_type != "local":
            return []  # SSH/WebDAV listing not supported
        local_path = dest_config.get("local_path")
        if not local_path:
            return []
        dest_dir = Path(local_path)
        if not dest_dir.exists():
            return []
        entries = []
        for f in dest_dir.glob("vault_*.enc"):
            stat = f.stat()
            entries.append(BackupEntry(
                path=str(f),
                created_at=stat.st_mtime,
                size_bytes=stat.st_size,
            ))
        entries.sort(key=lambda e: e.created_at, reverse=True)
        return entries

    # ------------------------------------------------------------------ #
    # Prune                                                                #
    # ------------------------------------------------------------------ #

    def prune_old(self, dest_config: dict, keep_n: int) -> int:
        """Delete oldest backups beyond keep_n. Returns count deleted.

        Only operates on local destinations.
        """
        entries = self.list_backups(dest_config)
        to_delete = entries[keep_n:]
        deleted = 0
        for entry in to_delete:
            try:
                Path(entry.path).unlink()
                deleted += 1
            except OSError:
                pass
        return deleted
