---
phase: "07"
plan: "06"
subsystem: backup
tags: [backup, restore, vault, two-phase-restore, local, ssh, webdav, cli, dashboard]
dependency_graph:
  requires: ["07-01"]
  provides: ["encrypted-local-backup", "backup-api", "backup-cli", "backup-dashboard"]
  affects: ["api.py", "main.py", "Dashboard"]
tech_stack:
  added: []
  patterns:
    - "Two-phase restore: decrypt backup in memory before replacing live vault"
    - "shutil.copy2 for local atomic file copy"
    - "os.replace for atomic vault swap after restore"
    - "BackupManager singleton at module level (stateless, thread-safe)"
key_files:
  created:
    - src/wireseal/backup/__init__.py
    - src/wireseal/backup/manager.py
    - Dashboard/src/app/pages/Backup.tsx
  modified:
    - src/wireseal/api.py
    - src/wireseal/main.py
    - Dashboard/src/app/api.ts
    - Dashboard/src/app/routes.tsx
    - Dashboard/src/app/components/Layout.tsx
decisions:
  - "BackupManager instantiated as module-level singleton (_backup_manager) — stateless class, safe to share across requests"
  - "webdav_pass excluded from GET /api/backup/config response to avoid credential exposure"
  - "restore_backup uses os.replace (atomic on POSIX) via tmp file to avoid partial-write corruption"
  - "Backup nav icon: HardDrive from lucide-react (semantic match for storage)"
  - "list_backups returns empty list for SSH/WebDAV — no standard directory listing protocol"
metrics:
  duration: "~20 minutes"
  completed: "2026-04-06"
  tasks_completed: 3
  files_modified: 7
  files_created: 3
---

# Phase 07 Plan 06: Encrypted Local Backup Summary

**One-liner:** Vault backup and restore via BackupManager (local/SSH/WebDAV), five REST endpoints, two CLI commands, and a Dashboard Backup page with config form, trigger button, backup list table, and two-phase restore modal.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Create backup package | de57019 | src/wireseal/backup/__init__.py, src/wireseal/backup/manager.py |
| 2 | backup API handlers in api.py | 158026e | src/wireseal/api.py |
| 3 | CLI commands, Dashboard Backup page | 0f6ef0b | main.py, api.ts, Backup.tsx, routes.tsx, Layout.tsx |

## What Was Built

### BackupManager (src/wireseal/backup/manager.py)

- `BackupEntry` dataclass: `path`, `created_at` (Unix timestamp), `size_bytes`
- `backup_filename(vault_path)`: generates `vault_YYYYMMDD_HHMMSS.enc` using UTC timestamp
- `create_backup(vault_path, dest_config)`: dispatches to `_create_local` (shutil.copy2), `_create_ssh` (rsync subprocess), or `_create_webdav` (urllib.request PUT)
- `restore_backup(src_path, vault_path, passphrase, admin_id)`: Phase 1 — open backup with `Vault.open()` to verify decryptability; Phase 2 — `shutil.copy2` to tmp + `os.replace` for atomic swap. Live vault never touched on Phase 1 failure.
- `list_backups(dest_config)`: globs `vault_*.enc` in local_path, sorts newest-first
- `prune_old(dest_config, keep_n)`: deletes entries beyond keep_n position; returns deleted count

### API Endpoints (src/wireseal/api.py)

Five new handlers registered under `/api/backup/*`:

| Method | Path | Handler | Notes |
|--------|------|---------|-------|
| GET | /api/backup/config | `_h_backup_config_get` | Returns config excluding webdav_pass |
| POST | /api/backup/config | `_h_backup_config_set` | Persists allowed keys to vault state |
| POST | /api/backup/trigger | `_h_backup_trigger` | Creates backup, prunes, updates last_backup_at |
| GET | /api/backup/list | `_h_backup_list` | Lists backups via BackupManager |
| POST | /api/backup/restore | `_h_backup_restore` | Two-phase restore; 401 on wrong passphrase; wipes session after success |

`_refresh_cache` updated to include `backup_config` key from vault state.

### CLI Commands (src/wireseal/main.py)

- `wireseal backup [--dest PATH]`: prompts passphrase (hide_input), reads backup_config from vault, calls BackupManager.create_backup
- `wireseal restore SRC`: prompts passphrase (hide_input), confirms destructive action, calls BackupManager.restore_backup

### Dashboard (Dashboard/src/app/)

- `api.ts`: `BackupConfig` and `BackupEntry` interfaces; five API methods: `getBackupConfig`, `setBackupConfig`, `triggerBackup`, `listBackups`, `restoreBackup`
- `pages/Backup.tsx`: Config form with destination-type switching (local/SSH/WebDAV conditional fields), enabled toggle, keep_n input; trigger button with success/error feedback; backup list table (path, created date, size, Restore button); restore modal with passphrase input and confirm button
- `routes.tsx`: `/backup` route added
- `Layout.tsx`: "Backup" nav link with `HardDrive` icon

## Verification Results

- Python syntax check: PASSED (py_compile on all three Python files)
- Symbol check: PASSED (all required exports present)
- Vite build: PASSED (1622 modules, no errors, built in 5.31s)
- pytest tests/security/: PASSED (58 passed)

## Deviations from Plan

None — plan executed exactly as specified. The handler signatures follow the existing `(req, _groups)` functional pattern already established by the DNS handlers, matching the routing table dispatch mechanism.

## Self-Check: PASSED

Files confirmed on disk:
- src/wireseal/backup/__init__.py: exists
- src/wireseal/backup/manager.py: exists
- Dashboard/src/app/pages/Backup.tsx: exists

Commits confirmed:
- de57019: feat(07-06): BackupManager package
- 158026e: feat(07-06): backup API handlers
- 0f6ef0b: feat(07-06): backup/restore CLI, Dashboard Backup page
