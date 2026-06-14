"""Backup and restore handlers."""
from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name


def _h_backup_config_get(req, _groups):
    _require_unlocked()
    with _lock:
        cache = _session["cache"] or {}
    cfg = cache.get("backup_config", {})
    safe = {k: v for k, v in cfg.items() if k != "webdav_pass"}
    from wireseal.backup.scheduler import schedule_status
    try:
        active = schedule_status().get("schedule_active", False)
    except Exception:
        active = False
    return {"backup_config": safe, "schedule_active": active}


def _sync_backup_schedule(vault_path) -> str | None:
    """Reconcile the OS scheduler + out-of-vault env with the saved config.

    Returns a warning string if scheduling could not be applied (e.g. the
    server is not running as root), otherwise None. Never raises — the manual
    backup path must keep working regardless.
    """
    from wireseal.backup import scheduler
    with _lock:
        cache = _session["cache"] or {}
    cfg = cache.get("backup_config", {}) or {}
    schedule = cfg.get("schedule", "off")
    enabled = bool(cfg.get("enabled"))
    try:
        if enabled and schedule in scheduler.SCHEDULES and schedule != "off":
            scheduler.write_backup_env(cfg, vault_path)
            scheduler.install_schedule(schedule)
        else:
            scheduler.remove_schedule()
            scheduler.remove_backup_env()
    except scheduler.ScheduleError as exc:
        return str(exc)
    except Exception as exc:
        return f"Could not apply backup schedule: {exc}"
    return None


def _h_backup_config_set(req, _groups):
    _require_unlocked()
    body = req._json()
    allowed_keys = {
        "enabled", "destination", "local_path", "ssh_host", "ssh_user", "ssh_path",
        "webdav_url", "webdav_user", "webdav_pass", "keep_n", "schedule",
    }
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        admin_id = _session.get("admin_id", "owner")
    with vault.open(passphrase, admin_id=admin_id) as state:
        cfg = state.data.setdefault("backup_config", {})
        for k, v in body.items():
            if k in allowed_keys:
                cfg[k] = v
        vault.save(state, passphrase)
    _refresh_cache_unlocked(vault, passphrase, admin_id)

    resp = {"ok": True}
    warning = _sync_backup_schedule(vault._path)
    if warning:
        resp["schedule_warning"] = warning
    return resp


def _h_backup_trigger(req, _groups):
    _require_unlocked()
    with _lock:
        cache = _session["cache"] or {}
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        admin_id = _session.get("admin_id", "owner")
    cfg = cache.get("backup_config", {})
    if not cfg.get("enabled"):
        raise _ApiError("Backup not enabled in backup_config. Set enabled=true first.", 400)
    vault_path = vault._path
    try:
        entry = _backup_manager.create_backup(vault_path, cfg)
    except (ValueError, RuntimeError) as exc:
        _notify_event("backup_failed", "WireSeal: backup failed",
                      f"Backup to {cfg.get('destination', 'local')} failed: {exc}",
                      priority="high")
        raise _ApiError(str(exc), 500)
    keep_n = cfg.get("keep_n", 10)
    if isinstance(keep_n, int) and keep_n > 0:
        _backup_manager.prune_old(cfg, keep_n)
    import time as _time
    with vault.open(passphrase, admin_id=admin_id) as state:
        state.data.setdefault("backup_config", {})["last_backup_at"] = entry.created_at
        vault.save(state, passphrase)
    _refresh_cache_unlocked(vault, passphrase, admin_id)
    from wireseal.security.audit import AuditLog
    AuditLog(_s._AUDIT_PATH).log("backup-trigger", {
        "path": entry.path, "size_bytes": entry.size_bytes, "actor": admin_id,
    })
    _notify_event("backup_done", "WireSeal: backup complete",
                  f"Backup created at {entry.path} ({entry.size_bytes} bytes).")
    return {"ok": True, "path": entry.path, "size_bytes": entry.size_bytes,
            "created_at": entry.created_at}


def _h_backup_list(req, _groups):
    _require_unlocked()
    with _lock:
        cache = _session["cache"] or {}
    cfg = cache.get("backup_config", {})
    entries = _backup_manager.list_backups(cfg)
    return {
        "backups": [
            {"path": e.path, "created_at": e.created_at, "size_bytes": e.size_bytes}
            for e in entries
        ]
    }


def _h_backup_restore(req, _groups):
    _require_unlocked()
    body = req._json()
    backup_path = body.get("backup_path", "")
    passphrase_str = body.get("passphrase", "")
    admin_id = body.get("admin_id", None)
    if not backup_path or not passphrase_str:
        raise _ApiError("backup_path and passphrase are required.", 400)
    with _lock:
        vault = _session["vault"]
        cache = _session["cache"] or {}
        session_admin_id = _session.get("admin_id", "owner")
    if admin_id is None:
        admin_id = session_admin_id
    vault_path = vault._path
    from pathlib import Path as _Path
    try:
        resolved_backup = _Path(backup_path).resolve(strict=True)
    except (FileNotFoundError, OSError, ValueError):
        raise _ApiError("Backup file not found.", 404)
    if any(part == ".." for part in _Path(backup_path).parts):
        raise _ApiError("backup_path must not contain '..' components.", 400)
    if not resolved_backup.is_file():
        raise _ApiError("backup_path must be a regular file.", 400)
    cfg = cache.get("backup_config", {}) or {}
    allowed_roots: list[_Path] = []
    local_backup_dir = cfg.get("local_path")
    if local_backup_dir:
        try:
            allowed_roots.append(_Path(local_backup_dir).resolve(strict=False))
        except (OSError, ValueError):
            pass
    try:
        allowed_roots.append(_Path(vault_path).resolve(strict=False).parent)
    except (OSError, ValueError):
        pass
    if not allowed_roots:
        raise _ApiError(
            "No backup directory is configured. Set backup_config.local_path "
            "before restoring.", 400,
        )
    for root in allowed_roots:
        try:
            resolved_backup.relative_to(root)
            break
        except ValueError:
            continue
    else:
        allowed_display = ", ".join(str(r) for r in allowed_roots)
        raise _ApiError(
            f"backup_path must live under an allowlisted backup directory "
            f"(permitted roots: {allowed_display}).",
            403,
        )
    backup_path = str(resolved_backup)
    from wireseal.security.secrets_wipe import wipe_bytes, wipe_string
    passphrase_ba = bytearray(passphrase_str.encode("utf-8"))
    try:
        from wireseal.security.exceptions import VaultUnlockError
        _backup_manager.restore_backup(backup_path, vault_path, passphrase_ba, admin_id=admin_id)
    except FileNotFoundError as exc:
        raise _ApiError(str(exc), 404)
    except Exception as exc:
        err_lower = str(exc).lower()
        if ("passphrase" in err_lower or "unlock" in err_lower or "gcm" in err_lower
                or "key" in err_lower or "decrypt" in err_lower or "backup" in err_lower):
            raise _ApiError("Restore failed - wrong passphrase or corrupted backup.", 401)
        raise _ApiError(str(exc), 500)
    finally:
        wipe_bytes(passphrase_ba)
        wipe_string(passphrase_str)
    with _lock:
        if _session["passphrase"]:
            try:
                _session["passphrase"].wipe()
            except Exception:
                pass
        _session.update(vault=None, passphrase=None, cache=None, admin_id=None, admin_role=None)
    from wireseal.security.audit import AuditLog
    AuditLog(_s._AUDIT_PATH).log("backup-restore", {
        "source": backup_path, "actor": admin_id,
    })
    return {"ok": True, "message": "Vault restored. Please re-unlock."}
