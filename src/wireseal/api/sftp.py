"""SFTP file browser handlers."""
from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name


def _validate_sftp_path(path: str) -> str:
    """Validate and normalize a remote SFTP path.

    Rejects null bytes, non-printable ASCII, and any remaining ``..``
    traversal components after normalization.
    """
    import posixpath as _posixpath
    if "\x00" in path:
        raise _ApiError("Invalid path", 400)
    # Reject non-printable ASCII (control chars)
    if any(ord(c) < 0x20 for c in path):
        raise _ApiError("Invalid path", 400)
    normalized = _posixpath.normpath(path)
    # After normpath, ".." components only remain if they escape the root
    parts = normalized.split("/")
    if ".." in parts:
        raise _ApiError("Path traversal not allowed", 400)
    # SEC (H-05): require an absolute path so an empty/relative path can't be
    # resolved against the remote CWD into an unintended location.
    if not normalized.startswith("/"):
        raise _ApiError("Path must be absolute", 400)
    return normalized


def _check_sftp_rate(session_id: str, bytes_transferred: int = 0) -> None:
    now = _time.monotonic()
    last = _sftp_rate_last.get(session_id, 0)
    if now - last < _SFTP_MIN_INTERVAL:
        raise _ApiError("Too many requests", 429)
    _sftp_rate_last[session_id] = now
    if bytes_transferred > 0:
        byte_budget = _sftp_rate_bytes.get(session_id, _SFTP_MAX_BYTES)
        if now - _sftp_rate_bytes.get(f"{session_id}_reset", 0) > 60:
            byte_budget = _SFTP_MAX_BYTES
            _sftp_rate_bytes[f"{session_id}_reset"] = now
        if bytes_transferred > byte_budget:
            raise _ApiError("Transfer rate limit exceeded", 429)
        _sftp_rate_bytes[session_id] = byte_budget - bytes_transferred


def _h_sftp_connect(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    host = str(body.get("host", "")).strip()
    port = int(body.get("port", 22))
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    key_name = str(body.get("key_name", "")).strip() or None
    if not host or not username:
        raise _ApiError("host and username are required", 400)
    if port < 1 or port > 65535:
        raise _ApiError("port out of range", 400)
    # Validate hostname format (same as SSH handler)
    if not _SSH_HOST_RE.match(host):
        raise _ApiError("Invalid hostname", 400)
    # Enforce SSH target allowlist (same as terminal)
    from wireseal.api.ssh import _ssh_check_target_allowed
    _ssh_check_target_allowed(host, port)
    key_pem: str | None = None
    if key_name:
        vault = _session.get("vault")
        passphrase = _session.get("passphrase")
        if vault and passphrase:
            try:
                with vault.open(passphrase) as state:
                    from wireseal.client.ssh_keys import get_private_key
                    try:
                        key = get_private_key(state._data, key_name)
                        key_pem = key.export_private_key().decode("utf-8")
                    except KeyError:
                        raise _ApiError(f"SSH key '{key_name}' not found", 404)
            except _ApiError:
                raise
            except Exception:
                raise _ApiError("Failed to load SSH key", 500)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    from wireseal.sftp.bridge import SftpTofuRequired
    from wireseal.security.audit import AuditLog
    try:
        session_id = _sftp_mgr().connect(host, port, username, password, key_name=key_name, key_pem=key_pem or "")
        with _lock:
            _actor = _session.get("admin_id", "unknown")
        AuditLog(_s._AUDIT_PATH).log("sftp-connect", {"host": host, "port": port, "username": username},
                                      actor=_actor)
        try:
            if _session.get("vault") and _session.get("passphrase"):
                v = _session["vault"]
                pp = _session["passphrase"]
                with v.open(pp) as _st:
                    _settings = _st.data.get("client_settings", {})
                    _saved = _settings.get("sftp_saved_connections", [])
                    _saved = [c for c in _saved if not (c["host"] == host and c["username"] == username)]
                    _saved.insert(0, {
                        "label": "",
                        "host": host,
                        "port": port,
                        "username": username,
                        "auth_mode": "key" if key_name else "password",
                        "key_name": key_name or "",
                    })
                    _saved = _saved[:50]
                    _settings["sftp_saved_connections"] = _saved
                    _st.data["client_settings"] = _settings
                    v.save(_st, pp)
        except Exception:
            pass
        return {"session_id": session_id, "host": host, "port": port, "username": username}
    except SftpTofuRequired as tofu:
        # Surface host key fingerprint so frontend can ask user to accept
        return {
            "tofu_required": True,
            "host": tofu.host,
            "port": tofu.port,
            "fingerprint": tofu.fingerprint,
            "key_export": tofu.key_export,
        }
    except OSError as e:
        err_msg = str(e)
        if "authentication" in err_msg.lower() or "auth" in err_msg.lower():
            raise _ApiError("Authentication failed. Check username and password.", 502)
        # Sanitize: don't leak raw exception details
        raise _ApiError("Connection failed. Check host and port.", 502)


def _h_sftp_disconnect(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    session_id = str(body.get("session_id", "")).strip() if isinstance(body, dict) else ""
    if not session_id:
        raise _ApiError("session_id is required", 400)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    _sftp_mgr().disconnect(session_id)
    # Clean up rate-limit state for this session
    _sftp_rate_last.pop(session_id, None)
    _sftp_rate_bytes.pop(session_id, None)
    _sftp_rate_bytes.pop(f"{session_id}_reset", None)
    return {"ok": True}


def _h_sftp_list(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_admin_role()  # SEC (H-03): reading remote files is admin-only
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "/")).strip())
    if not session_id:
        raise _ApiError("session_id is required", 400)
    _check_sftp_rate(session_id)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    import asyncssh as _asyncssh
    MAX_ENTRIES = 10_000
    async def _list():
        session = _sftp_mgr().get(session_id)
        entries = []
        truncated = False
        async for entry in session.sftp.scandir(path):
            if len(entries) >= MAX_ENTRIES:
                truncated = True
                break
            attrs = entry.attributes
            is_dir = False
            perm_str = ""
            if hasattr(attrs, 'permissions') and attrs.permissions:
                is_dir = bool(attrs.permissions & 0o40000)
                perm_str = oct(attrs.permissions)[2:]
            elif hasattr(attrs, 'type'):
                is_dir = attrs.type == 2
            entries.append({
                "name": entry.filename,
                "size": attrs.size if hasattr(attrs, 'size') else 0,
                "type": "dir" if is_dir else "file",
                "modified": attrs.mtime if hasattr(attrs, 'mtime') and attrs.mtime else 0,
                "permissions": perm_str,
            })
        entries.sort(key=lambda e: (0 if e["type"] == "dir" else 1, e["name"].lower()))
        return {"path": path, "entries": entries, "truncated": truncated}
    try:
        return _sftp_mgr().run(session_id, _list())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)


def _h_sftp_read(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_admin_role()  # SEC (H-03): reading remote files is admin-only
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "")).strip())
    if not session_id or not path:
        raise _ApiError("session_id and path are required", 400)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    import asyncssh as _asyncssh
    import base64 as _b64
    MAX_READ = 10 * 1024 * 1024
    async def _read():
        session = _sftp_mgr().get(session_id)
        stat = await session.sftp.stat(path)
        size = stat.size if hasattr(stat, 'size') else 0
        _check_sftp_rate(session_id, size)
        if size > MAX_READ:
            raise _ApiError("File too large (max 10 MB)", 413)
        # Read with size cap to guard against stat/read race or adversarial server
        async with session.sftp.open(path, "rb") as f:
            data = await f.read(MAX_READ + 1)
        if len(data) > MAX_READ:
            raise _ApiError("File too large (max 10 MB)", 413)
        import mimetypes as _mime
        mime, _ = _mime.guess_type(path)
        return {"path": path, "content_b64": _b64.b64encode(data).decode(), "size": len(data), "mime": mime or "application/octet-stream"}
    try:
        return _sftp_mgr().run(session_id, _read())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)


def _h_sftp_write(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_admin_role()
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "")).strip())
    content_b64 = str(body.get("content_b64", "")).strip()
    if not session_id or not path or not content_b64:
        raise _ApiError("session_id, path, and content_b64 are required", 400)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    import asyncssh as _asyncssh
    import base64 as _b64
    from wireseal.security.audit import AuditLog
    MAX_WRITE = 50 * 1024 * 1024
    try:
        data = _b64.b64decode(content_b64)
    except Exception:
        raise _ApiError("Invalid base64 content", 400)
    if len(data) > MAX_WRITE:
        raise _ApiError("File too large (max 50 MB)", 413)
    # Single rate check with byte count (not double-call)
    _check_sftp_rate(session_id, len(data))
    async def _write():
        session = _sftp_mgr().get(session_id)
        await session.sftp.writebytes(path, data)
        with _lock:
            _actor = _session.get("admin_id", "unknown")
        AuditLog(_s._AUDIT_PATH).log("sftp-write", {"path": path, "size": len(data), "host": session.host},
                                      actor=_actor)
        return {"ok": True, "path": path, "size": len(data)}
    try:
        return _sftp_mgr().run(session_id, _write())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)


def _h_sftp_delete(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_admin_role()
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "")).strip())
    if not session_id or not path:
        raise _ApiError("session_id and path are required", 400)
    _check_sftp_rate(session_id)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    import asyncssh as _asyncssh
    async def _delete():
        session = _sftp_mgr().get(session_id)
        from wireseal.security.audit import AuditLog
        try:
            await session.sftp.rmdir(path)
        except _asyncssh.SFTPFailure:
            await session.sftp.remove(path)
        with _lock:
            _actor = _session.get("admin_id", "unknown")
        AuditLog(_s._AUDIT_PATH).log("sftp-delete", {"path": path, "host": session.host}, actor=_actor)
        return {"ok": True, "path": path}
    try:
        return _sftp_mgr().run(session_id, _delete())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)


def _h_sftp_rename(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_admin_role()
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "")).strip())
    new_path = _validate_sftp_path(str(body.get("new_path", "")).strip())
    if not session_id or not path or not new_path:
        raise _ApiError("session_id, path, and new_path are required", 400)
    _check_sftp_rate(session_id)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    import asyncssh as _asyncssh
    async def _rename():
        session = _sftp_mgr().get(session_id)
        await session.sftp.rename(path, new_path)
        with _lock:
            _actor = _session.get("admin_id", "unknown")
        from wireseal.security.audit import AuditLog
        AuditLog(_s._AUDIT_PATH).log("sftp-rename", {"from": path, "to": new_path, "host": session.host},
                                      actor=_actor)
        return {"ok": True, "path": path, "new_path": new_path}
    try:
        return _sftp_mgr().run(session_id, _rename())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)


def _h_sftp_mkdir(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_admin_role()
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "")).strip())
    if not session_id or not path:
        raise _ApiError("session_id and path are required", 400)
    _check_sftp_rate(session_id)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    import asyncssh as _asyncssh
    async def _mkdir():
        session = _sftp_mgr().get(session_id)
        await session.sftp.mkdir(path, parents=True)
        with _lock:
            _actor = _session.get("admin_id", "unknown")
        from wireseal.security.audit import AuditLog
        AuditLog(_s._AUDIT_PATH).log("sftp-mkdir", {"path": path, "host": session.host}, actor=_actor)
        return {"ok": True, "path": path}
    try:
        return _sftp_mgr().run(session_id, _mkdir())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)


def _h_sftp_copy(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_admin_role()
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "")).strip())
    new_path = _validate_sftp_path(str(body.get("new_path", "")).strip())
    if not session_id or not path or not new_path:
        raise _ApiError("session_id, path, and new_path are required", 400)
    _check_sftp_rate(session_id)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    import asyncssh as _asyncssh
    MAX_COPY = 50 * 1024 * 1024
    async def _copy():
        session = _sftp_mgr().get(session_id)
        # Check size before reading into memory
        stat = await session.sftp.stat(path)
        size = stat.size if hasattr(stat, 'size') else 0
        if size > MAX_COPY:
            raise _ApiError("File too large to copy (max 50 MB)", 413)
        async with session.sftp.open(path, "rb") as f:
            data = await f.read(MAX_COPY + 1)
        if len(data) > MAX_COPY:
            raise _ApiError("File too large to copy (max 50 MB)", 413)
        await session.sftp.writebytes(new_path, data)
        with _lock:
            _actor = _session.get("admin_id", "unknown")
        from wireseal.security.audit import AuditLog
        AuditLog(_s._AUDIT_PATH).log("sftp-copy", {"from": path, "to": new_path, "host": session.host},
                                      actor=_actor)
        return {"ok": True, "path": path, "new_path": new_path}
    try:
        return _sftp_mgr().run(session_id, _copy())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)


def _h_sftp_chmod(req: "_Handler", _groups: tuple) -> dict:
    """Change file/directory permissions on the remote server."""
    _require_unlocked()
    _require_admin_role()
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "")).strip())
    mode = body.get("mode")
    if not session_id or not path:
        raise _ApiError("session_id and path are required", 400)
    if not isinstance(mode, int) or mode < 0 or mode > 0o7777:
        raise _ApiError("mode must be an integer 0-4095 (octal permissions)", 400)
    _check_sftp_rate(session_id)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    async def _chmod():
        session = _sftp_mgr().get(session_id)
        await session.sftp.chmod(path, mode)
        with _lock:
            _actor = _session.get("admin_id", "unknown")
        from wireseal.security.audit import AuditLog
        AuditLog(_s._AUDIT_PATH).log("sftp-chmod", {"path": path, "mode": oct(mode), "host": session.host},
                                      actor=_actor)
        return {"ok": True, "path": path, "mode": oct(mode)}
    try:
        return _sftp_mgr().run(session_id, _chmod())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)


def _h_sftp_stat(req: "_Handler", _groups: tuple) -> dict:
    """Get detailed file/directory attributes."""
    _require_unlocked()
    _require_admin_role()  # SEC (H-03): remote metadata is admin-only
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "")).strip())
    if not session_id or not path:
        raise _ApiError("session_id and path are required", 400)
    _check_sftp_rate(session_id)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    async def _stat():
        session = _sftp_mgr().get(session_id)
        attrs = await session.sftp.stat(path)
        result: dict = {"path": path}
        if hasattr(attrs, 'size'):
            result["size"] = attrs.size
        if hasattr(attrs, 'permissions') and attrs.permissions is not None:
            result["permissions"] = attrs.permissions
            result["permissions_octal"] = oct(attrs.permissions)
            result["is_dir"] = bool(attrs.permissions & 0o40000)
            result["is_link"] = bool(attrs.permissions & 0o120000)
        if hasattr(attrs, 'uid'):
            result["uid"] = attrs.uid
        if hasattr(attrs, 'gid'):
            result["gid"] = attrs.gid
        if hasattr(attrs, 'mtime') and attrs.mtime:
            result["modified"] = attrs.mtime
        if hasattr(attrs, 'atime') and attrs.atime:
            result["accessed"] = attrs.atime
        return result
    try:
        return _sftp_mgr().run(session_id, _stat())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)


def _h_sftp_exists(req: "_Handler", _groups: tuple) -> dict:
    """Check if a remote path exists (used for overwrite confirmation)."""
    _require_unlocked()
    _require_admin_role()  # SEC (H-03): remote metadata is admin-only
    body = req._json()
    if not isinstance(body, dict):
        raise _ApiError("Invalid JSON body", 400)
    session_id = str(body.get("session_id", "")).strip()
    path = _validate_sftp_path(str(body.get("path", "")).strip())
    if not session_id or not path:
        raise _ApiError("session_id and path are required", 400)
    from wireseal.sftp.bridge import get_manager as _sftp_mgr
    async def _exists():
        session = _sftp_mgr().get(session_id)
        try:
            await session.sftp.stat(path)
            return {"exists": True, "path": path}
        except Exception:
            return {"exists": False, "path": path}
    try:
        return _sftp_mgr().run(session_id, _exists())
    except LookupError:
        raise _ApiError("Session not found or expired. Reconnect.", 401)
