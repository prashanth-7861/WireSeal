"""SSH bridge and key management handlers."""
from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name


def _ssh_load_targets() -> list[dict]:
    try:
        raw = _SSH_TARGETS_CONFIG_PATH.read_text(encoding="utf-8")
        entries = json.loads(raw)
        if not isinstance(entries, list):
            return []
        result = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            h = e.get("host", "")
            p = e.get("port")
            if isinstance(h, str) and isinstance(p, int) and _SSH_HOST_RE.match(h) and 1 <= p <= 65535:
                result.append({"host": h, "port": p})
        return result
    except (OSError, json.JSONDecodeError, ValueError):
        return []


def _ssh_check_target_allowed(host: str, port: int) -> None:
    targets = _ssh_load_targets()
    if not any(t["host"] == host and t["port"] == port for t in targets):
        try:
            from wireseal.security.audit import AuditLog
            AuditLog(_s._AUDIT_PATH).log(
                "ssh-target-denied",
                {"host": host, "port": port},
                actor=_session.get("admin_id", "owner"),
            )
        except Exception:
            pass
        raise _ApiError("ssh target not allowed", 403)


def _validate_ssh_target_entry(entry: dict) -> dict:
    host = entry.get("host", "")
    port = entry.get("port")
    if not isinstance(host, str) or not _SSH_HOST_RE.match(host):
        raise _ApiError(
            "host must be a string matching ^[a-zA-Z0-9.\\-]{1,253}$", 400
        )
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise _ApiError("port must be an integer between 1 and 65535", 400)
    return {"host": host, "port": port}


def _h_ssh_targets_get(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    return {"targets": _ssh_load_targets()}


def _h_ssh_targets_set(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    raw_list = body.get("targets")
    if not isinstance(raw_list, list):
        raise _ApiError("targets must be a JSON array", 400)
    cleaned = [_validate_ssh_target_entry(e) for e in raw_list]
    _VAULT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _SSH_TARGETS_CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(cleaned, indent=2), encoding="utf-8")
    tmp.replace(_SSH_TARGETS_CONFIG_PATH)
    return {"ok": True, "targets": cleaned}


def _h_ssh_token(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    host = str(body.get("host", "")).strip()
    port = int(body.get("port", 22))
    username = str(body.get("username", "")).strip()
    password = body.get("password")
    profile_name = str(body.get("profile_name", "")).strip()
    term = str(body.get("term", "xterm-256color")).strip() or "xterm-256color"
    key_name = str(body.get("key_name", "")).strip() or None
    if not host:
        raise _ApiError("host is required", 400)
    if not username:
        raise _ApiError("username is required", 400)
    if port < 1 or port > 65535:
        raise _ApiError("port out of range", 400)
    if not profile_name:
        raise _ApiError("profile_name is required", 400)
    _cache = _session.get("cache") or {}
    if _cache.get("mode") != "client":
        _ssh_check_target_allowed(host, port)
    from wireseal.client.tunnel import tunnel_status as _tunnel_status
    status = _tunnel_status()
    if not status.get("connected"):
        raise _ApiError(
            "No active WireGuard tunnel. Connect to a server profile first.",
            409,
        )
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
            except Exception as exc:
                raise _ApiError(f"Failed to load SSH key: {exc}", 500)
    from wireseal.ssh.session_manager import get_manager
    from wireseal.ssh.ws_bridge import DEFAULT_PATH, DEFAULT_PORT
    from wireseal.security.audit import AuditLog
    actor_id = _session.get("admin_id", "owner")
    manager = get_manager()
    token = manager.issue_ticket(
        host=host,
        port=port,
        username=username,
        password=password if isinstance(password, str) else None,
        profile_name=profile_name,
        actor_id=actor_id,
        term=term,
        key_name=key_name,
        key_pem=key_pem,
    )
    AuditLog(_s._AUDIT_PATH).log(
        "ssh-token-issued",
        {
            "profile": profile_name,
            "host": host,
            "port": port,
            "username": username,
        },
        actor=actor_id,
    )
    return {
        "token": token,
        "ws_url": f"ws://127.0.0.1:{DEFAULT_PORT}{DEFAULT_PATH}?token={token}",
        "expires_in": 60,
    }


def _h_ssh_accept_host_key(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    host = str(body.get("host", "")).strip()
    port_raw = body.get("port", 22)
    key_export = str(body.get("key_export", "")).strip()
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        raise _ApiError("port must be an integer", 400)
    if not host:
        raise _ApiError("host is required", 400)
    if not key_export:
        raise _ApiError("key_export is required", 400)
    from wireseal.ssh.ws_bridge import append_known_host, _get_known_hosts_path
    log_dir = _VAULT_DIR / "ssh-sessions"
    log_dir.mkdir(parents=True, exist_ok=True)
    known_hosts_path = _get_known_hosts_path(log_dir)
    append_known_host(known_hosts_path, host, port, key_export)
    from wireseal.security.audit import AuditLog
    try:
        AuditLog(_s._AUDIT_PATH).log(
            "ssh-host-accepted",
            {"host": host, "port": port},
            actor=_session.get("admin_id", "owner"),
        )
    except Exception:
        pass
    return {"ok": True}


def _h_ssh_sessions(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    from wireseal.ssh.session_manager import get_manager
    return {"sessions": get_manager().list_active()}


def _h_ssh_keys_list(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    vault = _session.get("vault")
    passphrase = _session.get("passphrase")
    if not vault or not passphrase:
        raise _ApiError("Vault not unlocked", 401)
    with vault.open(passphrase) as state:
        from wireseal.client.ssh_keys import list_keys
        result = list_keys(state._data)
    return {"keys": result}


def _h_ssh_keys_generate(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    vault = _session.get("vault")
    passphrase = _session.get("passphrase")
    if not vault or not passphrase:
        raise _ApiError("Vault not unlocked", 401)
    body = req._json()
    name = str(body.get("name", "")).strip()
    key_type = str(body.get("key_type", "")).strip()
    if not name:
        raise _ApiError("name is required", 400)
    if key_type not in ("ed25519", "rsa-2048", "rsa-4096"):
        raise _ApiError("key_type must be 'ed25519', 'rsa-2048', or 'rsa-4096'", 400)
    from wireseal.client.ssh_keys import generate_keypair
    with vault.open(passphrase) as state:
        if name in state._data.get("ssh_keys", {}):
            raise _ApiError(f"Key '{name}' already exists", 409)
        entry = generate_keypair(state._data, name, key_type)
        vault.save(state, passphrase)
    return {
        "name": name,
        "type": entry["type"],
        "fingerprint": entry["fingerprint"],
        "created_at": entry["created_at"],
    }


def _h_ssh_keys_delete(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    vault = _session.get("vault")
    passphrase = _session.get("passphrase")
    if not vault or not passphrase:
        raise _ApiError("Vault not unlocked", 401)
    name = _groups[0] if _groups else ""
    if not name:
        raise _ApiError("Key name is required", 400)
    from wireseal.client.ssh_keys import delete_key
    with vault.open(passphrase) as state:
        try:
            delete_key(state._data, name)
        except KeyError:
            raise _ApiError(f"Key '{name}' not found", 404)
        vault.save(state, passphrase)
    return {"ok": True}


def _h_ssh_keys_public(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    vault = _session.get("vault")
    passphrase = _session.get("passphrase")
    if not vault or not passphrase:
        raise _ApiError("Vault not unlocked", 401)
    name = _groups[0] if _groups else ""
    if not name:
        raise _ApiError("Key name is required", 400)
    from wireseal.client.ssh_keys import export_public_key
    with vault.open(passphrase) as state:
        try:
            public_key = export_public_key(state._data, name)
        except KeyError:
            raise _ApiError(f"Key '{name}' not found", 404)
    return {
        "name": name,
        "public_key": public_key,
    }
