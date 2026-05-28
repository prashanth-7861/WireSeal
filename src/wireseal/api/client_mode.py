"""Client mode -- config management and tunnel control."""
from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name


_CLIENT_SETTINGS_DEFAULTS: dict = {
    "auto_connect_profile": None,
    "auto_lock_minutes": 15,
    "kill_switch": False,
    "dns_override": "",
    "ssh_saved_hosts": [],
    "sftp_saved_connections": [],
}


def _get_client_settings(state: Any) -> dict:
    stored = state.data.get("client_settings", {})
    return {**_CLIENT_SETTINGS_DEFAULTS, **stored}


def _h_client_import_config(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    body = req._json()
    name = body.get("name", "").strip()
    config_text = body.get("config_text", "")
    if not name:
        raise _ApiError("name is required", 400)
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", name):
        raise _ApiError("Name must be alphanumeric, hyphens, or underscores (max 32 chars)", 400)
    if not config_text:
        raise _ApiError("config_text is required", 400)
    from wireseal.client.config_store import import_config, validate_conf
    errors = validate_conf(config_text)
    if errors:
        raise _ApiError(f"Invalid config: {'; '.join(errors)}", 400)
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
    from wireseal.security.audit import AuditLog
    with vault.open(passphrase) as state:
        try:
            meta = import_config(state._data, name, config_text)
        except ValueError as exc:
            raise _ApiError(str(exc), 409)
        vault.save(state, passphrase)
    AuditLog(_VAULT_DIR / "audit.log").log(
        "client-config-import",
        {"name": name, **meta},
        actor=_session.get("admin_id", "owner"),
    )
    return {"ok": True, "name": name, **meta}


def _h_client_list_configs(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
    from wireseal.client.config_store import list_configs
    with vault.open(passphrase) as state:
        configs = list_configs(state._data)
    return {"configs": configs}


def _h_client_get_config(req: "_Handler", groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    name = groups[0]
    reveal = False
    try:
        from urllib.parse import urlsplit, parse_qs as _parse_qs
        q = urlsplit(getattr(req, "path", "") or "").query
        qs = _parse_qs(q)
        vals = qs.get("reveal", [])
        if vals and vals[0].lower() in ("1", "true", "yes"):
            reveal = True
    except Exception:
        reveal = False
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
    from wireseal.client.config_store import (
        get_config_redacted,
        get_config_revealed,
    )
    from wireseal.security.audit import AuditLog
    with vault.open(passphrase) as state:
        try:
            if reveal:
                config = get_config_revealed(state._data, name)
            else:
                config = get_config_redacted(state._data, name)
        except KeyError:
            raise _ApiError(f"Profile '{name}' not found", 404)
    if reveal:
        try:
            AuditLog(_s._AUDIT_PATH).log(
                "client-config-revealed",
                {"name": name, "via": "http-get"},
                actor=_session.get("admin_id", "owner"),
            )
        except Exception:
            pass
    return config


def _h_client_delete_config(req: "_Handler", groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    name = groups[0]
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
    from wireseal.client.config_store import delete_config
    from wireseal.security.audit import AuditLog
    with vault.open(passphrase) as state:
        try:
            delete_config(state._data, name)
        except KeyError:
            raise _ApiError(f"Profile '{name}' not found", 404)
        vault.save(state, passphrase)
    AuditLog(_VAULT_DIR / "audit.log").log(
        "client-config-delete",
        {"name": name},
        actor=_session.get("admin_id", "owner"),
    )
    return {"ok": True}


def _h_client_update_config(req: "_Handler", groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    name = groups[0]
    body = req._json()
    config_text = body.get("config_text", "")
    if not isinstance(config_text, str) or not config_text.strip():
        raise _ApiError("config_text must be a non-empty string", 400)
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
    from wireseal.client.config_store import update_config
    from wireseal.security.audit import AuditLog
    with vault.open(passphrase) as state:
        try:
            meta = update_config(state._data, name, config_text)
        except KeyError:
            raise _ApiError(f"Profile '{name}' not found", 404)
        except ValueError as exc:
            raise _ApiError(str(exc), 400)
        vault.save(state, passphrase)
    AuditLog(_VAULT_DIR / "audit.log").log(
        "client-config-update",
        {"name": name},
        actor=_session.get("admin_id", "owner"),
    )
    return {"ok": True, "name": name, **meta}


def _h_client_tunnel_up(req: "_Handler", groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    name = groups[0]
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
    from wireseal.client.config_store import get_config_revealed
    from wireseal.client.tunnel import apply_dns_override, tunnel_up
    from wireseal.security.audit import AuditLog
    ks_enabled = False
    dns_override = ""
    with vault.open(passphrase) as state:
        try:
            config = get_config_revealed(state._data, name)
            try:
                settings_data = _get_client_settings(state._data if hasattr(state, '_data') else state)
                ks_enabled = bool(settings_data.get("kill_switch", False))
                dns_override = settings_data.get("dns_override", "")
            except Exception:
                pass
        except KeyError:
            raise _ApiError(f"Profile '{name}' not found", 404)
    audit = AuditLog(_VAULT_DIR / "audit.log")
    try:
        audit.log(
            "client-config-revealed",
            {"name": name, "via": "tunnel-up"},
            actor=_session.get("admin_id", "owner"),
        )
    except Exception:
        pass
    config_text = config["config_text"]
    if dns_override:
        config_text = apply_dns_override(config_text, dns_override)
    try:
        result = tunnel_up(config_text, name, enable_kill_switch=ks_enabled)
    except RuntimeError as exc:
        raise _ApiError(str(exc), 500)
    audit.log(
        "client-tunnel-up",
        {"profile": name, "kill_switch": ks_enabled},
        actor=_session.get("admin_id", "owner"),
    )
    return result


def _h_client_tunnel_down(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    from wireseal.client.tunnel import tunnel_down
    from wireseal.security.audit import AuditLog
    try:
        result = tunnel_down()
    except RuntimeError as exc:
        raise _ApiError(str(exc), 500)
    AuditLog(_VAULT_DIR / "audit.log").log(
        "client-tunnel-down",
        {"profile": result.get("profile")},
        actor=_session.get("admin_id", "owner"),
    )
    return result


def _h_client_tunnel_status(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    from wireseal.client.tunnel import tunnel_status
    return tunnel_status()


def _h_client_settings_get(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
    with vault.open(passphrase) as state:
        return _get_client_settings(state)


def _h_client_settings_put(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_client_mode()
    body = req._json()
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id = _session.get("admin_id", "owner")
    if "auto_connect_profile" in body:
        val = body["auto_connect_profile"]
        if val is not None and not isinstance(val, str):
            raise _ApiError("auto_connect_profile must be a string or null", 400)
        if isinstance(val, str) and not re.fullmatch(r"[a-zA-Z0-9\-]{1,32}", val):
            raise _ApiError("auto_connect_profile must be a valid profile name", 400)
    if "auto_lock_minutes" in body:
        try:
            val = int(body["auto_lock_minutes"])
        except (TypeError, ValueError):
            raise _ApiError("auto_lock_minutes must be an integer", 400)
        if val < 1 or val > 1440:
            raise _ApiError("auto_lock_minutes must be between 1 and 1440", 400)
        body["auto_lock_minutes"] = val
    if "kill_switch" in body:
        if not isinstance(body["kill_switch"], bool):
            raise _ApiError("kill_switch must be a boolean", 400)
    if "dns_override" in body:
        val = str(body["dns_override"]).strip()
        if val:
            import ipaddress as _ipa
            for entry in val.split(","):
                entry = entry.strip()
                try:
                    _ipa.ip_address(entry)
                except ValueError:
                    raise _ApiError(f"Invalid DNS address: {entry}", 400)
        body["dns_override"] = val
    if "ssh_saved_hosts" in body:
        hosts = body["ssh_saved_hosts"]
        if not isinstance(hosts, list):
            raise _ApiError("ssh_saved_hosts must be a list", 400)
        if len(hosts) > 50:
            raise _ApiError("Maximum 50 saved SSH hosts", 400)
        validated: list[dict] = []
        for h in hosts:
            if not isinstance(h, dict):
                raise _ApiError("Each SSH host must be an object", 400)
            host_val = str(h.get("host", "")).strip()
            port_val = int(h.get("port", 22))
            user_val = str(h.get("username", "")).strip()
            label_val = str(h.get("label", "")).strip()
            if not host_val:
                raise _ApiError("SSH host address is required", 400)
            if port_val < 1 or port_val > 65535:
                raise _ApiError("SSH port must be 1-65535", 400)
            if not user_val:
                raise _ApiError("SSH username is required", 400)
            if not re.fullmatch(r"[a-zA-Z0-9.\-:]+", host_val):
                raise _ApiError(f"Invalid SSH host: {host_val}", 400)
            if not re.fullmatch(r"[a-zA-Z0-9._\-]+", user_val):
                raise _ApiError(f"Invalid SSH username: {user_val}", 400)
            validated.append({
                "host": host_val,
                "port": port_val,
                "username": user_val,
                "label": label_val[:64],
            })
        body["ssh_saved_hosts"] = validated
    if "sftp_saved_connections" in body:
        conns = body["sftp_saved_connections"]
        if not isinstance(conns, list):
            raise _ApiError("sftp_saved_connections must be a list", 400)
        if len(conns) > 50:
            raise _ApiError("Maximum 50 saved SFTP connections", 400)
        validated_conns: list[dict] = []
        for c in conns:
            if not isinstance(c, dict):
                raise _ApiError("Each SFTP connection must be an object", 400)
            label_val = str(c.get("label", "")).strip()[:64]
            host_val = str(c.get("host", "")).strip()
            port_val = int(c.get("port", 22))
            user_val = str(c.get("username", "")).strip()
            auth_val = str(c.get("auth_mode", "password")).strip()
            key_val = str(c.get("key_name", "")).strip()
            if not host_val:
                raise _ApiError("SFTP connection host is required", 400)
            if port_val < 1 or port_val > 65535:
                raise _ApiError("SFTP port must be 1-65535", 400)
            if not user_val:
                raise _ApiError("SFTP username is required", 400)
            if not re.fullmatch(r"[a-zA-Z0-9.\-:]+", host_val):
                raise _ApiError(f"Invalid SFTP host: {host_val}", 400)
            if not re.fullmatch(r"[a-zA-Z0-9._\-]+", user_val):
                raise _ApiError(f"Invalid SFTP username: {user_val}", 400)
            if auth_val not in ("password", "key"):
                raise _ApiError("auth_mode must be 'password' or 'key'", 400)
            validated_conns.append({
                "label": label_val,
                "host": host_val,
                "port": port_val,
                "username": user_val,
                "auth_mode": auth_val,
                "key_name": key_val,
            })
        body["sftp_saved_connections"] = validated_conns
    allowed_keys = set(_CLIENT_SETTINGS_DEFAULTS.keys())
    update = {k: v for k, v in body.items() if k in allowed_keys}
    if not update:
        raise _ApiError("No valid settings fields provided", 400)
    with vault.open(passphrase) as state:
        current = state.data.get("client_settings", {})
        current.update(update)
        state.data["client_settings"] = current
        vault.save(state, passphrase)
    from wireseal.security.audit import AuditLog
    AuditLog(_s._AUDIT_PATH).log(
        "client-settings-updated",
        {"fields": list(update.keys())},
        actor=_actor_id,
    )
    if "auto_lock_minutes" in update:
        global _SESSION_TIMEOUT
        _SESSION_TIMEOUT = update["auto_lock_minutes"] * 60
    return {**_CLIENT_SETTINGS_DEFAULTS, **current}
