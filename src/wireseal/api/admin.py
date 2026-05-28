from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name

from . import vault as _vault_module
for _vault_name in dir(_vault_module):
    if not _vault_name.startswith("__"):
        globals()[_vault_name] = getattr(_vault_module, _vault_name)
del _vault_module, _vault_name


def _service_adapter_or_die():

    from wireseal.platform.detect import get_adapter

    adapter = get_adapter()

    if not hasattr(adapter, "install_api_service"):

        raise _ApiError(

            "Background-service registration is not available on this OS.",

            501,

        )

    return adapter






def _h_admin_authenticate(req: "_Handler", _groups: tuple) -> dict:

    """Verify root/sudo password and activate admin mode.



    POST /api/admin/authenticate

    Body: {"password": "..."}



    Vault must be unlocked first. Admin mode grants unrestricted system access

    for _ADMIN_TIMEOUT seconds. Rate-limited to 3 attempts per 5 minutes.

    """

    _require_unlocked()

    body      = req._json()

    password  = body.get("password", "")

    client_ip = req.client_address[0]



    if not password and sys.platform != "win32":

        raise _ApiError("password is required", 400)



    _check_admin_rate_limit(client_ip)



    if not _verify_root_password(password):

        _record_admin_failure(client_ip)

        from wireseal.security.audit import AuditLog

        AuditLog(_s._AUDIT_PATH).log("admin-auth-failed", {"ip": client_ip}, actor="system")

        raise _ApiError("Invalid credentials.", 401)



    _clear_admin_failures(client_ip)



    import time as _time

    from wireseal.security.secret_types import SecretBytes

    from wireseal.security.audit import AuditLog



    pw_secret = SecretBytes(bytearray(password.encode("utf-8")))



    with _admin_lock:

        if _admin_session["password"] is not None:

            try:

                _admin_session["password"].wipe()

            except Exception:

                pass

        _admin_session["active"]     = True

        _admin_session["password"]   = pw_secret

        _admin_session["expires_at"] = _time.monotonic() + _ADMIN_TIMEOUT



    AuditLog(_s._AUDIT_PATH).log("admin-activate", {"ip": client_ip},

                              actor=_session.get("admin_id", "owner"))

    return {"ok": True, "expires_in": _ADMIN_TIMEOUT}






def _h_admin_deactivate_endpoint(req: "_Handler", _groups: tuple) -> dict:

    """Deactivate admin mode and wipe cached credentials.



    POST /api/admin/deactivate

    """

    _require_unlocked()

    _admin_deactivate()

    from wireseal.security.audit import AuditLog

    AuditLog(_s._AUDIT_PATH).log("admin-deactivate", {}, actor=_session.get("admin_id", "owner"))

    return {"ok": True}






def _h_admin_status(req: "_Handler", _groups: tuple) -> dict:

    """Return admin mode state and seconds remaining.



    GET /api/admin/status

    """

    import time as _time

    with _admin_lock:

        active  = _admin_session["active"]

        expires = _admin_session["expires_at"]



    if not active:

        return {"active": False, "expires_in": 0}



    remaining = max(0.0, (expires or 0.0) - _time.monotonic())

    if remaining == 0.0:

        _admin_deactivate()

        return {"active": False, "expires_in": 0}



    return {"active": True, "expires_in": int(remaining)}





# SEC-007: the generic /api/admin/exec endpoint was removed. Arbitrary

# command execution as root through a single API handler is unacceptable

# blast radius ΓÇö any XSS / CSRF / compromised credential that lands inside

# the admin session gets instant RCE with zero auditability of which

# subcommand was actually invoked.

#

# Callers that genuinely need to manage system state use the dedicated,

# narrow endpoints: /api/admin/services, /api/admin/services/<name>/<action>,

# /api/admin/file/read, /api/admin/file/write, and the key-rotation /

# service-management handlers. Each of those validates its arguments against

# a closed allow-list.

#

# A stub is kept behind the old route solely so existing clients get a clear

# 410 Gone instead of a 404 that looks like a routing bug.






def _h_admin_exec(req: "_Handler", _groups: tuple) -> dict:

    """Removed. Use the narrow admin endpoints instead."""

    _require_unlocked()

    _require_admin_active()

    raise _ApiError(

        "/api/admin/exec has been removed. Use /api/admin/services/* or "

        "/api/admin/file/* ΓÇö the generic root-exec endpoint is no longer "

        "available.",

        410,

    )






def _h_admin_services(req: "_Handler", _groups: tuple) -> dict:

    """List all systemd services with their state.



    GET /api/admin/services   ΓÇö Linux only.

    """

    _require_unlocked()

    _require_admin_active()



    if sys.platform != "linux":

        return {"services": [], "note": "Service management is Linux-only."}



    try:

        result = _admin_run(

            [

                "systemctl", "list-units", "--type=service",

                "--all", "--no-pager", "--plain", "--no-legend",

            ],

            timeout=15,

        )

    except _ApiError:

        raise

    except Exception as exc:

        raise _ApiError(f"Failed to list services: {exc}", 500)



    services: list[dict] = []

    for line in result.stdout.decode("utf-8", errors="replace").splitlines():

        parts = line.split(None, 4)

        if len(parts) >= 4:

            services.append({

                "unit":        parts[0],

                "load":        parts[1],

                "active":      parts[2],

                "sub":         parts[3],

                "description": parts[4].strip() if len(parts) > 4 else "",

            })



    return {"services": services}






def _h_admin_service_action(req: "_Handler", groups: tuple) -> dict:

    """Perform an action on a systemd service.



    POST /api/admin/services/<name>/<action>



    Linux only. Valid actions: start, stop, restart, reload, status, enable, disable.

    """

    _require_unlocked()

    _require_admin_active()



    service = groups[0] if groups else ""

    action  = groups[1] if len(groups) > 1 else ""



    if not re.fullmatch(r"[a-zA-Z0-9@._:-]{1,128}", service):

        raise _ApiError("Invalid service name.", 400)

    if action not in _SERVICE_ACTIONS:

        raise _ApiError(

            f"action must be one of: {', '.join(sorted(_SERVICE_ACTIONS))}", 400

        )

    if sys.platform != "linux":

        raise _ApiError("Service management is Linux-only.", 400)



    try:

        result = _admin_run(["systemctl", action, service, "--no-pager"], timeout=30)

    except _ApiError:

        raise

    except subprocess.TimeoutExpired:

        raise _ApiError("Service action timed out.", 504)

    except Exception as exc:

        raise _ApiError(f"Service action failed: {exc}", 500)



    from wireseal.security.audit import AuditLog

    AuditLog(_s._AUDIT_PATH).log(

        "admin-service", {"service": service, "action": action, "rc": result.returncode},

        actor=_session.get("admin_id", "owner"),

    )



    return {

        "ok":         result.returncode == 0,

        "returncode": result.returncode,

        "stdout":     result.stdout.decode("utf-8", errors="replace"),

        "stderr":     result.stderr.decode("utf-8", errors="replace"),

    }






def _h_admin_read_file(req: "_Handler", _groups: tuple) -> dict:

    """Read a file as root from an allowlisted location.



    POST /api/admin/file/read

    Body: {"path": "/etc/wireguard/wg0.conf"}



    SEC-008: ``path`` MUST resolve inside ``_ADMIN_FILE_ROOTS`` (vault dir +

    known WireGuard / nftables / WireSeal state directories on this OS).

    Attempts to read files outside that set ΓÇö ``/etc/shadow``,

    ``/root/.ssh/id_ed25519``, arbitrary user home paths ΓÇö are rejected with

    403 *before* the privileged helper is invoked. Output is also truncated to

    ``_MAX_ADMIN_READ_SIZE`` so a malicious symlink to a huge file can't be

    used to exfiltrate megabytes in one call.

    """

    _require_unlocked()

    _require_admin_active()



    body = req._json()

    # SEC-008: allowlist-gate the path before any subprocess is spawned.

    resolved = _validate_admin_path(body.get("path", ""))

    path_str = str(resolved)



    # SEC-008 follow-up: do NOT rely on "read everything, truncate after".

    # If an attacker planted a symlink inside an allowed root pointing to

    # ``/dev/zero`` or ``/dev/urandom``, a plain ``cat`` would stream

    # unbounded bytes until the 10s timeout fires, allocating gigabytes of

    # process memory in the meantime. Use ``head -c`` to cap the subprocess

    # at source (read +1 byte to detect truncation).

    try:

        result = _admin_run(

            ["head", "-c", str(_MAX_ADMIN_READ_SIZE + 1), "--", path_str],

            timeout=10,

        )

    except _ApiError:

        raise

    except Exception as exc:

        raise _ApiError(f"Read failed: {exc}", 500)



    if result.returncode != 0:

        err = result.stderr.decode("utf-8", errors="replace").strip()

        raise _ApiError(err or "File not found or permission denied.", 404)



    # Detect truncation: we asked for MAX+1 bytes, so if the subprocess

    # returned MAX+1 bytes the file was at least that large.

    truncated     = len(result.stdout) > _MAX_ADMIN_READ_SIZE

    content_bytes = result.stdout[:_MAX_ADMIN_READ_SIZE]



    from wireseal.security.audit import AuditLog

    AuditLog(_s._AUDIT_PATH).log(

        "admin-read-file",

        {"path": path_str, "truncated": truncated, "bytes": len(content_bytes)},

        actor=_session.get("admin_id", "owner"),

    )



    return {

        "path":       path_str,

        "content":    content_bytes.decode("utf-8", errors="replace"),

        "truncated":  truncated,

    }






def _h_admin_write_file(req: "_Handler", _groups: tuple) -> dict:

    """Write content to an allowlisted file as root.



    POST /api/admin/file/write

    Body: {"path": "/etc/wireguard/wg0.conf", "content": "..."}



    SEC-008: ``path`` must resolve inside ``_ADMIN_FILE_ROOTS``. Writes

    outside the allowlist return 403 and never reach ``tee``. Written content

    is also size-capped to the request body limit enforced in ``_json``.

    """

    _require_unlocked()

    _require_admin_active()



    body    = req._json()

    # SEC-008: resolve + allowlist-check before we spawn a privileged helper.

    resolved = _validate_admin_path(body.get("path", ""))

    path_str = str(resolved)

    content  = body.get("content", "")

    if not isinstance(content, str):

        raise _ApiError("content must be a string", 400)



    try:

        result = _admin_run(

            ["tee", "--", path_str],

            stdin_extra=content.encode("utf-8"),

            timeout=10,

        )

    except _ApiError:

        raise

    except Exception as exc:

        raise _ApiError(f"Write failed: {exc}", 500)



    if result.returncode != 0:

        err = result.stderr.decode("utf-8", errors="replace").strip()

        raise _ApiError(err or "Write failed.", 500)



    from wireseal.security.audit import AuditLog

    AuditLog(_s._AUDIT_PATH).log(

        "admin-write-file",

        {"path": path_str, "bytes": len(content)},

        actor=_session.get("admin_id", "owner"),

    )



    return {"ok": True, "path": path_str}





# ---------------------------------------------------------------------------

# Key rotation API endpoints (Phase 7)

# ---------------------------------------------------------------------------






def _h_rotate_server_keys(req: "_Handler", _groups: tuple) -> dict:

    """Rotate the server keypair and update all client configs.



    POST /api/rotate-server-keys



    Generates a new server keypair, rebuilds ALL client configs with the

    new server public key, validates everything, writes atomically,

    reloads WireGuard, and updates the vault.

    """

    _require_unlocked()

    _require_server_mode()

    # SEC-TOTP-05: require TOTP before rotating server keys. This operation

    # disrupts ALL connected clients ΓÇö an attacker with an unlocked session

    # must still prove TOTP possession to trigger mass-eviction.

    _require_confirmation(req._json())



    with _lock:

        vault      = _session["vault"]

        passphrase = _session["passphrase"]

        _actor_id  = _session.get("admin_id", "owner")



    from wireseal.core.keygen         import generate_keypair

    from wireseal.core.config_builder import ConfigBuilder

    from wireseal.security.validator  import validate_client_config, validate_server_config

    from wireseal.security.atomic     import atomic_write

    from wireseal.security.audit      import AuditLog

    from wireseal.platform.detect     import get_adapter



    with vault.open(passphrase) as state:

        clients = list(state.clients.keys())

        client_count = len(clients)



        # Generate new server keypair

        new_server_priv, new_server_pub = generate_keypair()

        new_server_pub_str  = new_server_pub.decode("ascii")

        new_server_priv_str = new_server_priv.expose_secret().decode("ascii")



        server_data   = state.server

        server_port   = server_data["port"]

        server_ip     = server_data["ip"]

        subnet        = state.ip_pool.get("subnet", "192.168.1.0/24")

        prefix_length = int(subnet.split("/")[1])



        builder     = ConfigBuilder()

        clients_dir = _VAULT_DIR / "clients"

        clients_dir.mkdir(parents=True, exist_ok=True)

        adapter = get_adapter()



        # Rebuild all client configs with new server public key

        new_client_hashes: dict[str, str] = {}

        updated_configs: dict[str, str] = {}

        for cname in clients:

            cdata = state.clients[cname]

            client_ip       = cdata["ip"]

            dns_server      = cdata.get("dns_server", "1.1.1.1, 8.8.8.8")

            server_endpoint = _resolve_client_endpoint(server_data)

            cpriv_str       = _extract(cdata.get("private_key", ""))

            cpsk_str        = _extract(cdata.get("psk", ""))



            updated_cfg = builder.render_client_config(

                client_private_key=cpriv_str,

                client_ip=client_ip,

                dns_server=dns_server,

                server_public_key=new_server_pub_str,

                psk=cpsk_str,

                server_endpoint=server_endpoint,

                mtu=_detect_mtu(),

                allowed_ips=cdata.get("allowed_ips", "0.0.0.0/0"),

            )



            try:

                validate_client_config({

                    "private_key": cpriv_str, "psk": cpsk_str,

                    "ip": client_ip, "dns_server": dns_server,

                    "server_public_key": new_server_pub_str,

                    "endpoint": server_endpoint,

                })

            except ValueError as exc:

                new_server_priv.wipe()

                raise _ApiError(

                    f"Client config validation failed for '{cname}': {exc}", 500

                ) from exc



            client_encoded = updated_cfg.encode("utf-8")

            atomic_write(clients_dir / f"{cname}.conf", client_encoded, mode=0o600)

            new_client_hashes[cname] = hashlib.sha256(client_encoded).hexdigest()

            updated_configs[cname] = updated_cfg



        # Build new server config

        peers_for_server = []

        for cname in clients:

            cdata = state.clients[cname]

            peers_for_server.append({

                "name": cname,

                "public_key": _extract(cdata.get("public_key", "")),

                "psk": _extract(cdata.get("psk", "")),

                "ip": cdata["ip"],

            })



        try:

            validate_server_config({

                "private_key": new_server_priv_str, "public_key": "",

                "port": server_port, "subnet": subnet,

                "clients": peers_for_server,

            })

        except ValueError as exc:

            new_server_priv.wipe()

            raise _ApiError(f"Server config validation failed: {exc}", 500) from exc



        new_server_config = builder.render_server_config(

            server_private_key=new_server_priv_str,

            server_ip=server_ip,

            prefix_length=prefix_length,

            server_port=server_port,

            clients=peers_for_server,

        )

        server_encoded = new_server_config.encode("utf-8")

        server_conf_path = adapter.get_config_path(_WG_IFACE)

        atomic_write(server_conf_path, server_encoded, mode=0o600)

        server_hash = hashlib.sha256(server_encoded).hexdigest()



        # Reload WireGuard

        wg_warning = _reload_wireguard(_WG_IFACE)



        # Update vault state

        state.server["private_key"] = new_server_priv_str

        state.server["public_key"]  = new_server_pub_str

        state.integrity["server"]   = server_hash

        for cname, chash in new_client_hashes.items():

            state.integrity[f"client-{cname}"] = chash

        vault.save(state, passphrase)



        AuditLog(_s._AUDIT_PATH).log(

            "rotate-server-keys", {"client_count": client_count}, actor=_actor_id,

        )



        with _lock:

            _session["cache"] = _refresh_cache(state)



    result: dict = {"ok": True, "client_count": client_count}

    if wg_warning:

        result["warning"] = wg_warning

    return result





# ---------------------------------------------------------------------------

# Multi-admin management helpers and handlers

# ---------------------------------------------------------------------------






def _require_owner() -> None:

    """Raise 403 if current session does not have owner role."""

    if _session.get("admin_role") != "owner":

        raise _ApiError("owner role required", 403)






def _h_list_admins(req: "_Handler", _groups: tuple) -> dict:

    """GET /api/admins ΓÇö list all admins."""

    _require_unlocked()

    with _lock:

        admins_data = (_session["cache"] or {}).get("admins", {})

    result = []

    for aid, info in admins_data.items():

        result.append({

            "id": aid,

            "role": info.get("role", "admin"),

            "totp_enrolled": info.get("totp_secret_b32") is not None,

            "backup_codes_remaining": len(info.get("backup_codes", [])),

            "last_unlock": info.get("last_unlock"),

        })

    return {"admins": result}






def _h_add_admin(req: "_Handler", _groups: tuple) -> dict:

    """POST /api/admins ΓÇö add a new admin keyslot."""

    _require_unlocked()

    _require_owner()

    body = req._json()

    # SEC-TOTP-02: require TOTP confirmation before adding admin keyslots.

    # Adding a new admin is permanent privilege escalation ΓÇö an attacker

    # with an unlocked session must still prove TOTP possession.

    _require_confirmation(body)

    admin_id   = body.get("admin_id", "").strip()

    passphrase = body.get("passphrase", "")

    role       = body.get("role", "admin")

    if not admin_id or not passphrase:

        raise _ApiError("admin_id and passphrase required", 400)

    if len(passphrase) < 12:

        raise _ApiError("passphrase must be at least 12 characters", 400)

    if role not in ("owner", "admin", "readonly"):

        raise _ApiError("role must be owner, admin, or readonly", 400)



    with _lock:

        vault     = _session["vault"]

        sess_pass = _session["passphrase"]

        acting_id = _session.get("admin_id", "owner")



    new_bytes = bytearray(passphrase.encode())

    try:

        with vault.open(sess_pass, admin_id=acting_id) as state:

            vault.add_keyslot(admin_id, new_bytes, role=role)

            # add_keyslot already syncs state.data["admins"] but ensure entry is complete

            state.data.setdefault("admins", {})[admin_id] = {

                "role": role,

                "created_at": _utcnow_iso(),

                "totp_secret_b32": None,

                "totp_enrolled_at": None,

                "backup_codes": [],

                "last_unlock": None,

            }

            with _lock:

                _session["cache"] = _refresh_cache(state)

    except _ApiError:

        raise

    except Exception as exc:

        raise _ApiError(str(exc), 409)

    finally:

        from wireseal.security.secrets_wipe import wipe_bytes

        wipe_bytes(new_bytes)



    from wireseal.security.audit import AuditLog

    AuditLog(_s._AUDIT_PATH).log("add-admin", {

        "target": admin_id, "role": role, "actor": acting_id,

    })

    return {"ok": True, "admin_id": admin_id}






def _h_remove_admin(req: "_Handler", groups: tuple) -> dict:

    """DELETE /api/admins/<id> ΓÇö remove an admin keyslot."""

    _require_unlocked()

    _require_owner()

    target_id = (groups[0] if groups else "").strip()

    if not target_id:

        raise _ApiError("admin_id is required", 400)



    with _lock:

        vault     = _session["vault"]

        sess_pass = _session["passphrase"]

        acting_id = _session.get("admin_id", "owner")



    if target_id == acting_id:

        raise _ApiError("cannot remove yourself", 409)



    # Check if target is last owner

    with _lock:

        admins = (_session["cache"] or {}).get("admins", {})

    owners = [aid for aid, info in admins.items() if info.get("role") == "owner"]

    if target_id in owners and len(owners) == 1:

        raise _ApiError("cannot remove the last owner", 409)



    # SEC-TOTP-04: require TOTP for admin removal (DELETE has no body, read

    # totp_code from query string). This prevents admin deletion via CSRF or

    # unattended unlocked session.

    from wireseal.security.totp import verify_totp, b32_to_secret

    from wireseal.security.secret_types import SecretBytes

    with _lock:

        cache = _session.get("cache") or {}

    admin_info = (cache.get("admins", {}) or {}).get(acting_id, {})

    totp_b32 = admin_info.get("totp_secret_b32")

    if totp_b32 is not None:

        try:

            from urllib.parse import urlsplit, parse_qs as _parse_qs_del

            q = urlsplit(getattr(req, "path", "") or "").query

            totp_code = (_parse_qs_del(q).get("totp_code") or [None])[0]

        except Exception:

            totp_code = None

        if not totp_code:

            raise _ApiError("totp_code required to remove admin. Add ?totp_code=... to the URL.", 401)

        _check_totp_rate_limit(acting_id)

        if isinstance(totp_b32, SecretBytes):

            totp_b32_str = bytes(totp_b32.expose_secret()).decode("utf-8")

        else:

            totp_b32_str = str(totp_b32)

        secret_raw = b32_to_secret(totp_b32_str)

        with _lock:

            used_set = _totp_used_codes.setdefault(acting_id, set())

        ok = verify_totp(secret_raw, str(totp_code), used_codes=used_set)

        if not ok:

            from wireseal.security.audit import AuditLog

            AuditLog(_s._AUDIT_PATH).log("totp-failed", {"admin_id": acting_id}, actor=acting_id)

            _record_totp_failure(acting_id)

            raise _ApiError("Invalid TOTP code.", 401)



    try:

        with vault.open(sess_pass, admin_id=acting_id) as state:

            vault.remove_keyslot(target_id)

            state.data.get("admins", {}).pop(target_id, None)

            with _lock:

                _session["cache"] = _refresh_cache(state)

    except _ApiError:

        raise

    except Exception as exc:

        raise _ApiError(str(exc), 404)



    from wireseal.security.audit import AuditLog

    AuditLog(_s._AUDIT_PATH).log("remove-admin", {

        "target": target_id, "actor": acting_id,

    })

    return {"ok": True}






def _h_change_admin_passphrase(req: "_Handler", groups: tuple) -> dict:

    """POST /api/admins/<id>/change-passphrase ΓÇö change an admin's passphrase.



    Owner can change any admin's passphrase without knowing the old one.

    Non-owner must provide old_passphrase and can only change their own.

    """

    _require_unlocked()

    target_id = (groups[0] if groups else "").strip()

    if not target_id:

        raise _ApiError("admin_id is required", 400)



    with _lock:

        vault       = _session["vault"]

        sess_pass   = _session["passphrase"]

        acting_id   = _session.get("admin_id", "owner")

        acting_role = _session.get("admin_role", "owner")



    # Non-owner may only change their own passphrase

    if acting_role != "owner" and acting_id != target_id:

        raise _ApiError("may only change your own passphrase", 403)



    body = req._json()

    # SEC-TOTP-03: require TOTP before changing any admin passphrase.

    # Owner changing another admin's passphrase bypasses the old-passphrase

    # check ΓÇö this must be gated by TOTP to prevent lateral movement from

    # an unattended unlocked session.

    _require_confirmation(body)

    new_passphrase = body.get("new_passphrase", "")

    old_passphrase = body.get("old_passphrase", "")

    if not new_passphrase:

        raise _ApiError("new_passphrase required", 400)

    if len(new_passphrase) < 12:

        raise _ApiError("new_passphrase must be at least 12 characters", 400)



    # Non-owner changing their own passphrase must provide old_passphrase

    if acting_role != "owner" and not old_passphrase:

        raise _ApiError("old_passphrase required for non-owner passphrase change", 400)



    new_bytes = bytearray(new_passphrase.encode())

    old_bytes = bytearray(old_passphrase.encode()) if old_passphrase else bytearray()

    try:

        with vault.open(sess_pass, admin_id=acting_id) as _state:

            if acting_role == "owner" and acting_id != target_id:

                # Owner changing another admin's passphrase: remove + re-add using master key

                from wireseal.security.keyslot import create_keyslot

                store = vault._session_store

                if store is None:

                    raise _ApiError("Vault is not FORMAT_VERSION 3; multi-admin not active", 409)

                slot = store.find(target_id)

                if slot is None:

                    raise _ApiError(f"No keyslot for admin '{target_id}'", 404)

                new_slot = create_keyslot(

                    target_id, new_bytes, vault._session_master_key, role=slot.role

                )

                store.keyslots = [new_slot if s.admin_id == target_id else s

                                  for s in store.keyslots]

            else:

                vault.change_keyslot_passphrase(target_id, old_bytes, new_bytes)

    except _ApiError:

        raise

    except Exception as exc:

        raise _ApiError(str(exc), 400)

    finally:

        from wireseal.security.secrets_wipe import wipe_bytes

        wipe_bytes(new_bytes)

        wipe_bytes(old_bytes)



    from wireseal.security.audit import AuditLog

    AuditLog(_s._AUDIT_PATH).log("change-passphrase", {

        "target": target_id, "actor": acting_id,

    })

    return {"ok": True}





# ---------------------------------------------------------------------------

# TOTP handlers

# ---------------------------------------------------------------------------





