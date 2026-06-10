"""Client management handlers."""

import logging

from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _name

_clients_log = logging.getLogger("wireseal.api.clients")

def _h_heartbeat(req: "_Handler", groups: tuple) -> dict:
    """Reset TTL for a client. Rate-limited to 1 reset per 30s per client.

    SEC-015: authenticated by a per-client bearer token presented via the
    ``X-WireSeal-Heartbeat`` header. The token is a 32-byte random value
    assigned when the client is added and returned only to callers who
    already hold the vault passphrase (via /api/client/configs/<name>).
    This prevents any unauthenticated local process from defeating ZTNA
    TTL revocation by pinging heartbeat indefinitely.

    Legacy clients (created before SEC-015) have no stored token; they
    receive one lazily on the next authenticated config fetch, and
    heartbeat rejects them with 401 until that migration happens.
    """
    import time as _time
    import hmac as _hmac
    name = groups[0]

    # Rate limiting â€" guard _heartbeat_cooldown with _lock for thread safety.
    now = _time.time()
    with _lock:
        last = _heartbeat_cooldown.get(name, 0)
        if now - last < _HEARTBEAT_MIN_INTERVAL:
            raise _ApiError("Heartbeat rate limit exceeded.", 429)

    with _lock:
        cache      = _session.get("cache") or {}
        vault      = _session.get("vault")
        passphrase = _session.get("passphrase")
        admin_id   = _session.get("admin_id", "owner")

    if vault is None:
        raise _ApiError("Server vault is locked.", 503)

    client = cache.get("clients", {}).get(name)
    if not client:
        raise _ApiError("Client not found.", 404)

    # SEC-015: authenticate via X-WireSeal-Heartbeat header
    presented = req.headers.get("X-WireSeal-Heartbeat", "") if hasattr(req, "headers") else ""
    stored    = client.get("heartbeat_token") or ""
    if not stored:
        raise _ApiError(
            "Client has no heartbeat token -- fetch config while vault is "
            "unlocked to provision one.", 401,
        )
    if not presented or not _hmac.compare_digest(presented, stored):
        # Never reveal whether the header was missing vs. wrong.
        raise _ApiError("Unauthorized heartbeat.", 401)

    if client.get("permanent", True):
        return {"ok": True, "permanent": True}

    ttl_seconds = client.get("ttl_seconds") or 86400
    new_expires = now + ttl_seconds
    with _lock:
        _heartbeat_cooldown[name] = now

    # Update vault
    with vault.open(passphrase, admin_id=admin_id) as state:
        if name in state.clients:
            state.clients[name]["ttl_expires_at"] = new_expires
        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, admin_id)

    from wireseal.security.audit import AuditLog
    try:
        AuditLog(_s._AUDIT_PATH).log("heartbeat", {"name": name, "expires_at": new_expires}, actor="system")
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)

    return {"ok": True, "expires_at": new_expires}


def _h_set_client_ttl(req: "_Handler", groups: tuple) -> dict:
    """Set or clear TTL for an existing client. Requires unlocked vault."""
    _require_unlocked()
    name = groups[0]
    body = req._json()
    permanent   = body.get("permanent", False)
    ttl_seconds = body.get("ttl_seconds")

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        admin_id   = _session.get("admin_id", "owner")
        cache      = _session.get("cache") or {}

    if name not in cache.get("clients", {}):
        raise _ApiError("Client not found.", 404)

    import time as _time
    with vault.open(passphrase, admin_id=admin_id) as state:
        if name not in state.clients:
            raise _ApiError("Client not found.", 404)
        client = state.clients[name]
        if permanent or ttl_seconds == 0:
            client["permanent"]      = True
            client["ttl_seconds"]    = None
            client["ttl_expires_at"] = None
            result = {"ok": True, "permanent": True}
        else:
            client["permanent"]      = False
            client["ttl_seconds"]    = int(ttl_seconds)
            client["ttl_expires_at"] = _time.time() + int(ttl_seconds)
            result = {"ok": True, "expires_at": client["ttl_expires_at"]}
        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, admin_id)
    return result


# ---------------------------------------------------------------------------
# Client access control management endpoints
# ---------------------------------------------------------------------------


def _h_get_client_details(req: "_Handler", groups: tuple) -> dict:

    """GET /api/clients/{name}/details â€" full client info including access control."""
    _require_unlocked()
    _require_server_mode()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    import time as _time
    from wireseal.security.access_control import check_expiry_status, expiry_warning_days

    with _lock:
        cache = _session.get("cache") or {}

    clients = cache.get("clients", {})
    if name not in clients:
        raise _ApiError(f"Client '{name}' not found.", 404)

    d = clients[name]
    now = _time.time()
    status = check_expiry_status(d, now)
    warn_days = expiry_warning_days(d, now)
    expires_in = None
    if not d.get("permanent", True) and d.get("ttl_expires_at"):
        expires_in = max(0, int(d["ttl_expires_at"] - now))

    return {
        "name":               name,
        "ip":                 d["ip"],
        "access_level":       d.get("access_level", "standard"),
        "status":             status.value,
        "description":        d.get("description", ""),
        "privileges":         d.get("privileges"),
        "permanent":          d.get("permanent", True),
        "ttl_seconds":        d.get("ttl_seconds"),
        "ttl_expires_at":     d.get("ttl_expires_at"),
        "expires_in_seconds": expires_in,
        "warning_days":       warn_days,
        "auto_revoke":        d.get("auto_revoke", True),
        "created_at":         d.get("created_at"),
    }


def _h_edit_client(req: "_Handler", groups: tuple) -> dict:

    """PUT /api/clients/{name} â€" edit access level, privileges, description.

    Requires TOTP or passphrase confirmation.
    """
    _require_unlocked()
    _require_server_mode()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    body = req._json()
    _require_confirmation(body, allow_session_skip=True)

    from wireseal.security.access_control import (
        VALID_ACCESS_LEVELS, validate_access_level_change,
        default_privileges, merge_privileges,
    )
    from wireseal.security.audit import AuditLog


def _h_server_status(req: "_Handler", _groups: tuple) -> dict:

    """GET /api/server/status â€" return server runtime status."""
    _require_unlocked()
    _require_server_mode()
    wireguard = _get_wireguard_adapter()
    return {
        "server_running": wireguard.is_running(),
        "interface": _WIREGUARD_INTERFACE,
    }


def _h_extend_client(req: "_Handler", groups: tuple) -> dict:

    """POST /api/clients/{name}/extend â€" extend or change expiry.

    Requires TOTP or passphrase confirmation.
    Body: { extend_seconds, expires_at, remove_expiry, totp_code|confirm_passphrase }
    """
    _require_unlocked()
    _require_server_mode()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    body = req._json()
    _require_confirmation(body, allow_session_skip=True)

    from wireseal.security.audit import AuditLog
    import time as _time

    extend_seconds = body.get("extend_seconds")
    new_expires_at = body.get("expires_at")
    remove_expiry = body.get("remove_expiry", False)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id  = _session.get("admin_id", "owner")
        cache      = _session.get("cache") or {}

    if name not in cache.get("clients", {}):
        raise _ApiError(f"Client '{name}' not found.", 404)

    result = {}
    with vault.open(passphrase, admin_id=_actor_id) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)
        client = state.clients[name]

        old_expires = client.get("ttl_expires_at")

        if remove_expiry:
            client["permanent"] = True
            client["ttl_seconds"] = None
            client["ttl_expires_at"] = None
            result = {"ok": True, "permanent": True}
        elif extend_seconds is not None:
            secs = int(extend_seconds)
            if secs <= 0:
                raise _ApiError("extend_seconds must be positive.", 400)
            base = client.get("ttl_expires_at") or _time.time()
            # If already expired, extend from now
            if base < _time.time():
                base = _time.time()
            client["permanent"] = False
            client["ttl_expires_at"] = base + secs
            client["ttl_seconds"] = secs
            # Re-activate if was expired
            if client.get("status") == "expired":
                client["status"] = "active"
            result = {"ok": True, "expires_at": client["ttl_expires_at"]}
        elif new_expires_at is not None:
            ts = float(new_expires_at)
            if ts <= _time.time():
                raise _ApiError("expires_at must be in the future.", 400)
            client["permanent"] = False
            client["ttl_expires_at"] = ts
            client["ttl_seconds"] = int(ts - _time.time())
            if client.get("status") == "expired":
                client["status"] = "active"
            result = {"ok": True, "expires_at": ts}
        else:
            raise _ApiError(
                "Provide extend_seconds, expires_at, or remove_expiry.", 400
            )

        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, _actor_id)
    AuditLog(_s._AUDIT_PATH).log(
        "client-extended",
        {"name": name, "old_expires": old_expires, "new_expires": client.get("ttl_expires_at")},
        actor=_actor_id,
    )
    return result


def _h_revoke_client(req: "_Handler", groups: tuple) -> dict:

    """POST /api/clients/{name}/revoke â€" immediately revoke a client.

    Removes the WireGuard peer but keeps the client record with status=revoked.
    Requires TOTP or passphrase confirmation.
    """
    _require_unlocked()
    _require_server_mode()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    body = req._json()
    _require_confirmation(body, allow_session_skip=True)

    from wireseal.security.audit import AuditLog

    actor_level = _get_actor_access_level()

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id  = _session.get("admin_id", "owner")
        cache      = _session.get("cache") or {}

    if name not in cache.get("clients", {}):
        raise _ApiError(f"Client '{name}' not found.", 404)

    with vault.open(passphrase, admin_id=_actor_id) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)
        client = state.clients[name]

        # Check permission
        from wireseal.security.access_control import AccessLevel
        target_level = AccessLevel.from_str(client.get("access_level", "standard"))
        actor = AccessLevel.from_str(actor_level)
        if not actor.can_manage(target_level):
            raise _ApiError("Insufficient privileges to revoke this client.", 403)

        if client.get("status") == "revoked":
            raise _ApiError("Client is already revoked.", 409)

        # Remove WireGuard peer (but keep record)
        pubkey = client.get("public_key", "")
        from wireseal.security.secret_types import SecretBytes
        if isinstance(pubkey, SecretBytes):
            pubkey = pubkey.expose_secret().decode("ascii")
        if pubkey:
            import subprocess
            cmd = [_resolve_wg_tool("wg"), "set", _WG_IFACE, "peer", str(pubkey), "remove"]
            if sys.platform != "win32":
                cmd = _sudo(cmd)
            try:
                subprocess.run(cmd, capture_output=True, timeout=5, creationflags=_SP_FLAGS)
            except Exception as exc:
                logging.getLogger("wireseal.security").warning("Failed to remove WireGuard peer for revoked client %s: %s", name, exc)

        client["status"] = "revoked"
        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, _actor_id)
    AuditLog(_s._AUDIT_PATH).log("client-revoked", {"name": name}, actor=_actor_id)
    return {"ok": True, "name": name, "status": "revoked"}


def _h_suspend_client(req: "_Handler", groups: tuple) -> dict:

    """POST /api/clients/{name}/suspend â€" suspend or unsuspend a client.

    Suspended clients have their WireGuard peer removed but can be restored.
    Body: { action: "suspend"|"unsuspend", totp_code|confirm_passphrase }
    """
    _require_unlocked()
    _require_server_mode()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    body = req._json()
    _require_confirmation(body, allow_session_skip=True)

    action = body.get("action", "suspend")
    if action not in ("suspend", "unsuspend"):
        raise _ApiError("action must be 'suspend' or 'unsuspend'.", 400)

    from wireseal.security.audit import AuditLog
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.platform.detect import get_adapter

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id  = _session.get("admin_id", "owner")

    with vault.open(passphrase, admin_id=_actor_id) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)
        client = state.clients[name]

        if action == "suspend":
            if client.get("status") in ("revoked", "suspended"):
                raise _ApiError(f"Client is already {client['status']}.", 409)
            # Remove peer
            pubkey = client.get("public_key", "")
            from wireseal.security.secret_types import SecretBytes
            if isinstance(pubkey, SecretBytes):
                pubkey = pubkey.expose_secret().decode("ascii")
            if pubkey:
                import subprocess
                cmd = [_resolve_wg_tool("wg"), "set", _WG_IFACE, "peer", str(pubkey), "remove"]
                if sys.platform != "win32":
                    cmd = _sudo(cmd)
                try:
                    subprocess.run(cmd, capture_output=True, timeout=5, creationflags=_SP_FLAGS)
                except Exception as exc:
                    logging.getLogger("wireseal.security").warning("Failed to remove WireGuard peer for suspended client %s: %s", name, exc)
            client["status"] = "suspended"
        else:  # unsuspend
            if client.get("status") != "suspended":
                raise _ApiError("Client is not suspended.", 409)
            client["status"] = "active"
            # Re-add peer by regenerating server config with all active peers
            peers = [
                {
                    "name":       n,
                    "public_key": _extract(d["public_key"]),
                    "psk":        _extract(d["psk"]),
                    "ip":         d["ip"],
                }
                for n, d in state.clients.items()
                if d.get("status", "active") == "active"
            ]
            server_config = ConfigBuilder().render_server_config(
                server_private_key=_extract(state.server["private_key"]),
                server_ip=state.server["ip"],
                prefix_length=int(state.ip_pool["subnet"].split("/")[1]),
                server_port=state.server["port"],
                clients=peers,
            )
            try:
                adapter = get_adapter()
                adapter.check_privileges()
                adapter.deploy_config(server_config)
                _reload_wireguard()
            except Exception as exc:
                logging.getLogger("wireseal.security").warning("Unsuspend deploy failed for client %s: %s", name, exc)

        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, _actor_id)
    AuditLog(_s._AUDIT_PATH).log(
        f"client-{action}ed", {"name": name, "action": action}, actor=_actor_id
    )
    return {"ok": True, "name": name, "status": client["status"]}


def _h_list_clients(req: "_Handler", _groups: tuple) -> list:

    _require_unlocked()
    import time as _time
    from wireseal.security.access_control import check_expiry_status
    with _lock:
        cache = _session["cache"] or {}
    now = _time.time()
    result = []
    for n, d in cache.get("clients", {}).items():
        status = check_expiry_status(d, now).value
        expires_in = None
        if not d.get("permanent", True) and d.get("ttl_expires_at"):
            expires_in = max(0, int(d["ttl_expires_at"] - now))
        result.append({
            "name":               n,
            "ip":                 d["ip"],
            "permanent":          d.get("permanent", True),
            "ttl_seconds":        d.get("ttl_seconds"),
            "ttl_expires_at":     d.get("ttl_expires_at"),
            "expires_in_seconds": expires_in,
            "access_level":       d.get("access_level", "standard"),
            "status":             status,
            "description":        d.get("description", ""),
            "created_at":         d.get("created_at"),
        })
    return result


def _h_add_client(req: "_Handler", _groups: tuple) -> dict:

    _require_unlocked()
    _require_server_mode()
    import time as _time
    with _lock:
        admin_id = _session.get("admin_id", "owner")
        now = _time.time()
        timestamps = _CLIENT_CREATIONS.setdefault(admin_id, [])
        timestamps[:] = [t for t in timestamps if now - t < 3600]
        if len(timestamps) >= _CLIENT_CREATION_LIMIT:
            raise _ApiError("Client creation rate limit exceeded (max 50/hour).", 429)
        timestamps.append(now)
    body = req._json()
    name = body.get("name", "").strip()
    if not name:
        raise _ApiError("name is required", 400)
    if not re.fullmatch(r"^[a-zA-Z0-9-]{1,32}$", name):
        raise _ApiError(
            "Name must be alphanumeric + hyphens only, max 32 chars", 400
        )

    tunnel_mode = body.get("tunnel_mode", "split-vpn")
    if tunnel_mode not in ("split-lan", "split-vpn", "full"):
        raise _ApiError("tunnel_mode must be 'split-lan', 'split-vpn', or 'full'.", 400)

    # MTU: user override â†’ server-detected â†’ 1280 safe default
    req_mtu = body.get("mtu")
    if req_mtu is not None:
        req_mtu = int(req_mtu)
        if req_mtu < 1280 or req_mtu > 1420:
            raise _ApiError("mtu must be between 1280 and 1420.", 400)

    # Access control fields (backward-compatible â€" all optional)
    access_level = body.get("access_level", "standard")
    from wireseal.security.access_control import (
        VALID_ACCESS_LEVELS, build_client_access_fields, compute_expires_at,
    )
    if access_level not in VALID_ACCESS_LEVELS:
        raise _ApiError(
            f"access_level must be one of: {', '.join(VALID_ACCESS_LEVELS)}", 400
        )
    client_description = body.get("description", "")
    client_privileges = body.get("privileges")
    auto_revoke = body.get("auto_revoke", True)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id  = _session.get("admin_id", "owner")

    from wireseal.core.keygen         import generate_keypair
    from wireseal.core.psk            import generate_psk
    from wireseal.core.ip_pool        import IPPool
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.atomic     import atomic_write
    from wireseal.security.audit      import AuditLog
    from wireseal.platform.detect     import get_adapter

    allocated_ip = ""
    with vault.open(passphrase) as state:
        if name in state.clients:
            raise _ApiError(f"Client '{name}' already exists.", 409)

        priv_key, pub_key_bytes = generate_keypair()
        pub_key_str  = pub_key_bytes.decode("ascii")
        priv_key_str = priv_key.expose_secret().decode("ascii")

        psk     = generate_psk()
        psk_str = psk.expose_secret().decode("ascii")

        pool = IPPool(state.ip_pool["subnet"])
        pool.load_state(state.ip_pool.get("allocated", {}))
        allocated_ip = pool.allocate(name)

        server_endpoint = _resolve_client_endpoint(state.server)
        server_ip       = state.server["ip"]
        server_pub_key  = _extract(state.server["public_key"])

        vpn_subnet  = state.ip_pool.get("subnet", "192.168.1.0/24")
        lan_subnet  = state.server.get("lan_subnet", "")
        lan_gateway = state.server.get("lan_gateway", "")

        # Re-detect LAN subnet and gateway if not stored
        if tunnel_mode == "split-lan":
            try:
                adapter = get_adapter()
                if not lan_subnet:
                    lan_subnet = adapter.detect_lan_subnet()
                    if lan_subnet:
                        state.server["lan_subnet"] = lan_subnet
                        _session["cache"]["server"]["lan_subnet"] = lan_subnet
                if not lan_gateway:
                    lan_gateway = adapter.detect_default_gateway()
                    if lan_gateway:
                        state.server["lan_gateway"] = lan_gateway
                        _session["cache"]["server"]["lan_gateway"] = lan_gateway
            except (OSError, ValueError, Exception) as e:
                _clients_log.debug("LAN detection failed during add-client", exc_info=True)

        # Compute AllowedIPs based on tunnel_mode:
        #   full      - route ALL traffic through VPN (0.0.0.0/0)
        #   split-vpn - route only VPN subnet through tunnel (internet direct)
        #   split-lan - route VPN subnet + server LAN through tunnel
        if tunnel_mode == "full":
            allowed_ips = "0.0.0.0/0"
        elif tunnel_mode == "split-lan":
            parts = [vpn_subnet]
            if lan_subnet:
                parts.append(lan_subnet)
            allowed_ips = ", ".join(parts)
        else:  # split-vpn (default)
            allowed_ips = vpn_subnet

        builder       = ConfigBuilder()
        client_mtu    = req_mtu if req_mtu is not None else _detect_mtu()
        client_dns    = _dns_for_tunnel_mode(tunnel_mode, lan_subnet, lan_gateway)
        client_config = builder.render_client_config(
            client_private_key=priv_key_str,
            client_ip=allocated_ip,
            dns_server=client_dns,
            server_public_key=server_pub_key,
            psk=psk_str,
            server_endpoint=server_endpoint,
            mtu=client_mtu,
            allowed_ips=allowed_ips,
        )

        clients_dir     = _s._VAULT_DIR / "clients"
        clients_dir.mkdir(parents=True, exist_ok=True)
        client_conf_path = clients_dir / f"{name}.conf"
        atomic_write(client_conf_path, client_config.encode(), mode=0o600)

        config_hash = hashlib.sha256(client_config.encode()).hexdigest()

        peers = [
            {
                "name":       n,
                "public_key": _extract(d["public_key"]),
                "psk":        _extract(d["psk"]),
                "ip":         d["ip"],
            }
            for n, d in state.clients.items()
        ]
        peers.append({
            "name":       name,
            "public_key": pub_key_str,
            "psk":        psk_str,
            "ip":         allocated_ip,
        })

        server_config = builder.render_server_config(
            server_private_key=_extract(state.server["private_key"]),
            server_ip=server_ip,
            prefix_length=int(state.ip_pool["subnet"].split("/")[1]),
            server_port=state.server["port"],
            clients=peers,
        )
        wg_warning = ""
        try:
            adapter = get_adapter()
            adapter.check_privileges()
            adapter.deploy_config(server_config)
            wg_warning = _reload_wireguard()
        except Exception as exc:
            _clients_log.exception("WireGuard setup failed")
            wg_warning = f"WireGuard setup failed: {exc}"

        import time as _time
        ttl_seconds = body.get("ttl_seconds")
        if ttl_seconds is not None and int(ttl_seconds) > 0:
            _ttl_secs = int(ttl_seconds)
            _ttl_expires = _time.time() + _ttl_secs
            _permanent = False
        else:
            _ttl_secs = None
            _ttl_expires = None
            _permanent = True

        # SEC-015: generate a per-client heartbeat bearer token (32 bytes hex).
        import secrets as _secrets_hb
        heartbeat_token = _secrets_hb.token_hex(32)

        # Build access control metadata
        ac_fields = build_client_access_fields(
            access_level=access_level,
            privileges=client_privileges,
            description=client_description,
            ttl_seconds=_ttl_secs,
            expires_at=body.get("expires_at"),
            auto_revoke=auto_revoke,
        )

        state.clients[name] = {
            "private_key":     priv_key_str,
            "public_key":      pub_key_str,
            "psk":             psk_str,
            "ip":              allocated_ip,
            "config_hash":     config_hash,
            "permanent":       _permanent,
            "ttl_seconds":     _ttl_secs,
            "ttl_expires_at":  _ttl_expires,
            "heartbeat_token": heartbeat_token,
            "tunnel_mode":     tunnel_mode,
            "allowed_ips":     allowed_ips,
            "dns_server":      client_dns,
            # Access control fields
            "access_level":    ac_fields["access_level"],
            "privileges":      ac_fields["privileges"],
            "description":     ac_fields["description"],
            "status":          ac_fields["status"],
            "auto_revoke":     ac_fields["auto_revoke"],
            "created_at":      ac_fields["created_at"],
        }
        state.ip_pool["allocated"]        = pool.get_allocated()
        state.integrity[f"client-{name}"] = config_hash
        vault.save(state, passphrase)

        AuditLog(_s._AUDIT_PATH).log(
            "add-client",
            {"name": name, "ip": allocated_ip, "access_level": access_level},
            actor=_actor_id,
        )

        with _lock:
            _session["cache"] = _refresh_cache(state)

    # TOTP gate: if admin has TOTP enrolled, don't return config data yet
    with _lock:
        _cache = _session.get("cache") or {}
    _admins = _cache.get("admins", {}) if _cache else {}
    _admin_info = _admins.get(_actor_id, {})
    if _admin_info.get("totp_secret_b32"):
        return {"name": name, "ip": allocated_ip, "totp_required": True}

    result: dict = {"name": name, "ip": allocated_ip, "access_level": access_level}
    if wg_warning:
        result["warning"] = wg_warning
    return result


def _h_remove_client(req: "_Handler", groups: tuple) -> dict:

    _require_unlocked()
    _require_server_mode()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id  = _session.get("admin_id", "owner")

    from wireseal.core.ip_pool        import IPPool
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.audit      import AuditLog
    from wireseal.platform.detect     import get_adapter

    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)

        revoked_ip = state.clients[name]["ip"]

        peers = [
            {
                "name":       n,
                "public_key": _extract(d["public_key"]),
                "psk":        _extract(d["psk"]),
                "ip":         d["ip"],
            }
            for n, d in state.clients.items()
            if n != name
        ]

        server_config = ConfigBuilder().render_server_config(
            server_private_key=_extract(state.server["private_key"]),
            server_ip=state.server["ip"],
            prefix_length=int(state.ip_pool["subnet"].split("/")[1]),
            server_port=state.server["port"],
            clients=peers,
        )
        try:
            adapter = get_adapter()
            adapter.check_privileges()
            adapter.deploy_config(server_config)
            reload_err = _reload_wireguard()
            if reload_err:
                print(f"[wireseal] remove-client reload warning: {reload_err}",
                      file=sys.stderr)
        except Exception as exc:
            print(f"[wireseal] remove-client reload failed: {exc}",
                  file=sys.stderr)

        pool = IPPool(state.ip_pool["subnet"])
        pool.load_state(state.ip_pool.get("allocated", {}))
        pool.release(revoked_ip)
        state.ip_pool["allocated"] = pool.get_allocated()

        del state.clients[name]
        state.integrity.pop(f"client-{name}", None)
        state.integrity.pop(f"client-{name}_verified", None)

        conf_path = _s._VAULT_DIR / "clients" / f"{name}.conf"
        try:
            conf_path.unlink(missing_ok=True)
        except OSError as _exc:
            logging.getLogger("wireseal").warning("Failed to remove client config file: %s", _exc)

        vault.save(state, passphrase)
        AuditLog(_s._AUDIT_PATH).log("remove-client", {"name": name}, actor=_actor_id)

        with _lock:
            _session["cache"] = _refresh_cache(state)

    return {"ok": True}


def _h_client_qr(req: "_Handler", groups: tuple) -> dict:

    _require_unlocked()
    _require_totp_for_reveal(req)
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id  = _session.get("admin_id", "owner")

    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.audit      import AuditLog

    config_str = ""
    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)
        cdata = state.clients[name]
        _tm = cdata.get("tunnel_mode", "full")
        _ls = state.server.get("lan_subnet", "")
        _lg = state.server.get("lan_gateway", "")
        config_str = ConfigBuilder().render_client_config(
            client_private_key=_extract(cdata["private_key"]),
            client_ip=cdata["ip"],
            dns_server=cdata.get("dns_server") or _dns_for_tunnel_mode(_tm, _ls, _lg),
            server_public_key=_extract(state.server["public_key"]),
            psk=_extract(cdata["psk"]),
            server_endpoint=_resolve_client_endpoint(state.server),
            mtu=_detect_mtu(),
            allowed_ips=cdata.get("allowed_ips", "0.0.0.0/0"),
        )

    try:
        import qrcode
        import qrcode.image.svg

        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(config_str)
        qr.make(fit=True)

        # Try PNG first (needs Pillow), fall back to SVG (no deps)
        try:
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            png_b64 = base64.b64encode(buf.getvalue()).decode()
            img_format = "png"
        except (ImportError, OSError, AttributeError):
            # Pillow not available — use SVG
            img = qr.make_image(image_factory=qrcode.image.svg.SvgPathFillImage)
            buf = io.BytesIO()
            img.save(buf)
            png_b64 = base64.b64encode(buf.getvalue()).decode()
            img_format = "svg+xml"
    except ImportError:
        raise _ApiError("QR code generation unavailable — 'qrcode' package not installed", 500)
    except Exception as _exc:
        _clients_log.warning("QR code generation failed: %s", _exc)
        raise _ApiError("QR code generation failed.", 500)

    AuditLog(_s._AUDIT_PATH).log("export-qr", {"client": name}, actor=_actor_id)
    return {"name": name, "qr_png_b64": png_b64, "format": img_format}


def _h_client_self_config(req: "_Handler", _groups: tuple) -> dict:

    """GET /api/client/self/config â€" Client fetches its own config using heartbeat token.

    Authenticated by the per-client heartbeat token (``X-WireSeal-Heartbeat``
    header). Does NOT require vault unlock, server mode, or TOTP â€" intended
    for machine-to-machine use where the client already holds its secret token.

    Rate-limited to 1 request per 60 seconds per token to prevent brute-force
    enumeration of heartbeat tokens.
    """
    import time as _time
    import hmac as _hmac

    presented = req.headers.get("X-WireSeal-Heartbeat", "") if hasattr(req, "headers") else ""
    if not presented:
        raise _ApiError("X-WireSeal-Heartbeat header is required.", 401)

    # Rate limit per token
    now = _time.time()
    token_hash = hashlib.sha256(presented.encode()).hexdigest()[:16]
    with _lock:
        last = _heartbeat_cooldown.get(f"_self_config_{token_hash}", 0)
        if now - last < 60.0:
            raise _ApiError("Rate limit exceeded. Try again later.", 429)

    with _lock:
        vault = _session.get("vault")
        passphrase = _session.get("passphrase")

    if vault is None or passphrase is None:
        raise _ApiError("Server vault is locked.", 503)

    from wireseal.core.config_builder import ConfigBuilder

    with vault.open(passphrase) as state:
        client_name = None
        cdata = None
        for cname, cdata_raw in state.clients.items():
            stored_token = cdata_raw.get("heartbeat_token", "")
            if stored_token and _hmac.compare_digest(presented, stored_token):
                client_name = cname
                cdata = cdata_raw
                break

        if not client_name or cdata is None:
            raise _ApiError("Client not found or heartbeat token mismatch.", 404)

        _heartbeat_cooldown[f"_self_config_{token_hash}"] = now

        heartbeat_token = cdata.get("heartbeat_token", "")
        _tm = cdata.get("tunnel_mode", "full")
        _ls = state.server.get("lan_subnet", "")
        _lg = state.server.get("lan_gateway", "")
        config_str = ConfigBuilder().render_client_config(
            client_private_key=_extract(cdata["private_key"]),
            client_ip=cdata["ip"],
            dns_server=cdata.get("dns_server") or _dns_for_tunnel_mode(_tm, _ls, _lg),
            server_public_key=_extract(state.server["public_key"]),
            psk=_extract(cdata["psk"]),
            server_endpoint=_resolve_client_endpoint(state.server),
            mtu=_detect_mtu(),
            allowed_ips=cdata.get("allowed_ips", "0.0.0.0/0"),
        )

    from wireseal.security.audit import AuditLog
    try:
        AuditLog(_s._AUDIT_PATH).log(
            "client-self-config",
            {"name": client_name},
            actor="system",
        )
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)

    return {"name": client_name, "config": config_str}


def _h_client_config(req: "_Handler", groups: tuple) -> dict:

    """Return the client WireGuard config as text for download."""
    _require_unlocked()
    _require_totp_for_reveal(req)
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id  = _session.get("admin_id", "owner")

    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.audit      import AuditLog

    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)
        cdata = state.clients[name]
        # SEC-015: lazy-migrate legacy clients without heartbeat tokens.
        heartbeat_token = cdata.get("heartbeat_token")
        if not heartbeat_token:
            import secrets as _secrets_hb
            heartbeat_token = _secrets_hb.token_hex(32)
            cdata["heartbeat_token"] = heartbeat_token
            vault.save(state, passphrase)
        _tm = cdata.get("tunnel_mode", "full")
        _ls = state.server.get("lan_subnet", "")
        _lg = state.server.get("lan_gateway", "")
        config_str = ConfigBuilder().render_client_config(
            client_private_key=_extract(cdata["private_key"]),
            client_ip=cdata["ip"],
            dns_server=cdata.get("dns_server") or _dns_for_tunnel_mode(_tm, _ls, _lg),
            server_public_key=_extract(state.server["public_key"]),
            psk=_extract(cdata["psk"]),
            server_endpoint=_resolve_client_endpoint(state.server),
            mtu=_detect_mtu(),
            allowed_ips=cdata.get("allowed_ips", "0.0.0.0/0"),
        )

    AuditLog(_s._AUDIT_PATH).log("export-config", {"client": name}, actor=_actor_id)
    return {"name": name, "config": config_str, "heartbeat_token": heartbeat_token}


def _h_client_config_download(req: "_Handler", groups: tuple) -> None:

    """Serve the client WireGuard config as a direct file download."""
    _require_unlocked()
    _require_totp_for_reveal(req)
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id  = _session.get("admin_id", "owner")

    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.audit      import AuditLog

    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)
        cdata = state.clients[name]
        _tm = cdata.get("tunnel_mode", "full")
        _ls = state.server.get("lan_subnet", "")
        _lg = state.server.get("lan_gateway", "")
        config_str = ConfigBuilder().render_client_config(
            client_private_key=_extract(cdata["private_key"]),
            client_ip=cdata["ip"],
            dns_server=cdata.get("dns_server") or _dns_for_tunnel_mode(_tm, _ls, _lg),
            server_public_key=_extract(state.server["public_key"]),
            psk=_extract(cdata["psk"]),
            server_endpoint=_resolve_client_endpoint(state.server),
            mtu=_detect_mtu(),
            allowed_ips=cdata.get("allowed_ips", "0.0.0.0/0"),
        )

    AuditLog(_s._AUDIT_PATH).log("export-config", {"client": name}, actor=_actor_id)

    body = config_str.encode("utf-8")
    safe_name = re.sub(r"[^a-zA-Z0-9_\-.]", "_", name)
    req.send_response(200)
    req.send_header("Content-Type", "application/octet-stream")
    req.send_header("Content-Disposition", f'attachment; filename="{safe_name}.conf"')
    req.send_header("Content-Length", str(len(body)))
    req._cors()
    req.end_headers()
    req.wfile.write(body)
    return None  # Signal to _dispatch that response is already written


def _h_rotate_client_keys(req: "_Handler", groups: tuple) -> dict:
    """Rotate the keypair and PSK for a specific client.

    POST /api/clients/<name>/rotate
    Server-mode only â€" client vaults have no clients to rotate.

    Generates new client keypair + PSK, rebuilds both client and server
    configs, validates them, writes atomically, reloads WireGuard, and
    updates the vault.  Returns the new client config + QR PNG.
    """
    _require_unlocked()
    _require_server_mode()
    # SEC-TOTP-07: require TOTP confirmation before rotating client keys.
    # Client key rotation invalidates the existing config â€" all connected
    # sessions for this client are terminated until the new config is deployed.
    _require_confirmation(req._json())
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id  = _session.get("admin_id", "owner")

    from wireseal.core.keygen         import generate_keypair
    from wireseal.core.psk            import generate_psk
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.validator  import validate_client_config, validate_server_config
    from wireseal.security.atomic     import atomic_write
    from wireseal.security.audit      import AuditLog
    from wireseal.platform.detect     import get_adapter

    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)

        client_data = state.clients[name]

        # Generate new material
        new_priv, new_pub_bytes = generate_keypair()
        new_psk = generate_psk()
        new_pub_str  = new_pub_bytes.decode("ascii")
        new_priv_str = new_priv.expose_secret().decode("ascii")
        new_psk_str  = new_psk.expose_secret().decode("ascii")

        # Collect server info
        server_data     = state.server
        server_pub_key  = _extract(server_data["public_key"])
        client_ip       = client_data["ip"]
        server_port     = server_data["port"]
        server_endpoint = _resolve_client_endpoint(server_data)
        subnet          = state.ip_pool.get("subnet", "192.168.1.0/24")
        prefix_length   = int(subnet.split("/")[1])
        _tm = client_data.get("tunnel_mode", "full")
        _ls = server_data.get("lan_subnet", "")
        _lg = server_data.get("lan_gateway", "")
        dns_server      = client_data.get("dns_server") or _dns_for_tunnel_mode(_tm, _ls, _lg)

        # Build new client config
        builder = ConfigBuilder()
        new_client_config = builder.render_client_config(
            client_private_key=new_priv_str,
            client_ip=client_ip,
            dns_server=dns_server,
            server_public_key=server_pub_key,
            psk=new_psk_str,
            server_endpoint=server_endpoint,
            mtu=_detect_mtu(),
            allowed_ips=client_data.get("allowed_ips", "0.0.0.0/0"),
        )

        # Build updated server config
        peers = []
        for cname, cdata in state.clients.items():
            if cname == name:
                peers.append({
                    "name": cname, "public_key": new_pub_str,
                    "psk": new_psk_str, "ip": cdata["ip"],
                })
            else:
                peers.append({
                    "name": cname, "public_key": _extract(cdata["public_key"]),
                    "psk": _extract(cdata["psk"]), "ip": cdata["ip"],
                })

        new_server_config = builder.render_server_config(
            server_private_key=_extract(server_data["private_key"]),
            server_ip=server_data["ip"],
            prefix_length=prefix_length,
            server_port=server_port,
            clients=peers,
        )

        # Validate
        try:
            validate_client_config({
                "private_key": new_priv_str, "psk": new_psk_str,
                "ip": client_ip, "dns_server": dns_server,
                "server_public_key": server_pub_key,
                "endpoint": server_endpoint,
            })
        except ValueError as exc:
            new_priv.wipe()
            new_psk.wipe()
            raise _ApiError(f"Client config validation failed: {exc}", 500) from exc

        try:
            validate_server_config({
                "private_key": _extract(server_data["private_key"]),
                "public_key": "", "port": server_port,
                "subnet": subnet, "clients": peers,
            })
        except ValueError as exc:
            new_priv.wipe()
            new_psk.wipe()
            raise _ApiError(f"Server config validation failed: {exc}", 500) from exc

        # Write configs atomically
        clients_dir = _s._VAULT_DIR / "clients"
        clients_dir.mkdir(parents=True, exist_ok=True)
        client_conf_path = clients_dir / f"{name}.conf"
        client_encoded = new_client_config.encode("utf-8")
        atomic_write(client_conf_path, client_encoded, mode=0o600)
        client_hash = hashlib.sha256(client_encoded).hexdigest()

        adapter = get_adapter()
        server_conf_path = adapter.get_config_path(_WG_IFACE)
        server_encoded = new_server_config.encode("utf-8")
        atomic_write(server_conf_path, server_encoded, mode=0o600)
        server_hash = hashlib.sha256(server_encoded).hexdigest()

        # Reload WireGuard
        wg_warning = _reload_wireguard(_WG_IFACE)

        # Update vault state
        state.clients[name]["private_key"] = new_priv_str
        state.clients[name]["public_key"]  = new_pub_str
        state.clients[name]["psk"]         = new_psk_str
        state.integrity[f"client-{name}"]  = client_hash
        state.integrity["server"]          = server_hash
        vault.save(state, passphrase)

        AuditLog(_s._AUDIT_PATH).log("rotate-client-keys", {"name": name}, actor=_actor_id)

        with _lock:
            _session["cache"] = _refresh_cache(state)

    # Generate QR
    qr_b64 = ""
    try:
        qr_img = io.BytesIO()
        import qrcode  # type: ignore
        qrcode.make(new_client_config).save(qr_img, format="PNG")
        qr_b64 = base64.b64encode(qr_img.getvalue()).decode()
    except (ImportError, OSError, AttributeError):
        _clients_log.debug("QR generation failed during key rotation", exc_info=True)

    result: dict = {"ok": True, "name": name, "config": new_client_config}
    if qr_b64:
        result["qr_png_b64"] = qr_b64
    if wg_warning:
        result["warning"] = wg_warning
    return result

