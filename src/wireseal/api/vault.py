"""Vault lifecycle handlers."""

import logging

from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _name

_vault_log = logging.getLogger("wireseal.api.vault")

def _h_vault_info(req: "_Handler", _groups: tuple) -> dict:
    # SEC-FIX-3: Do NOT expose totp_required_for (admin ID list) to
    # unauthenticated callers â€” it enables pre-auth admin enumeration.
    # Only vault_initialized, vault_locked, and mode are safe to return
    # without authentication. The totp_required_for list is now available
    # only via GET /api/admins/totp-status (requires _require_unlocked).
    locked = _session["vault"] is None
    vault_mode: str | None = None
    multi_admin: bool = False
    if not locked and _session["cache"]:
        vault_mode = _session["cache"].get("mode")
        admins_data = _session["cache"].get("admins", {})
        multi_admin = len(admins_data) > 1
    return {
        "initialized":  _s._VAULT_PATH.exists(),
        "locked":       locked,
        "interface":    _WG_IFACE,
        "pin_set":      _s._PIN_PATH.exists(),
        "multi_admin":  multi_admin,
        "mode":         vault_mode,
    }



def _h_init(req: "_Handler", _groups: tuple) -> dict:
    # SEC-016: atomic existence check + create. Without the lock, two
    # concurrent POST /api/init calls can both observe an absent vault
    # and both call Vault.create â€” the second wins and silently discards
    # the first caller's passphrase. Holding _init_lock across the
    # existence check AND the creation serialises concurrent init
    # attempts. A dedicated non-reentrant lock is used so the (slow)
    # Argon2 KDF inside Vault.create does not starve other API endpoints
    # that share the main _lock.
    if not _init_lock.acquire(timeout=60):
        raise _ApiError("Another init operation is in progress.", 409)
    try:
        return _h_init_locked(req)
    finally:
        _init_lock.release()



def _h_init_locked(req: "_Handler", _groups: tuple = ()) -> dict:
    if _s._VAULT_PATH.exists():
        raise _ApiError("Vault already exists. Use /api/unlock.", 409)

    body           = req._json()
    passphrase_str = body.get("passphrase", "")
    if len(passphrase_str) < 12:
        raise _ApiError("Passphrase must be at least 12 characters.", 400)

    mode = body.get("mode", "server")
    if mode not in ("server", "client"):
        raise _ApiError("mode must be 'server' or 'client'.", 400)

    subnet   = body.get("subnet", "192.168.1.0/24")
    try:
        port = int(body.get("port", 51820))
    except (TypeError, ValueError):
        raise _ApiError("Port must be an integer.", 400)
    # Hard-reject blocklisted ports; warnings are kept for return.
    _ok, port_warning = _validate_wg_port(port)
    endpoint = body.get("endpoint") or None
    if endpoint:
        endpoint = _validate_endpoint(endpoint)

    from wireseal.security.secret_types  import SecretBytes
    from wireseal.security.secrets_wipe  import wipe_string
    from wireseal.security.vault         import Vault
    from wireseal.security.audit         import AuditLog
    from wireseal.core.keygen            import generate_keypair
    from wireseal.core.ip_pool           import IPPool
    from wireseal.core.config_builder    import ConfigBuilder

    passphrase = SecretBytes(bytearray(passphrase_str.encode()))

    # â”€â”€ Client-only vault init â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Client mode never generates a server keypair, installs WireGuard,
    # applies firewall rules, or enables a tunnel service. It creates an
    # encrypted vault for storing imported client configs only.
    if mode == "client":
        try:
            from datetime import datetime as _dt, timezone as _tz
            now_iso = _dt.now(_tz.utc).isoformat()
            initial_state = {
                "schema_version": 2,
                "mode":           "client",
                "client_configs": {},
                "integrity":      {},
                "admins": {
                    "owner": {
                        "role": "owner",
                        "created_at": now_iso,
                        "totp_secret_b32": None,
                        "totp_enrolled_at": None,
                        "backup_codes": [],
                        "last_unlock": None,
                    }
                },
                "dns_mappings": {},
                "backup_config": {
                    "enabled": False, "destination": "local",
                    "local_path": None, "keep_n": 10, "last_backup_at": None,
                },
            }
            vault = Vault.create(_s._VAULT_PATH, passphrase, initial_state)
            admins_cache = {k: dict(v) if isinstance(v, dict) else v for k, v in initial_state.get("admins", {}).items()}
            bc_cache = dict(initial_state.get("backup_config", {}))
            cache = {
                "mode": "client", "server": {}, "clients": {}, "ip_pool": {},
                "admins": admins_cache,
                "dns_mappings": {}, "backup_config": bc_cache,
            }
            with _lock:
                _session.update(vault=vault, passphrase=passphrase, cache=cache)
            passphrase = None  # ownership transferred to session

            AuditLog(_s._AUDIT_PATH).log(
                "init", {"mode": "client"}, actor="system"
            )
            return {
                "ok":    True,
                "mode":  "client",
            }
        except _ApiError:
            raise
        except Exception:
            if passphrase is not None:
                passphrase.wipe()
            raise _ApiError("Client vault initialization failed.", 500)
        finally:
            wipe_string(passphrase_str)

    try:
        if endpoint is None:
            try:
                from wireseal.dns.ip_resolver import resolve_public_ip
                endpoint = str(resolve_public_ip())
            except (OSError, ValueError, ImportError):
                endpoint = None

        priv_key, pub_key_bytes = generate_keypair()
        pub_key_str  = pub_key_bytes.decode("ascii")
        priv_key_str = priv_key.expose_secret().decode("ascii")

        pool      = IPPool(subnet)
        server_ip = pool.server_ip

        initial_state = {
            "schema_version": 1,
            "mode":           "server",
            "server": {
                "private_key": priv_key_str,
                "public_key":  pub_key_str,
                "ip":          server_ip,
                "subnet":      pool.subnet_str,
                "port":        port,
                "endpoint":    endpoint,
            },
            "clients":  {},
            "ip_pool":  {"subnet": pool.subnet_str,
                         "allocated": pool.get_allocated()},
            "integrity": {},
        }

        # â”€â”€ Step 1: Create the encrypted vault (always succeeds or fails fast) â”€â”€
        vault = Vault.create(_s._VAULT_PATH, passphrase, initial_state)

        # Build cache directly from initial_state instead of re-opening the
        # vault (which would run Argon2id KDF again, adding ~5s of latency).
        # `mode` MUST be present so:
        #   1. /api/vault-info returns "mode": "server" â†’ Dashboard's
        #      probeVault() can sync the React mode state to "server" and
        #      render the server Layout instead of the mode picker.
        #   2. _require_server_mode() / _require_client_mode() see the
        #      correct value and gate cross-mode endpoint access.
        cache = {
            "mode":   "server",
            "server": {
                "ip":       server_ip,
                "subnet":   pool.subnet_str,
                "port":     port,
                "endpoint": endpoint or "",
                "duckdns":  "",
            },
            "clients": {},
            "ip_pool": dict(initial_state["ip_pool"]),
        }
        with _lock:
            _session.update(vault=vault, passphrase=passphrase, cache=cache)
        passphrase = None  # ownership transferred to session

        AuditLog(_s._AUDIT_PATH).log("init", {"subnet": subnet, "port": port}, actor="system")

        # â”€â”€ Step 2: Platform setup (best-effort â€” failures are warnings) â”€â”€â”€â”€â”€â”€â”€â”€
        # These operations require admin privileges and WireGuard to be installed.
        # If they fail, the vault is still created and the dashboard works.
        warnings_list: list[str] = []

        try:
            from wireseal.platform.detect import get_adapter
            adapter = get_adapter()
            adapter.check_privileges()
        except Exception as exc:
            warnings_list.append("Not running as admin â€” platform setup skipped.")
            # Cannot proceed with platform setup without admin
            return {
                "ok":         True,
                "server_ip":  server_ip,
                "subnet":     pool.subnet_str,
                "public_key": pub_key_str,
                "endpoint":   endpoint,
                "warnings":   warnings_list,
            }

        try:
            config = ConfigBuilder().render_server_config(
                server_private_key=priv_key_str,
                server_ip=server_ip,
                prefix_length=int(pool.subnet_str.split("/")[1]),
                server_port=port,
                clients=[],
            )
            adapter.deploy_config(config)
        except Exception as exc:
            warnings_list.append("Config deploy failed.")

        try:
            adapter.install_wireguard()
        except Exception as exc:
            warnings_list.append("WireGuard install skipped.")

        try:
            adapter.enable_ip_forwarding()
        except Exception as exc:
            warnings_list.append("IP forwarding skipped.")

        try:
            adapter.apply_firewall_rules(port, _WG_IFACE, pool.subnet_str)
        except Exception as exc:
            warnings_list.append("Firewall rules skipped.")

        # Open port in firewalld and ensure SSH is running (Linux only)
        if hasattr(adapter, "open_firewalld_port"):
            try:
                adapter.open_firewalld_port(port)
            except (OSError, PermissionError) as _exc:
                _vault_log.warning("firewalld port open skipped: %s", _exc)
                warnings_list.append("firewalld port open skipped.")
        if hasattr(adapter, "ensure_sshd"):
            try:
                adapter.ensure_sshd()
            except (OSError, PermissionError) as _exc:
                _vault_log.warning("SSH server setup skipped: %s", _exc)
                warnings_list.append("SSH server setup skipped.")
        # Server hardening (SSH, kernel, fail2ban, auto-updates)
        if hasattr(adapter, "harden_server"):
            try:
                adapter.harden_server()
            except (OSError, PermissionError) as _exc:
                _vault_log.warning("Server hardening skipped: %s", _exc)
                warnings_list.append("Server hardening skipped.")

        try:
            adapter.enable_tunnel_service(_WG_IFACE)
        except Exception as exc:
            warnings_list.append("Tunnel service failed.")

        # Detect LAN subnet for split-tunnel AllowedIPs.
        lan_subnet = ""
        try:
            lan_subnet = adapter.detect_lan_subnet()
        except (OSError, ValueError) as _exc:
            _vault_log.warning("LAN subnet detection failed: %s", _exc)
            warnings_list.append("LAN subnet detection failed — split-tunnel will use VPN subnet only.")
        if lan_subnet:
            try:
                with vault.open(passphrase) as state:
                    state.server["lan_subnet"] = lan_subnet
                    vault.save(state, passphrase)
                with _lock:
                    _session["cache"]["server"]["lan_subnet"] = lan_subnet
            except Exception as _exc:
                _vault_log.warning("Could not persist LAN subnet to vault: %s", _exc)
                warnings_list.append("Could not persist LAN subnet to vault.")

        if port_warning:
            warnings_list.append(f"Port {port}: {port_warning}")
        return {
            "ok":           True,
            "server_ip":    server_ip,
            "subnet":       pool.subnet_str,
            "public_key":   pub_key_str,
            "endpoint":     endpoint,
            "port":         port,
            "lan_subnet":   lan_subnet or None,
            "warnings":     warnings_list if warnings_list else None,
            "port_warning": port_warning,
        }
    except _ApiError:
        raise
    except Exception as exc:
        if passphrase is not None:
            passphrase.wipe()
        # Log full traceback to stderr + AppData log so users can copy the
        # real error when reporting bugs. Generic wrapper kept so we never
        # leak sensitive paths or keys to the HTTP response body â€” only the
        # exception class + message goes back, full traceback stays local.
        import traceback as _tb
        _tb.print_exc()
        try:
            from wireseal.security.audit import AuditLog
            AuditLog(_s._AUDIT_PATH).log(
                "init-failed",
                {"error_class": type(exc).__name__, "error": str(exc)[:500]},
                actor="system",
            )
        except Exception as _audit_exc:
            logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)
        raise _ApiError(
            "Server initialization failed. Check the audit log.",
            500,
        )
    finally:
        wipe_string(passphrase_str)


_ADMIN_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def _validate_admin_id(admin_id: str) -> str:
    """SEC-013: reject admin_id values containing characters outside
    ``[A-Za-z0-9_-]`` or longer than 64 chars. Returns the validated id.
    """
    if not isinstance(admin_id, str) or not _ADMIN_ID_RE.match(admin_id or ""):
        raise _ApiError(
            "admin_id must match [A-Za-z0-9_-]{1,64}.", 400,
        )
    return admin_id



def _h_unlock(req: "_Handler", _groups: tuple) -> dict:
    client_ip = req.client_address[0]
    if _check_rate_limit(client_ip, "unlock"):
        raise _ApiError("Too many unlock attempts. Try again later.", 429)

    body           = req._json()
    passphrase_str = body.get("passphrase", "")
    admin_id       = _validate_admin_id(body.get("admin_id", "owner"))
    if not passphrase_str:
        raise _ApiError("passphrase is required", 400)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string
    from wireseal.security.vault        import Vault
    from wireseal.security.audit        import AuditLog

    totp_code = body.get("totp_code")  # optional â€” required only when enrolled

    passphrase = SecretBytes(bytearray(passphrase_str.encode()))
    try:
        vault = Vault(_s._VAULT_PATH)
        try:
            with vault.open(passphrase, admin_id=admin_id) as st:
                # Update last_unlock for this admin
                admins_dict = st.data.setdefault("admins", {})
                # SEC-013: reject unknown admin_id with valid passphrase.
                # Previously the code silently defaulted to "owner" role for
                # fabricated admin_ids, giving an attacker with a valid
                # passphrase the strongest role regardless of their slot.
                if admin_id not in admins_dict:
                    raise _ApiError("Unknown admin_id.", 401)
                admins_dict[admin_id]["last_unlock"] = _utcnow_iso()
                admin_role = admins_dict[admin_id].get("role", "admin")

                # Load persisted anti-replay set so codes survive restarts.
                _load_totp_used_codes(st.data, admin_id)

                # TOTP enforcement: if admin has enrolled TOTP, require a valid code.
                totp_b32 = admins_dict.get(admin_id, {}).get("totp_secret_b32")
                if totp_b32 is not None:
                    if not totp_code:
                        raise _ApiError("totp_code required", 401)
                    _check_totp_rate_limit(admin_id)
                    # SEC-CC-02: totp_secret_b32 is SecretBytes after _wrap_secrets;
                    # unwrap to str before passing to b32_to_secret.
                    from wireseal.security.secret_types import SecretBytes as _SB
                    if isinstance(totp_b32, _SB):
                        totp_b32_str = bytes(totp_b32.expose_secret()).decode("utf-8")
                    else:
                        totp_b32_str = str(totp_b32)
                    totp_secret = b32_to_secret(totp_b32_str)
                    totp_str = str(totp_code)
                    # Hold _lock during check+record to make anti-replay atomic.
                    with _lock:
                        used_set = _totp_used_codes.setdefault(admin_id, set())
                        totp_ok = verify_totp(totp_secret, totp_str, used_codes=used_set)
                    if not totp_ok:
                        AuditLog(_s._AUDIT_PATH).log("totp-failed", {"admin_id": admin_id}, actor=admin_id)
                        _record_totp_failure(admin_id)
                        raise _ApiError("invalid_totp", 401)
                    import time as _time
                    with _lock:
                        _totp_session_verified[admin_id] = _time.monotonic()

                _migrate_legacy_client_tokens(st, vault, passphrase)
                cache = _refresh_cache(st)
        except _ApiError:
            passphrase.wipe()
            _record_unlock_failure(client_ip)
            _record_rate_limit_failure(client_ip, "unlock")
            raise
        except Exception as exc:
            passphrase.wipe()
            _record_unlock_failure(client_ip)
            _record_rate_limit_failure(client_ip, "unlock")
            raise _ApiError("Incorrect passphrase.", 401)

        with _lock:
            if _session["passphrase"]:
                _session["passphrase"].wipe()
            _session.update(
                vault=vault, passphrase=passphrase, cache=cache,
                admin_id=admin_id, admin_role=admin_role,
            )

        _clear_unlock_failures(client_ip)
        _clear_rate_limit(client_ip, "unlock")
        audit = AuditLog(_s._AUDIT_PATH)
        audit.log("unlock-web", {"admin_id": admin_id}, actor=admin_id)
        # Start a per-session audit log for this unlock session
        try:
            _sessions_dir = _s._VAULT_DIR / "sessions"
            audit.session_start(_sessions_dir)
        except Exception as _audit_exc:
            logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)

        # Server mode: auto-deploy WireGuard config if missing on disk.
        # This handles DPAPI wipe, accidental deletion, or fresh machine.
        # Tunnel is NOT auto-started — user controls via Dashboard buttons.
        if cache.get("mode") == "server":
            try:
                from wireseal.platform.detect import get_adapter
                _adapter = get_adapter()
                _cfg_path = _adapter.get_config_path("wg0")
                _dpapi    = _cfg_path.with_suffix(".conf.dpapi")
                if not _cfg_path.exists() and not _dpapi.exists():
                    srv = cache.get("server") or {}
                    if srv.get("ip"):
                        with vault.open(passphrase, admin_id=admin_id) as _st:
                            _srv = _st.data.get("server") or {}
                            _pk  = _srv.get("private_key")
                            if _pk:
                                _ext = lambda v: v.expose_secret().decode("ascii") if hasattr(v, "expose_secret") else str(v)
                                _clients = [
                                    {"name": n, "public_key": _ext(d["public_key"]),
                                     "psk": _ext(d["psk"]), "ip": d["ip"]}
                                    for n, d in (_st.data.get("clients") or {}).items()
                                    if d.get("status", "active") == "active"
                                ]
                                from wireseal.core.config_builder import ConfigBuilder
                                _cfg = ConfigBuilder().render_server_config(
                                    server_private_key=_ext(_pk),
                                    server_ip=srv["ip"],
                                    prefix_length=int((cache.get("ip_pool") or {}).get("subnet", "10.0.0.0/24").split("/")[1]),
                                    server_port=srv.get("port", 51820),
                                    clients=_clients,
                                )
                                _adapter.deploy_config(_cfg)
                                logging.getLogger("wireseal.vault").info("Auto-deployed WireGuard config on unlock (was missing)")
            except Exception as _deploy_exc:
                logging.getLogger("wireseal.vault").warning("Config auto-deploy on unlock failed: %s", _deploy_exc)

        # Client mode: honour auto_connect_profile setting if configured.
        auto_profile = None
        if cache.get("mode") == "client":
            try:
                client_settings = _get_client_settings(
                    type("_S", (), {"data": cache})()
                )
                auto_profile = client_settings.get("auto_connect_profile")
            except (KeyError, AttributeError, TypeError):
                pass

        result: dict = {"ok": True, "role": admin_role}
        if auto_profile:
            try:
                from wireseal.client.config_store import get_config_revealed
                from wireseal.client.tunnel import apply_dns_override, tunnel_up

                with vault.open(passphrase) as st2:
                    cfg = get_config_revealed(st2._data, auto_profile)

                config_text = cfg["config_text"]
                ks_en = bool(client_settings.get("kill_switch"))
                dns_ov = client_settings.get("dns_override", "")
                if dns_ov:
                    config_text = apply_dns_override(config_text, dns_ov)
                tunnel_up(config_text, auto_profile, enable_kill_switch=ks_en)
                result["auto_connected"] = auto_profile
            except Exception as exc:
                result["auto_connect_error"] = str(exc)

        return result
    finally:
        wipe_string(passphrase_str)



def _h_lock(req: "_Handler", _groups: tuple) -> dict:
    from wireseal.security.audit import AuditLog
    _admin_deactivate()  # admin mode is tied to the authenticated session
    with _lock:
        _lock_actor = _session.get("admin_id") or "system"
        # Persist used codes before clearing session
        _lock_actor_inner = _lock_actor
    _persist_totp_used_codes(_lock_actor_inner)
    with _lock:
        if _session["passphrase"]:
            _session["passphrase"].wipe()
        _session.update(vault=None, passphrase=None, cache=None,
                        admin_id=None, admin_role=None)
        # Clear used TOTP codes and session for this admin.
        _totp_used_codes.pop(_lock_actor_inner, None)
        _totp_session_verified.pop(_lock_actor_inner, None)
    AuditLog(_s._AUDIT_PATH).log("lock", {}, actor=_lock_actor)
    # End the per-session audit log
    try:
        AuditLog(_s._AUDIT_PATH).session_end()
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)
    return {"ok": True}


def _detect_new_handshakes(peers: list[dict]) -> None:
    """Compare current handshake times against the module-level cache.

    For each peer that has crossed from disconnected (last_handshake_seconds
    >= 180 or absent from cache) to connected (last_handshake_seconds < 180),
    write a 'peer-connected' entry to the audit log and update the cache.

    Intentionally swallows all exceptions: a failing audit write must never
    crash the status endpoint.
    """
    global _peer_handshake_cache
    try:
        from wireseal.security.audit import AuditLog
        audit = AuditLog(_s._AUDIT_PATH)
        new_cache: dict[str, int] = {}
        for p in peers:
            key = p.get("public_key", p.get("public_key_short", ""))
            secs = p.get("last_handshake_seconds", -1)
            new_cache[key] = secs
            prev = _peer_handshake_cache.get(key)
            # Fire event: was disconnected (or unseen), now connected
            was_disconnected = (prev is None) or (prev < 0) or (prev >= 180)
            now_connected = 0 <= secs < 180
            if was_disconnected and now_connected:
                try:
                    audit.log(
                        "peer-connected",
                        {
                            "name": p.get("name", "unknown"),
                            "peer": p.get("public_key_short", ""),
                            "last_handshake_seconds": secs,
                        },
                        actor="system",
                    )
                except Exception as _audit_exc:
                    logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)
        _peer_handshake_cache = new_cache
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)



def _h_change_passphrase(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    # SEC-TOTP-01: require TOTP or passphrase re-confirmation before allowing
    # passphrase change. An attacker with an unlocked session (walked-away
    # terminal, XSS in dashboard, compromised same-origin tab) must still
    # prove possession of TOTP to escalate to permanent control.
    _require_confirmation(body)
    current_str = body.get("current", "")
    new_str     = body.get("new", "")

    if len(new_str) < 12:
        raise _ApiError("New passphrase must be at least 12 characters.", 400)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe  import wipe_string
    from wireseal.security.audit         import AuditLog

    with _lock:
        vault     = _session["vault"]
        _actor_id = _session.get("admin_id", "owner")

    old_passphrase = SecretBytes(bytearray(current_str.encode()))
    new_passphrase = SecretBytes(bytearray(new_str.encode()))
    try:
        try:
            vault.change_passphrase(old_passphrase, new_passphrase)
        except Exception:
            old_passphrase.wipe()
            new_passphrase.wipe()
            raise _ApiError("Passphrase change failed â€” check current passphrase.", 401)

        with _lock:
            _session["passphrase"].wipe()
            _session["passphrase"] = new_passphrase
        old_passphrase.wipe()

        # Wipe PIN â€” it's encrypted with the old passphrase, now stale
        _pin_wipe()

        AuditLog(_s._AUDIT_PATH).log("change-passphrase", {}, actor=_actor_id)
        return {"ok": True, "pin_removed": _s._PIN_PATH.exists() is False}
    finally:
        wipe_string(current_str)
        wipe_string(new_str)



def _h_fresh_start_challenge_read(req: "_Handler", _groups: tuple) -> dict:
    """Return the fresh-start challenge token from disk.

    GET /api/fresh-start/challenge-token

    Original SEC-002 design required the caller to read the challenge
    file from the local filesystem â€” that ruled out the dashboard JS
    (no FS access) and forced fresh-start to be CLI-only. The dashboard
    then ran fresh-start with no token and got 400.

    This endpoint re-exposes the token through HTTP, but ONLY when the
    request originates from the local loopback interface AND passes the
    same-origin check. A cross-origin browser CSRF cannot reach a
    same-origin endpoint by definition; a remote network attacker can't
    bind to 127.0.0.1 from outside. Both gates together preserve the
    "physical/admin filesystem access" property that SEC-002 wanted.
    """
    _require_same_origin(req)

    # Loopback-only â€” refuse if the connection came from elsewhere.
    client_ip = req.client_address[0] if req.client_address else ""
    if client_ip not in ("127.0.0.1", "::1", "localhost"):
        raise _ApiError(
            "Fresh-start token is only readable from the local machine.",
            403,
        )

    path = _fresh_start_challenge_path()
    if not path.exists():
        raise _ApiError(
            "No challenge issued. POST /api/fresh-start/challenge first.",
            404,
        )

    try:
        raw = path.read_text(encoding="ascii").strip().splitlines()
    except OSError as exc:
        raise _ApiError(f"Failed to read challenge file: {exc}", 500)
    if not raw:
        raise _ApiError("Challenge file is empty.", 500)

    token = raw[0]
    return {"ok": True, "challenge_token": token}



def _h_fresh_start_challenge(req: "_Handler", _groups: tuple) -> dict:
    """Issue a one-time challenge token for fresh-start.

    POST /api/fresh-start/challenge

    SEC-002: The token is written to ``_s._VAULT_DIR/.reset-challenge``. The
    caller must then READ that file from the filesystem and submit its
    first line as ``challenge_token`` to ``POST /api/fresh-start``.
    Browser-based CSRF attackers can POST here but cannot read the file â€”
    so a compromised tab cannot destroy the vault without physical/admin
    filesystem access.
    """
    _require_same_origin(req)
    _ = _create_fresh_start_challenge()
    # NOTE: we deliberately do NOT return the token in the response body.
    # Returning it would let a browser CSRF attacker read it. The caller
    # must read it from disk, which requires filesystem privileges the
    # attacker doesn't have.
    from wireseal.security.audit import AuditLog
    try:
        AuditLog(_s._AUDIT_PATH).log(
            "fresh-start-challenge-issued",
            {"ip": req.client_address[0]},
            actor="system",
        )
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)
    # SEC-002 follow-up: do NOT disclose the absolute vault-directory path in
    # the response body. A cross-origin caller (who would already have been
    # blocked by _require_same_origin) or any observer of proxy/gateway logs
    # should not learn where the vault lives. The filename is fixed
    # (".reset-challenge"); a legitimate local CLI caller knows the vault dir
    # from its own config.
    return {
        "ok": True,
        "message": (
            f"Challenge written to <vault-dir>/{_FRESH_START_CHALLENGE_NAME}. "
            "Read the first line of that file and submit it as "
            '"challenge_token" in POST /api/fresh-start.'
        ),
        "challenge_filename": _FRESH_START_CHALLENGE_NAME,
        "expires_in": _FRESH_START_TTL_SECONDS,
    }



def _h_fresh_start(req: "_Handler", _groups: tuple) -> dict:
    """Destroy the vault directory after two-factor confirmation.

    SEC-002: Requires both:
      * the literal confirmation string ``{"confirm": "CONFIRM"}``, AND
      * a single-use ``challenge_token`` obtained by reading the challenge
        file written by ``POST /api/fresh-start/challenge``.

    The challenge file lives on the local filesystem with mode 0o600 â€”
    a browser CSRF cannot read it, but the legitimate user (who controls
    the machine) can. This gates irreversible destruction behind a
    capability the attacker does not possess.

    We still do NOT require vault unlock here â€” the whole point of the
    endpoint is to recover from a forgotten passphrase. The filesystem
    capability replaces the passphrase as the proof of authority.
    """
    _require_same_origin(req)
    body = req._json()
    if body.get("confirm") != "CONFIRM":
        raise _ApiError('Send {"confirm":"CONFIRM"} to proceed.', 400)

    token = body.get("challenge_token", "")
    _consume_fresh_start_challenge(token)

    from wireseal.security.audit import AuditLog
    try:
        AuditLog(_s._AUDIT_PATH).log(
            "fresh-start-invoked",
            {"ip": req.client_address[0]},
            actor="system",
        )
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)

    # Stop the WireGuard tunnel
    if sys.platform == "win32":
        svc = f"WireGuardTunnel${_WG_IFACE}"
        try:
            subprocess.run(["sc.exe", "stop", svc], check=False, capture_output=True, timeout=10, creationflags=_SP_FLAGS)
        except Exception as _exc:
            logging.getLogger("wireseal").warning("Failed to stop WireGuard service: %s", _exc)
        from wireseal.platform.windows import WG_EXE as wg_exe
        if wg_exe.exists():
            try:
                subprocess.run([str(wg_exe), "/uninstalltunnelservice", _WG_IFACE], check=False, capture_output=True, timeout=10, creationflags=_SP_FLAGS)
            except Exception as _exc:
                logging.getLogger("wireseal").warning("Failed to uninstall WireGuard tunnel service: %s", _exc)
    else:
        try:
            subprocess.run(_sudo([_resolve_wg_tool("wg-quick"), "down", _WG_IFACE]), check=False, capture_output=True, timeout=10)
        except Exception as _exc:
            logging.getLogger("wireseal").warning("Failed to bring down wg-quick: %s", _exc)

    import shutil
    shutil.rmtree(_s._VAULT_DIR, ignore_errors=True)

    from wireseal.platform.detect import get_adapter
    try:
        cfg = get_adapter().get_config_path(_WG_IFACE)
        cfg.unlink(missing_ok=True)
    except Exception as _exc:
        logging.getLogger("wireseal").warning("Failed to remove adapter config: %s", _exc)

    with _lock:
        if _session["passphrase"]:
            _session["passphrase"].wipe()
        _session.update(vault=None, passphrase=None, cache=None)

    return {"ok": True}




