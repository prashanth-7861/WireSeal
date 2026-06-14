"""Tunnel and background-service handlers."""
from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name


def _parse_handshake_to_seconds(hs: str) -> int:
    if not hs or hs.strip().lower() in ("never", ""):
        return -1
    total = 0
    cleaned = re.sub(r"\bago\b", "", hs, flags=re.IGNORECASE).replace(",", " ")
    tokens = cleaned.split()
    i = 0
    matched_any = False
    while i < len(tokens) - 1:
        try:
            val = int(tokens[i])
        except ValueError:
            i += 1
            continue
        unit = tokens[i + 1].lower().rstrip("s")
        if unit == "second":
            total += val
            matched_any = True
        elif unit == "minute":
            total += val * 60
            matched_any = True
        elif unit == "hour":
            total += val * 3600
            matched_any = True
        elif unit == "day":
            total += val * 86400
            matched_any = True
        elif unit == "week":
            total += val * 604800
            matched_any = True
        i += 2
    return total if matched_any else -1


def _format_transfer_bytes(raw: str) -> str:
    raw = raw.strip()
    m = re.match(r"^([\d.]+)\s*([KMGT]?i?B)$", raw, re.IGNORECASE)
    if not m:
        return raw if raw else "0 B"
    try:
        value = float(m.group(1))
    except ValueError:
        return "0 B"
    unit = m.group(2).upper()
    multipliers = {
        "B": 1,
        "KIB": 1024, "KB": 1000,
        "MIB": 1024 ** 2, "MB": 1000 ** 2,
        "GIB": 1024 ** 3, "GB": 1000 ** 3,
        "TIB": 1024 ** 4, "TB": 1000 ** 4,
    }
    byte_val = value * multipliers.get(unit, 1)
    if byte_val < 1000:
        return f"{byte_val:.0f} B"
    elif byte_val < 1_000_000:
        return f"{byte_val / 1000:.2f} KB"
    elif byte_val < 1_000_000_000:
        return f"{byte_val / 1_000_000:.2f} MB"
    else:
        return f"{byte_val / 1_000_000_000:.2f} GB"


def _parse_wg_show(output: str) -> list[dict]:
    peers: list[dict] = []
    cur: dict | None = None
    for line in output.strip().splitlines():
        s = line.strip()
        if s.startswith("peer:"):
            if cur:
                peers.append(cur)
            cur = {
                "public_key":             s.split(":", 1)[1].strip(),
                "public_key_short":       s.split(":", 1)[1].strip()[:12] + "...",
                "allowed_ips":            "",
                "endpoint":               "",
                "last_handshake":         "never",
                "last_handshake_seconds": -1,
                "transfer_rx":            "0 B",
                "transfer_tx":            "0 B",
                "connected":              False,
            }
        elif cur:
            if s.startswith("allowed ips:"):
                cur["allowed_ips"] = s.split(":", 1)[1].strip()
            elif s.startswith("endpoint:"):
                cur["endpoint"] = s.split(":", 1)[1].strip()
            elif s.startswith("latest handshake:"):
                hs = s.split(":", 1)[1].strip()
                cur["last_handshake"] = hs
                secs = _parse_handshake_to_seconds(hs)
                cur["last_handshake_seconds"] = secs
                cur["connected"] = 0 <= secs < 180
            elif s.startswith("transfer:"):
                parts = s.split(":", 1)[1].strip().split(",")
                if len(parts) == 2:
                    cur["transfer_rx"] = _format_transfer_bytes(
                        parts[0].replace("received", "").strip()
                    )
                    cur["transfer_tx"] = _format_transfer_bytes(
                        parts[1].replace("sent", "").strip()
                    )
    if cur:
        peers.append(cur)
    return peers


def _service_adapter_or_die():
    from wireseal.platform.detect import get_adapter
    adapter = get_adapter()
    if not hasattr(adapter, "install_api_service"):
        raise _ApiError(
            "Background-service registration is not available on this OS.",
            501,
        )
    return adapter


def _h_start_server(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_server_mode()
    from wireseal.security.audit import AuditLog
    check = subprocess.run(
        _sudo(["ip", "link", "show", _WG_IFACE]) if sys.platform != "win32"
        else ["sc.exe", "query", f"WireGuardTunnel${_WG_IFACE}"],
        capture_output=True, timeout=5,
        creationflags=_SP_FLAGS,
    )
    if sys.platform == "win32":
        if b"RUNNING" in (check.stdout or b""):
            return {"ok": True, "note": "already running"}
        svc = f"WireGuardTunnel${_WG_IFACE}"
        from wireseal.platform.detect import get_adapter
        adapter = get_adapter()
        from wireseal.platform.windows import WG_EXE as wg_exe
        config_path = adapter.get_config_path(_WG_IFACE)
        # DPAPI: wireguard.exe encrypts .conf → .conf.dpapi on service
        # install, then deletes the original .conf.  Check both forms.
        dpapi_path = config_path.with_suffix(".conf.dpapi")
        config_exists = config_path.exists() or dpapi_path.exists()
        service_exists = check.returncode == 0
        if not service_exists:
            if not wg_exe.exists():
                raise _ApiError(
                    "WireGuard is not installed. Install from "
                    "https://www.wireguard.com/install/ and restart "
                    "the application.",
                    500,
                )
            if not config_exists:
                # Auto-recover: re-deploy config from vault if unlocked.
                recovered = False
                _recover_log = logging.getLogger("wireseal.service")
                try:
                    with _lock:
                        _vault = _session.get("vault")
                        _pp    = _session.get("passphrase")
                        _aid   = _session.get("admin_id", "owner")
                    if _vault and _pp:
                        from wireseal.core.config_builder import ConfigBuilder
                        with _vault.open(_pp, admin_id=_aid) as _st:
                            srv = _st.data.get("server") or {}
                            if srv.get("private_key"):
                                _extract = lambda v: v.expose_secret().decode("ascii") if hasattr(v, "expose_secret") else str(v)
                                peers = [
                                    {"name": n, "public_key": _extract(d["public_key"]),
                                     "psk": _extract(d["psk"]), "ip": d["ip"]}
                                    for n, d in (_st.data.get("clients") or {}).items()
                                    if d.get("status", "active") == "active"
                                ]
                                cfg = ConfigBuilder().render_server_config(
                                    server_private_key=_extract(srv["private_key"]),
                                    server_ip=srv["ip"],
                                    prefix_length=int((_st.data.get("ip_pool") or {}).get("subnet", "10.0.0.0/24").split("/")[1]),
                                    server_port=srv.get("port", 51820),
                                    clients=peers,
                                )
                                adapter.deploy_config(cfg)
                                recovered = True
                                _recover_log.info("Auto-deployed WireGuard config (was missing)")
                            else:
                                _recover_log.warning("Vault has no server private_key — cannot auto-deploy config")
                    else:
                        _recover_log.warning("Vault not unlocked — cannot auto-deploy config")
                except Exception as _exc:
                    _recover_log.error("Config auto-deploy failed: %s", _exc)
                if not recovered:
                    raise _ApiError(
                        "WireGuard configuration not found. "
                        "Go to Settings \u2192 Regenerate Config to "
                        "re-deploy from vault, then try again.",
                        500,
                    )
            try:
                adapter.enable_tunnel_service(_WG_IFACE)
            except Exception as exc:
                raise _ApiError(f"Failed to install tunnel service: {exc}", 500)
        start_result = subprocess.run(
            ["sc.exe", "start", svc],
            check=False, capture_output=True, timeout=15,
            creationflags=_SP_FLAGS,
        )
        if start_result.returncode != 0:
            err = (start_result.stderr or start_result.stdout or b"").decode("utf-8", errors="replace")
            if "1056" not in err:
                raise _ApiError(f"Failed to start service: {err.strip()}", 500)
        # sc.exe start is async — wait for service to reach RUNNING state
        import time
        for _ in range(10):
            time.sleep(1)
            poll = subprocess.run(
                ["sc.exe", "query", svc],
                capture_output=True, text=True, timeout=5,
                creationflags=_SP_FLAGS,
            )
            if poll.returncode == 0 and "RUNNING" in poll.stdout:
                break
        AuditLog(_s._AUDIT_PATH).log("start", {"interface": _WG_IFACE},
                                      actor=_session.get("admin_id", "owner"))
        return {"ok": True}
    if check.returncode == 0:
        return {"ok": True, "note": "already running"}
    try:
        result = subprocess.run(
            _sudo([_resolve_wg_tool("wg-quick"), "up", _WG_IFACE]),
            check=False, capture_output=True, timeout=30,
        )
        if result.returncode == 0:
            AuditLog(_s._AUDIT_PATH).log("start", {"interface": _WG_IFACE},
                                          actor=_session.get("admin_id", "owner"))
            return {"ok": True}
        err = result.stderr.decode("utf-8", errors="replace")
        raise _ApiError(f"Failed to start: {err}", 500)
    except FileNotFoundError:
        raise _ApiError("wg-quick not found -- is WireGuard installed?", 500)


def _h_terminate(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_server_mode()
    from wireseal.security.audit import AuditLog
    if sys.platform == "win32":
        svc = f"WireGuardTunnel${_WG_IFACE}"
        stop_result = subprocess.run(
            ["sc.exe", "stop", svc],
            check=False, capture_output=True, timeout=15,
            creationflags=_SP_FLAGS,
        )
        AuditLog(_s._AUDIT_PATH).log("terminate", {"interface": _WG_IFACE},
                                      actor=_session.get("admin_id", "owner"))
        return {"ok": True}
    try:
        subprocess.run(
            _sudo([_resolve_wg_tool("wg-quick"), "down", _WG_IFACE]),
            check=True, capture_output=True, timeout=15,
        )
        AuditLog(_s._AUDIT_PATH).log("terminate", {"interface": _WG_IFACE},
                                      actor=_session.get("admin_id", "owner"))
        return {"ok": True}
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode() if exc.stderr else ""
        if "not a WireGuard interface" in stderr or "does not exist" in stderr:
            return {"ok": True, "note": "interface was already down"}
        raise _ApiError("Failed to stop WireGuard interface.", 500)
    except FileNotFoundError:
        raise _ApiError("wg-quick not found -- is WireGuard installed?", 500)


def _h_update_endpoint(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_server_mode()
    body = req._json()
    endpoint = body.get("endpoint")
    if not endpoint:
        try:
            from wireseal.dns.ip_resolver import resolve_public_ip
            endpoint = str(resolve_public_ip())
        except Exception as exc:
            raise _ApiError("Could not auto-detect public IP.", 500)
    else:
        endpoint = _validate_endpoint(endpoint)
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id = _session.get("admin_id", "owner")
    from wireseal.security.audit import AuditLog
    try:
        with vault.open(passphrase) as state:
            state.server["endpoint"] = endpoint
            vault.save(state, passphrase)
            with _lock:
                _session["cache"] = _refresh_cache(state)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(f"Vault read/save failed: {exc}", 500)
    try:
        AuditLog(_s._AUDIT_PATH).log(
            "update-endpoint", {"endpoint": endpoint}, actor=_actor_id
        )
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)
    return {"ok": True, "endpoint": endpoint}


def _h_change_port(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    _require_server_mode()
    body = req._json()
    try:
        new_port = int(body.get("port", 0))
    except (TypeError, ValueError):
        raise _ApiError("Port must be an integer 1-65535.", 400)
    _ok, port_warning = _validate_wg_port(new_port)
    confirm_warning = bool(body.get("confirm_warning", False))
    if port_warning and not confirm_warning:
        raise _ApiError(
            f"Port {new_port}: {port_warning} "
            f"Resubmit with `confirm_warning: true` to proceed.", 400
        )
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        _actor_id = _session.get("admin_id", "owner")
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.platform.detect import get_adapter
    from wireseal.security.audit import AuditLog
    warnings: list[str] = []
    old_port: int | None = None
    server_cfg: str | None = None
    subnet_str: str | None = None
    try:
        with vault.open(passphrase) as state:
            old_port = int(state.server.get("port", 51820))
            if old_port == new_port:
                raise _ApiError(
                    f"Port {new_port} matches current port -- nothing to do.", 400
                )
            if "ip" not in state.server or "private_key" not in state.server:
                raise _ApiError(
                    "Server vault is missing required keys "
                    "(ip / private_key). Run init or restore vault.",
                    500,
                )
            if "subnet" not in state.ip_pool:
                raise _ApiError(
                    "Server vault is missing ip_pool.subnet. Run init.", 500
                )
            subnet_str = state.ip_pool["subnet"]
            try:
                prefix_length = int(subnet_str.split("/")[1])
            except (IndexError, ValueError):
                raise _ApiError(
                    f"Vault subnet is malformed: {subnet_str!r}", 500
                )
            peers = [
                {
                    "name": n,
                    "public_key": _extract(d["public_key"]),
                    "psk": _extract(d["psk"]),
                    "ip": d["ip"],
                }
                for n, d in state.clients.items()
            ]
            try:
                server_cfg = ConfigBuilder().render_server_config(
                    server_private_key=_extract(state.server["private_key"]),
                    server_ip=state.server["ip"],
                    prefix_length=prefix_length,
                    server_port=new_port,
                    clients=peers,
                )
            except Exception as exc:
                raise _ApiError(
                    f"wg0.conf render failed (vault unchanged): {exc}", 500
                )
            state.server["port"] = new_port
            vault.save(state, passphrase)
            with _lock:
                _session["cache"] = _refresh_cache(state)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(f"Vault read/save failed: {exc}", 500)
    adapter = None
    try:
        adapter = get_adapter()
        adapter.check_privileges()
    except Exception as exc:
        warnings.append(f"Platform adapter unavailable: {exc}")
    if adapter is not None and server_cfg is not None:
        try:
            adapter.deploy_config(server_cfg)
        except Exception as exc:
            warnings.append(f"Config deploy failed: {exc}")
        try:
            adapter.apply_firewall_rules(new_port, _WG_IFACE, subnet_str)
        except Exception as exc:
            warnings.append(f"Firewall reconcile skipped: {exc}")
        if hasattr(adapter, "open_firewalld_port"):
            try:
                adapter.open_firewalld_port(new_port)
            except Exception as exc:
                warnings.append(f"firewalld port open skipped: {exc}")
    try:
        wg_warning = _reload_wireguard()
        if wg_warning:
            warnings.append(wg_warning)
    except Exception as exc:
        warnings.append(f"Tunnel restart failed: {exc}")
    try:
        AuditLog(_s._AUDIT_PATH).log(
            "change-port",
            {"old_port": old_port, "new_port": new_port,
             "warnings": warnings},
            actor=_actor_id,
        )
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)
    return {
        "ok": True,
        "old_port": old_port,
        "new_port": new_port,
        "warnings": warnings if warnings else None,
        "port_warning": port_warning,
        "note": "Re-export / re-scan client QR codes -- peers cache the old endpoint.",
    }


def _h_service_status(req: "_Handler", _groups: tuple) -> dict:
    _require_server_mode()
    _require_unlocked()
    adapter = _service_adapter_or_die()
    return {"ok": True, **adapter.api_service_status()}


def _h_service_install(req: "_Handler", _groups: tuple) -> dict:
    _require_server_mode()
    _require_unlocked()
    adapter = _service_adapter_or_die()
    body = req._json()
    bind = body.get("bind") or "127.0.0.1"
    try:
        port = int(body.get("port") or 8080)
    except (TypeError, ValueError):
        raise _ApiError("port must be an integer.", 400)
    autostart = bool(body.get("autostart", True))
    try:
        adapter.install_api_service(bind=bind, port=port, autostart=autostart, vault_dir=str(_VAULT_DIR))
    except Exception as exc:
        raise _ApiError(f"Service install failed: {exc}", 500)
    from wireseal.security.audit import AuditLog
    try:
        AuditLog(_s._AUDIT_PATH).log(
            "service-install",
            {"bind": bind, "port": port, "autostart": autostart},
            actor=_session.get("admin_id", "owner"),
        )
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)
    return {"ok": True, **adapter.api_service_status()}


def _h_service_uninstall(req: "_Handler", _groups: tuple) -> dict:
    _require_server_mode()
    _require_unlocked()
    adapter = _service_adapter_or_die()
    try:
        adapter.uninstall_api_service()
    except Exception as exc:
        raise _ApiError(f"Service uninstall failed: {exc}", 500)
    from wireseal.security.audit import AuditLog
    try:
        AuditLog(_s._AUDIT_PATH).log(
            "service-uninstall", {},
            actor=_session.get("admin_id", "owner"),
        )
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)
    return {"ok": True}


def _h_service_start(req: "_Handler", _groups: tuple) -> dict:
    _require_server_mode()
    _require_unlocked()
    adapter = _service_adapter_or_die()
    try:
        adapter.start_api_service()
    except Exception as exc:
        raise _ApiError(f"Service start failed: {exc}", 500)
    return {"ok": True, **adapter.api_service_status()}


def _h_service_stop(req: "_Handler", _groups: tuple) -> dict:
    _require_server_mode()
    _require_unlocked()
    adapter = _service_adapter_or_die()
    try:
        adapter.stop_api_service()
    except Exception as exc:
        raise _ApiError(f"Service stop failed: {exc}", 500)
    return {"ok": True, **adapter.api_service_status()}


_SERVICE_ACTIONS = frozenset({
    "start", "stop", "restart", "reload", "status", "enable", "disable",
})


def _h_uninstall(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    _require_confirmation(body)
    if body.get("confirm") != "UNINSTALL":
        raise _ApiError(
            "POST body must include {\"confirm\": \"UNINSTALL\"} to proceed.",
            400,
        )
    purge = bool(body.get("purge", False))
    import platform as _platform
    import shutil
    import threading
    import time as _time
    import os as _os
    system = _platform.system()
    import sys as _sys
    scripts_dir: Path | None = None
    if getattr(_sys, "frozen", False):
        meipass = getattr(_sys, "_MEIPASS", None)
        if meipass:
            scripts_dir = Path(meipass) / "scripts"
    if scripts_dir is None or not scripts_dir.exists():
        try:
            scripts_dir = Path(__file__).resolve().parents[2] / "scripts"
        except (IndexError, OSError):
            scripts_dir = Path("scripts")
    if system == "Linux":
        script = scripts_dir / "uninstall-linux.sh"
        cmd = ["bash", str(script), "--yes"]
        if purge:
            cmd.append("--purge")
    elif system == "Darwin":
        script = scripts_dir / "uninstall-macos.sh"
        cmd = ["bash", str(script), "--yes"]
        if purge:
            cmd.append("--purge")
    elif system == "Windows":
        script = scripts_dir / "uninstall-windows.ps1"
        cmd = [
            "powershell.exe", "-ExecutionPolicy", "Bypass",
            "-File", str(script), "-Yes",
        ]
        if purge:
            cmd.append("-Purge")
    else:
        raise _ApiError(f"Unsupported platform: {system}", 501)
    if not script.exists():
        raise _ApiError(
            f"Uninstall script not found at {script}. Frozen-binary "
            "users should run the OS-native uninstaller from "
            "Add/Remove Programs / .pkg / .deb instead.",
            500,
        )
    interpreter = cmd[0]
    if not shutil.which(interpreter):
        raise _ApiError(
            f"Required interpreter '{interpreter}' not found on PATH.", 500
        )
    from wireseal.security.audit import AuditLog
    actor = _session.get("admin_id", "owner")
    try:
        AuditLog(_s._AUDIT_PATH).log(
            "uninstall", {"system": system, "purge": purge}, actor=actor,
        )
    except Exception as _audit_exc:
        logging.getLogger("wireseal.audit").warning("Audit log write failed: %s", _audit_exc)
    spawn_kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if system == "Windows":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        spawn_kwargs["creationflags"] = (
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        )
    else:
        spawn_kwargs["start_new_session"] = True
    try:
        subprocess.Popen(cmd, **spawn_kwargs)
    except Exception as exc:
        raise _ApiError(f"Failed to spawn uninstall script: {exc}", 500)
    def _delayed_exit() -> None:
        _time.sleep(2.0)
        _os._exit(0)
    threading.Thread(target=_delayed_exit, daemon=True).start()
    return {
        "ok": True,
        "system": system,
        "purge": purge,
        "note": "Uninstall started. The API server is shutting down. "
                "Refresh this page after a few seconds -- it should fail "
                "to connect once the service is gone.",
    }


# ------------------------------------------------------------------
# Regenerate WireGuard config from vault
# ------------------------------------------------------------------

def _h_regenerate_config(req: "_Handler", _groups: tuple) -> dict:
    """Re-deploy wg0.conf from vault state.

    Useful when the config file is missing (DPAPI wipe, accidental
    deletion, fresh machine) and auto-recovery didn't trigger.
    """
    _require_unlocked()
    _require_server_mode()
    from wireseal.security.audit import AuditLog
    from wireseal.platform.detect import get_adapter
    from wireseal.core.config_builder import ConfigBuilder

    adapter = get_adapter()
    log = logging.getLogger("wireseal.service")

    with _lock:
        vault = _session.get("vault")
        pp    = _session.get("passphrase")
        aid   = _session.get("admin_id", "owner")
    if not vault or not pp:
        raise _ApiError("Vault is not unlocked.", 401)

    try:
        with vault.open(pp, admin_id=aid) as st:
            srv = st.data.get("server") or {}
            pk  = srv.get("private_key")
            if not pk:
                raise _ApiError(
                    "Vault has no server private key. "
                    "Run initial setup again (Fresh Start → re-initialise).",
                    500,
                )
            _ext = lambda v: v.expose_secret().decode("ascii") if hasattr(v, "expose_secret") else str(v)
            peers = [
                {"name": n, "public_key": _ext(d["public_key"]),
                 "psk": _ext(d["psk"]), "ip": d["ip"]}
                for n, d in (st.data.get("clients") or {}).items()
                if d.get("status", "active") == "active"
            ]
            pool = st.data.get("ip_pool") or {}
            cfg = ConfigBuilder().render_server_config(
                server_private_key=_ext(pk),
                server_ip=srv["ip"],
                prefix_length=int(pool.get("subnet", "10.0.0.0/24").split("/")[1]),
                server_port=srv.get("port", 51820),
                clients=peers,
            )
            path = adapter.deploy_config(cfg)
    except _ApiError:
        raise
    except Exception as exc:
        log.error("Config regeneration failed: %s", exc)
        raise _ApiError(f"Config regeneration failed: {exc}", 500)

    log.info("WireGuard config regenerated manually via API")
    AuditLog(_s._AUDIT_PATH).log(
        "regenerate-config", {"path": str(path)},
        actor=_session.get("admin_id", "owner"),
    )
    return {"ok": True, "path": str(path)}
