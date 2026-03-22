"""WireSeal REST API server — stdlib only, no extra dependencies.

Run via ``wireseal serve`` (requires root/admin like all wireseal commands).
Listens on 127.0.0.1:8080 by default.

All routes except GET /api/vault-info require an unlocked vault.
Unlock by calling POST /api/unlock with the vault passphrase.

Endpoints
---------
GET  /api/vault-info              vault exists? locked?
POST /api/init                    first-time setup
POST /api/unlock                  load vault into memory
POST /api/lock                    wipe in-memory vault state
GET  /api/status                  wg show + vault clients
GET  /api/clients                 list clients
POST /api/clients                 add-client
DELETE /api/clients/<name>        remove-client
GET  /api/clients/<name>/qr       client QR as base64 PNG + raw config
GET  /api/audit-log               last 100 audit log entries
POST /api/change-passphrase       re-encrypt vault
POST /api/terminate               wg-quick down
POST /api/fresh-start             destroy vault + configs
POST /api/update-endpoint         update stored public IP
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Static frontend helpers
# ---------------------------------------------------------------------------

_MIME: dict[str, str] = {
    ".html":  "text/html; charset=utf-8",
    ".js":    "application/javascript",
    ".mjs":   "application/javascript",
    ".css":   "text/css",
    ".svg":   "image/svg+xml",
    ".png":   "image/png",
    ".jpg":   "image/jpeg",
    ".ico":   "image/x-icon",
    ".json":  "application/json",
    ".woff":  "font/woff",
    ".woff2": "font/woff2",
    ".ttf":   "font/ttf",
    ".txt":   "text/plain",
}


def _get_dist_dir() -> Path | None:
    """Locate the bundled React dashboard dist directory.

    Checks two locations in order:
    1. PyInstaller one-file bundle  → sys._MEIPASS / dashboard
    2. Development checkout         → <repo root> / Dashboard / dist
    """
    # PyInstaller sets _MEIPASS to the temp extraction directory
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        d = Path(meipass) / "dashboard"
        if d.is_dir():
            return d

    # Development: api.py lives at src/wireseal/api.py → go up 3 levels
    dev = Path(__file__).parent.parent.parent / "Dashboard" / "dist"
    if dev.is_dir():
        return dev

    return None

# ---------------------------------------------------------------------------
# Module-level session state
# ---------------------------------------------------------------------------

_lock = threading.RLock()

_session: dict = {
    "vault":      None,   # Vault instance (path + methods)
    "passphrase": None,   # SecretBytes kept in memory
    "cache":      None,   # Non-secret snapshot for fast reads
}

_VAULT_DIR  = Path.home() / ".wireseal"
_VAULT_PATH = _VAULT_DIR / "vault.enc"
_AUDIT_PATH = _VAULT_DIR / "audit.log"
_WG_IFACE   = "wg0"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _ApiError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def _require_unlocked() -> None:
    if _session["vault"] is None:
        raise _ApiError("Vault is locked. POST /api/unlock first.", 401)


def _refresh_cache(state: Any) -> dict:
    """Build a non-secret snapshot from an open VaultState."""
    return {
        "server": {
            "ip":       state.server.get("ip", ""),
            "subnet":   state.server.get("subnet",
                            state.ip_pool.get("subnet", "")),
            "port":     state.server.get("port", 51820),
            "endpoint": state.server.get("endpoint", ""),
            "duckdns":  state.server.get("duckdns_domain", ""),
        },
        "clients": {
            name: {"ip": data["ip"]}
            for name, data in state.clients.items()
        },
        "ip_pool": dict(state.ip_pool),
    }


def _extract(value: Any) -> str:
    """Return plain str from either str or SecretBytes."""
    from wireseal.security.secret_types import SecretBytes
    if isinstance(value, SecretBytes):
        return value.expose_secret().decode("utf-8")
    return str(value)


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


def _h_vault_info(req: "_Handler", _groups: tuple) -> dict:
    return {
        "initialized": _VAULT_PATH.exists(),
        "locked":      _session["vault"] is None,
        "interface":   _WG_IFACE,
    }


def _h_init(req: "_Handler", _groups: tuple) -> dict:
    if _VAULT_PATH.exists():
        raise _ApiError("Vault already exists. Use /api/unlock.", 409)

    body           = req._json()
    passphrase_str = body.get("passphrase", "")
    if len(passphrase_str) < 12:
        raise _ApiError("Passphrase must be at least 12 characters.", 400)

    subnet   = body.get("subnet", "10.0.0.0/24")
    port     = int(body.get("port", 51820))
    endpoint = body.get("endpoint") or None

    from wireseal.security.secret_types  import SecretBytes
    from wireseal.security.secrets_wipe  import wipe_string
    from wireseal.security.vault         import Vault
    from wireseal.security.audit         import AuditLog
    from wireseal.core.keygen            import generate_keypair
    from wireseal.core.ip_pool           import IPPool
    from wireseal.core.config_builder    import ConfigBuilder
    from wireseal.platform.detect        import get_adapter

    passphrase = SecretBytes(bytearray(passphrase_str.encode()))
    try:
        if endpoint is None:
            try:
                from wireseal.dns.ip_resolver import resolve_public_ip
                endpoint = str(resolve_public_ip())
            except Exception:
                endpoint = None

        priv_key, pub_key_bytes = generate_keypair()
        pub_key_str  = pub_key_bytes.decode("ascii")
        priv_key_str = priv_key.expose_secret().decode("ascii")

        pool      = IPPool(subnet)
        server_ip = pool.server_ip

        initial_state = {
            "schema_version": 1,
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

        vault = Vault.create(_VAULT_PATH, passphrase, initial_state)

        adapter = get_adapter()
        adapter.check_privileges()

        config = ConfigBuilder().render_server_config(
            server_private_key=priv_key_str,
            server_ip=server_ip,
            prefix_length=int(pool.subnet_str.split("/")[1]),
            server_port=port,
            clients=[],
        )
        adapter.deploy_config(config)

        config_hash = hashlib.sha256(config.encode()).hexdigest()
        with vault.open(passphrase) as st:
            st.integrity["server"] = config_hash
            vault.save(st, passphrase)

        adapter.install_wireguard()
        adapter.apply_firewall_rules(port, _WG_IFACE, pool.subnet_str)
        adapter.enable_tunnel_service(_WG_IFACE)

        AuditLog(_AUDIT_PATH).log("init", {"subnet": subnet, "port": port})

        with vault.open(passphrase) as st:
            cache = _refresh_cache(st)
        with _lock:
            _session.update(vault=vault, passphrase=passphrase, cache=cache)
        passphrase = None  # ownership transferred to session

        return {
            "ok":         True,
            "server_ip":  server_ip,
            "subnet":     pool.subnet_str,
            "public_key": pub_key_str,
            "endpoint":   endpoint,
        }
    except _ApiError:
        raise
    except Exception as exc:
        if passphrase is not None:
            passphrase.wipe()
        wipe_string(passphrase_str)
        raise _ApiError(str(exc), 500)


def _h_unlock(req: "_Handler", _groups: tuple) -> dict:
    body           = req._json()
    passphrase_str = body.get("passphrase", "")
    if not passphrase_str:
        raise _ApiError("passphrase is required", 400)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.vault        import Vault
    from wireseal.security.audit        import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode()))
    vault = Vault(_VAULT_PATH)
    try:
        with vault.open(passphrase) as st:
            cache = _refresh_cache(st)
    except Exception as exc:
        passphrase.wipe()
        raise _ApiError(f"Incorrect passphrase: {exc}", 401)

    with _lock:
        if _session["passphrase"]:
            _session["passphrase"].wipe()
        _session.update(vault=vault, passphrase=passphrase, cache=cache)

    AuditLog(_AUDIT_PATH).log("unlock-web", {})
    return {"ok": True}


def _h_lock(req: "_Handler", _groups: tuple) -> dict:
    with _lock:
        if _session["passphrase"]:
            _session["passphrase"].wipe()
        _session.update(vault=None, passphrase=None, cache=None)
    return {"ok": True}


def _h_status(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    with _lock:
        cache = _session["cache"] or {}

    running = False
    peers: list[dict] = []
    try:
        result = subprocess.run(
            ["wg", "show"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            running = True
            peers = _parse_wg_show(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    ip_to_name = {
        data["ip"].split("/")[0]: name
        for name, data in cache.get("clients", {}).items()
    }
    for p in peers:
        ip = p.get("allowed_ips", "").split("/")[0]
        p["name"] = ip_to_name.get(ip, "unknown")

    return {
        "running":       running,
        "interface":     _WG_IFACE,
        "server_ip":     cache.get("server", {}).get("ip", ""),
        "endpoint":      cache.get("server", {}).get("endpoint", ""),
        "port":          cache.get("server", {}).get("port", 51820),
        "peers":         peers,
        "total_clients": len(cache.get("clients", {})),
    }


def _parse_wg_show(output: str) -> list[dict]:
    peers: list[dict] = []
    cur: dict | None = None
    for line in output.strip().splitlines():
        s = line.strip()
        if s.startswith("peer:"):
            if cur:
                peers.append(cur)
            cur = {
                "public_key_short": s.split(":", 1)[1].strip()[:12] + "...",
                "allowed_ips":      "",
                "last_handshake":   "never",
                "transfer_rx":      "0 B",
                "transfer_tx":      "0 B",
                "connected":        False,
            }
        elif cur:
            if s.startswith("allowed ips:"):
                cur["allowed_ips"] = s.split(":", 1)[1].strip()
            elif s.startswith("latest handshake:"):
                hs = s.split(":", 1)[1].strip()
                cur["last_handshake"] = hs
                cur["connected"] = any(x in hs for x in ("second", "minute"))
            elif s.startswith("transfer:"):
                parts = s.split(":", 1)[1].strip().split(",")
                if len(parts) == 2:
                    cur["transfer_rx"] = parts[0].replace("received", "").strip()
                    cur["transfer_tx"] = parts[1].replace("sent", "").strip()
    if cur:
        peers.append(cur)
    return peers


def _h_list_clients(req: "_Handler", _groups: tuple) -> list:
    _require_unlocked()
    with _lock:
        cache = _session["cache"] or {}
    return [
        {"name": n, "ip": d["ip"]}
        for n, d in cache.get("clients", {}).items()
    ]


def _h_add_client(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    name = body.get("name", "").strip()
    if not name:
        raise _ApiError("name is required", 400)
    if not re.fullmatch(r"^[a-zA-Z0-9-]{1,32}$", name):
        raise _ApiError(
            "Name must be alphanumeric + hyphens only, max 32 chars", 400
        )

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.core.keygen         import generate_keypair
    from wireseal.core.psk            import generate_psk
    from wireseal.core.ip_pool        import IPPool
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.atomic     import atomic_write
    from wireseal.security.audit      import AuditLog
    from wireseal.platform.detect     import get_adapter
    from wireseal.main import (
        _extract_secret_str,
        _resolve_client_endpoint,
        _reload_wireguard,
    )

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
        server_pub_key  = _extract_secret_str(state.server["public_key"])

        builder       = ConfigBuilder()
        client_config = builder.render_client_config(
            client_private_key=priv_key_str,
            client_ip=allocated_ip,
            dns_server=server_ip,
            server_public_key=server_pub_key,
            psk=psk_str,
            server_endpoint=server_endpoint,
        )

        clients_dir     = _VAULT_DIR / "clients"
        clients_dir.mkdir(parents=True, exist_ok=True)
        client_conf_path = clients_dir / f"{name}.conf"
        atomic_write(client_conf_path, client_config.encode(), mode=0o600)

        config_hash = hashlib.sha256(client_config.encode()).hexdigest()

        peers = [
            {
                "name":       n,
                "public_key": _extract_secret_str(d["public_key"]),
                "psk":        _extract_secret_str(d["psk"]),
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
            server_private_key=_extract_secret_str(state.server["private_key"]),
            server_ip=server_ip,
            prefix_length=int(state.ip_pool["subnet"].split("/")[1]),
            server_port=state.server["port"],
            clients=peers,
        )
        adapter = get_adapter()
        adapter.deploy_config(server_config)
        _reload_wireguard()

        state.clients[name] = {
            "private_key": priv_key_str,
            "public_key":  pub_key_str,
            "psk":         psk_str,
            "ip":          allocated_ip,
            "config_hash": config_hash,
        }
        state.ip_pool["allocated"]        = pool.get_allocated()
        state.integrity[f"client-{name}"] = config_hash
        vault.save(state, passphrase)

        AuditLog(_AUDIT_PATH).log("add-client", {"name": name, "ip": allocated_ip})

        with _lock:
            _session["cache"] = _refresh_cache(state)

    return {"name": name, "ip": allocated_ip}


def _h_remove_client(req: "_Handler", groups: tuple) -> dict:
    _require_unlocked()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.core.ip_pool        import IPPool
    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.security.audit      import AuditLog
    from wireseal.platform.detect     import get_adapter
    from wireseal.main import _extract_secret_str, _reload_wireguard

    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)

        revoked_ip = state.clients[name]["ip"]

        peers = [
            {
                "name":       n,
                "public_key": _extract_secret_str(d["public_key"]),
                "psk":        _extract_secret_str(d["psk"]),
                "ip":         d["ip"],
            }
            for n, d in state.clients.items()
            if n != name
        ]

        server_config = ConfigBuilder().render_server_config(
            server_private_key=_extract_secret_str(state.server["private_key"]),
            server_ip=state.server["ip"],
            prefix_length=int(state.ip_pool["subnet"].split("/")[1]),
            server_port=state.server["port"],
            clients=peers,
        )
        adapter = get_adapter()
        adapter.deploy_config(server_config)
        _reload_wireguard()

        pool = IPPool(state.ip_pool["subnet"])
        pool.load_state(state.ip_pool.get("allocated", {}))
        pool.release(revoked_ip)
        state.ip_pool["allocated"] = pool.get_allocated()

        del state.clients[name]
        state.integrity.pop(f"client-{name}", None)
        state.integrity.pop(f"client-{name}_verified", None)

        conf_path = _VAULT_DIR / "clients" / f"{name}.conf"
        try:
            conf_path.unlink(missing_ok=True)
        except OSError:
            pass

        vault.save(state, passphrase)
        AuditLog(_AUDIT_PATH).log("remove-client", {"name": name})

        with _lock:
            _session["cache"] = _refresh_cache(state)

    return {"ok": True}


def _h_client_qr(req: "_Handler", groups: tuple) -> dict:
    _require_unlocked()
    name = (groups[0] if groups else "").strip()
    if not name:
        raise _ApiError("client name is required", 400)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.core.config_builder import ConfigBuilder
    from wireseal.main import _extract_secret_str, _resolve_client_endpoint

    config_str = ""
    with vault.open(passphrase) as state:
        if name not in state.clients:
            raise _ApiError(f"Client '{name}' not found.", 404)
        cdata = state.clients[name]
        config_str = ConfigBuilder().render_client_config(
            client_private_key=_extract_secret_str(cdata["private_key"]),
            client_ip=cdata["ip"],
            dns_server=state.server["ip"],
            server_public_key=_extract_secret_str(state.server["public_key"]),
            psk=_extract_secret_str(cdata["psk"]),
            server_endpoint=_resolve_client_endpoint(state.server),
        )

    import qrcode
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(config_str)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_b64 = base64.b64encode(buf.getvalue()).decode()

    return {"name": name, "qr_png_b64": png_b64}


def _h_audit_log(req: "_Handler", _groups: tuple) -> dict:
    if not _AUDIT_PATH.exists():
        return {"entries": []}
    try:
        text    = _AUDIT_PATH.read_text()
        entries = []
        for line in text.strip().splitlines()[-100:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return {"entries": list(reversed(entries))}
    except OSError:
        return {"entries": []}


def _h_change_passphrase(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body        = req._json()
    current_str = body.get("current", "")
    new_str     = body.get("new", "")

    if len(new_str) < 12:
        raise _ApiError("New passphrase must be at least 12 characters.", 400)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe  import wipe_string
    from wireseal.security.audit         import AuditLog

    with _lock:
        vault = _session["vault"]

    old_passphrase = SecretBytes(bytearray(current_str.encode()))
    new_passphrase = SecretBytes(bytearray(new_str.encode()))
    try:
        vault.change_passphrase(old_passphrase, new_passphrase)
    except Exception as exc:
        old_passphrase.wipe()
        new_passphrase.wipe()
        wipe_string(current_str)
        wipe_string(new_str)
        raise _ApiError(str(exc), 401)

    with _lock:
        _session["passphrase"].wipe()
        _session["passphrase"] = new_passphrase
    old_passphrase.wipe()
    wipe_string(current_str)
    wipe_string(new_str)

    AuditLog(_AUDIT_PATH).log("change-passphrase", {})
    return {"ok": True}


def _h_terminate(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    try:
        subprocess.run(
            ["wg-quick", "down", _WG_IFACE],
            check=True, capture_output=True, timeout=15,
        )
        from wireseal.security.audit import AuditLog
        AuditLog(_AUDIT_PATH).log("terminate", {"interface": _WG_IFACE})
        return {"ok": True}
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode() if exc.stderr else ""
        if "not a WireGuard interface" in stderr or "does not exist" in stderr:
            return {"ok": True, "note": "interface was already down"}
        raise _ApiError(f"terminate failed: {stderr}", 500)
    except FileNotFoundError:
        raise _ApiError("wg-quick not found — is WireGuard installed?", 500)


def _h_fresh_start(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body = req._json()
    if body.get("confirm") != "CONFIRM":
        raise _ApiError('Send {"confirm":"CONFIRM"} to proceed.', 400)

    try:
        subprocess.run(
            ["wg-quick", "down", _WG_IFACE],
            check=False, capture_output=True, timeout=10,
        )
    except Exception:
        pass

    import shutil
    shutil.rmtree(_VAULT_DIR, ignore_errors=True)

    from wireseal.platform.detect import get_adapter
    try:
        cfg = get_adapter().get_config_path(_WG_IFACE)
        cfg.unlink(missing_ok=True)
    except Exception:
        pass

    with _lock:
        if _session["passphrase"]:
            _session["passphrase"].wipe()
        _session.update(vault=None, passphrase=None, cache=None)

    return {"ok": True}


def _h_update_endpoint(req: "_Handler", _groups: tuple) -> dict:
    _require_unlocked()
    body     = req._json()
    endpoint = body.get("endpoint")
    if not endpoint:
        try:
            from wireseal.dns.ip_resolver import resolve_public_ip
            endpoint = str(resolve_public_ip())
        except Exception as exc:
            raise _ApiError(f"Could not auto-detect public IP: {exc}", 500)

    with _lock:
        vault      = _session["vault"]
        passphrase = _session["passphrase"]

    from wireseal.security.audit import AuditLog
    with vault.open(passphrase) as state:
        state.server["endpoint"] = endpoint
        vault.save(state, passphrase)
        with _lock:
            _session["cache"] = _refresh_cache(state)

    AuditLog(_AUDIT_PATH).log("update-endpoint", {"endpoint": endpoint})
    return {"ok": True, "endpoint": endpoint}


# ---------------------------------------------------------------------------
# Routing table  — order matters for overlapping patterns
# ---------------------------------------------------------------------------

_ROUTES: list[tuple[str, re.Pattern, Any]] = [
    ("GET",    re.compile(r"^/api/vault-info$"),             _h_vault_info),
    ("POST",   re.compile(r"^/api/init$"),                   _h_init),
    ("POST",   re.compile(r"^/api/unlock$"),                 _h_unlock),
    ("POST",   re.compile(r"^/api/lock$"),                   _h_lock),
    ("GET",    re.compile(r"^/api/status$"),                 _h_status),
    ("GET",    re.compile(r"^/api/clients$"),                _h_list_clients),
    ("POST",   re.compile(r"^/api/clients$"),                _h_add_client),
    # QR must come before the generic DELETE so GET .../qr is matched first
    ("GET",    re.compile(r"^/api/clients/([^/]+)/qr$"),     _h_client_qr),
    ("DELETE", re.compile(r"^/api/clients/([^/]+)$"),        _h_remove_client),
    ("GET",    re.compile(r"^/api/audit-log$"),              _h_audit_log),
    ("POST",   re.compile(r"^/api/change-passphrase$"),      _h_change_passphrase),
    ("POST",   re.compile(r"^/api/terminate$"),              _h_terminate),
    ("POST",   re.compile(r"^/api/fresh-start$"),            _h_fresh_start),
    ("POST",   re.compile(r"^/api/update-endpoint$"),        _h_update_endpoint),
]

# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default access log
        pass

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise _ApiError(f"Invalid JSON: {exc}", 400)

    def _send(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path = self.path.split("?")[0]
        for route_method, pattern, handler in _ROUTES:
            if route_method != method:
                continue
            m = pattern.match(path)
            if m:
                try:
                    self._send(handler(self, m.groups()))
                except _ApiError as exc:
                    self._send({"error": str(exc)}, exc.status)
                except Exception as exc:
                    self._send({"error": f"Internal error: {exc}"}, 500)
                return
        self._send({"error": "Not found"}, 404)

    def _serve_static(self, path: str) -> None:
        """Serve a file from the bundled React dist directory."""
        dist = _get_dist_dir()
        if dist is None:
            body = b"Dashboard not bundled. Run 'npm run build' in Dashboard/."
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        rel = path.lstrip("/")
        file_path = (dist / rel) if rel else (dist / "index.html")

        # SPA fallback: unknown paths (e.g. /clients, /about) → index.html
        if not file_path.exists() or file_path.is_dir():
            file_path = dist / "index.html"

        if not file_path.exists():
            self.send_response(404)
            self.end_headers()
            return

        data = file_path.read_bytes()
        suffix = file_path.suffix.lower()
        mime = _MIME.get(suffix, "application/octet-stream")
        # Long-lived cache for hashed assets; no-cache for index.html
        cache = "no-cache, no-store" if suffix == ".html" else "public, max-age=31536000, immutable"

        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        # API routes take priority; everything else is served as static frontend
        if self.path.split("?")[0].startswith("/api/") or self.path.split("?")[0] == "/api":
            self._dispatch("GET")
        else:
            self._serve_static(self.path.split("?")[0])

    def do_POST(self):   self._dispatch("POST")
    def do_DELETE(self): self._dispatch("DELETE")


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start the WireSeal API server (blocking)."""
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"[wireseal] API server listening on http://{host}:{port}")
    print(f"[wireseal] Open your browser at http://{host}:{port}/")
    print("[wireseal] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        with _lock:
            if _session["passphrase"]:
                _session["passphrase"].wipe()
        server.server_close()
        print("\n[wireseal] Server stopped. Vault state wiped.")
