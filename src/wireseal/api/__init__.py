"""WireSeal REST API server"""
from __future__ import annotations

from . import _shared as _api_shared_module
from . import vault as _vault_module
from . import clients as _clients_module
from . import security as _security_module
from . import admin as _admin_module
from . import dns as _dns_module
from . import backup as _backup_module
from . import update as _update_module
from . import service as _service_module
from . import ssh as _ssh_module
from . import sftp as _sftp_module
from . import client_mode as _client_mode_module

# Re-export all names from _shared (before remaining code, so remaining code can use them)
for _api_shared_name in dir(_api_shared_module):
    if not _api_shared_name.startswith("__"):
        globals()[_api_shared_name] = getattr(_api_shared_module, _api_shared_name)

# Re-export all names from vault
for _vault_name in dir(_vault_module):
    if not _vault_name.startswith("__"):
        globals()[_vault_name] = getattr(_vault_module, _vault_name)

# Re-export all names from clients
for _clients_name in dir(_clients_module):
    if not _clients_name.startswith("__"):
        globals()[_clients_name] = getattr(_clients_module, _clients_name)

# Re-export all names from security
for _security_name in dir(_security_module):
    if not _security_name.startswith("__"):
        globals()[_security_name] = getattr(_security_module, _security_name)

# Re-export all names from admin
for _admin_name in dir(_admin_module):
    if not _admin_name.startswith("__"):
        globals()[_admin_name] = getattr(_admin_module, _admin_name)

# Re-export all names from dns
for _dns_name in dir(_dns_module):
    if not _dns_name.startswith("__"):
        globals()[_dns_name] = getattr(_dns_module, _dns_name)

# Re-export all names from backup
for _backup_name in dir(_backup_module):
    if not _backup_name.startswith("__"):
        globals()[_backup_name] = getattr(_backup_module, _backup_name)

# Re-export all names from update
for _update_name in dir(_update_module):
    if not _update_name.startswith("__"):
        globals()[_update_name] = getattr(_update_module, _update_name)

# Re-export all names from service
for _service_name in dir(_service_module):
    if not _service_name.startswith("__"):
        globals()[_service_name] = getattr(_service_module, _service_name)

# Re-export all names from ssh
for _ssh_name in dir(_ssh_module):
    if not _ssh_name.startswith("__"):
        globals()[_ssh_name] = getattr(_ssh_module, _ssh_name)

# Re-export all names from sftp
for _sftp_name in dir(_sftp_module):
    if not _sftp_name.startswith("__"):
        globals()[_sftp_name] = getattr(_sftp_module, _sftp_name)

# Re-export all names from client_mode
for _client_mode_name in dir(_client_mode_module):
    if not _client_mode_name.startswith("__"):
        globals()[_client_mode_name] = getattr(_client_mode_module, _client_mode_name)


"""WireSeal REST API server ΓÇö stdlib only, no extra dependencies.



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






import base64

import datetime

import hashlib

import io

import json

import os

import re

import subprocess

import sys

import threading

import time as _time

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pathlib import Path

from typing import Any



# ---------------------------------------------------------------------------

# Static frontend helpers

# ---------------------------------------------------------------------------






















from wireseal.security.totp import (  # noqa: E402 ΓÇö placed after stdlib imports

    generate_totp_secret,

    totp_uri,

    verify_totp,

    generate_backup_codes,

    hash_backup_code,

    verify_backup_code,

    secret_to_b32,

    b32_to_secret,

)

from wireseal.backup.manager import BackupManager as _BackupManager



# Module-level BackupManager singleton (stateless, safe to share)




# ---------------------------------------------------------------------------

# Module-level session state

# ---------------------------------------------------------------------------

















if hasattr(os, "register_at_fork"):

    os.register_at_fork(after_in_child=_wipe_session_on_fork)





# Pending TOTP enrollment state keyed by admin_id.

# Populated by _h_totp_enroll_begin, consumed by _h_totp_enroll_confirm.

# Entries are {secret: bytes, used_codes: set[str]}.















# SEC-FIX-1: SSH target allowlist ΓÇö prevents admins from proxying to arbitrary

# hosts. The allowlist is stored in _VAULT_DIR so it lives alongside the vault

# and is writable only by the process owner.


# SSH keys stored in vault state._data["ssh_keys"] via client.ssh_keys module



# Regex that a valid SSH target hostname must match (no wildcards, no slashes).




# PIN-based quick unlock ΓÇö encrypts the passphrase with a PIN-derived key.

# After 5 wrong attempts the PIN file is wiped (must use full passphrase).

# SEC-014 / SEC-023: failures are tracked per-IP (not globally) and

# check-then-increment is atomic under _lock so two concurrent wrong PINs

# from different IPs can't both slip past the 5-attempt threshold.






# ---------------------------------------------------------------------------

# Rate limiting for /api/unlock ΓÇö prevents brute-force passphrase guessing.

# Tracks failed attempts per IP in a sliding window. After _UNLOCK_MAX

# failures within _UNLOCK_WINDOW seconds, returns 429 Too Many Requests.

# ---------------------------------------------------------------------------






# Rate-limit heartbeat resets: maps client_name ΓåÆ last_reset_timestamp





# M-20: Rate limit client creation ΓÇö max 50 per hour per admin session





# TOTP anti-replay: maps admin_id ΓåÆ set of recently-used 6-digit codes.

# Guarded by _lock.  Cleared on lock to prevent unbounded growth.




# TOTP session validity: maps admin_id ΓåÆ monotonic timestamp of last TOTP

# verification.  While within _TOTP_SESSION_HOURS, sensitive actions skip

# re-prompting for a TOTP code (TOTP-plan ┬º8.2).  Guarded by _lock.

# Cleared on vault lock.





# Maps peer public_key ΓåÆ last_handshake_seconds from previous _h_status call.

# Used to detect new handshake events for the audit log (DASH-06).




# SFTP per-session rate limiting: 50ms min interval, 50MB/min transfer









# ---------------------------------------------------------------------------

# Security hardening constants & helpers (SEC-002, 004, 005, 007, 008, 010, 018)

# ---------------------------------------------------------------------------



# SEC-004: hard cap on request body size ΓÇö prevents OOM DoS via large

# Content-Length. 1 MiB is 16x the largest legitimate body (a WireGuard

# config import of ~40 KiB) and comfortably fits all vault backup payloads.




# SEC-002: fresh-start challenge lives on the filesystem inside _VAULT_DIR.

# Possession of the token proves local filesystem read access ΓÇö a browser

# CSRF attack cannot read it. Token rotates on every challenge request and

# is consumed (deleted) on successful fresh-start.





# SEC-008: admin/file/* may only touch files under these roots, resolved

# once at import. Callers submit a path; we verify it resolves inside one

# of these trees (after following symlinks) before shelling out to cat/tee.




# SEC-008: cap admin read size to prevent exfiltrating huge files in one shot.

















# SEC-016: serialise /api/init concurrency so two racing POSTs cannot both

# observe an absent vault and both call Vault.create ΓÇö the second would

# silently discard the first caller's passphrase, leaving that session

# holding a passphrase that no longer decrypts the vault.














import threading as _threading


# {admin_id: {"attempts": [timestamps], "lockout_until": float, "session_count": int}}


# {admin_id: [timestamps]}









# ---------------------------------------------------------------------------

# Helpers

# ---------------------------------------------------------------------------


















def _h_health(req: "_Handler", _groups: tuple) -> dict:

    """Lightweight health endpoint for monitoring — no auth, no subprocess."""

    import time

    uptime = int(time.monotonic() - _server_start_time) if _server_start_time else 0

    try:

        from wireseal import __version__ as _wireseal_version

    except Exception:

        _wireseal_version = "unknown"

    import shutil

    disk_free = -1

    try:

        du = shutil.disk_usage(str(_VAULT_DIR) if _VAULT_DIR else ".")

        disk_free = du.free

    except Exception:

        pass

    mem_avail = -1

    import sys as _sys

    try:

        if _sys.platform == "win32":

            import ctypes as _ctypes

            class _MEMORYSTATUSEX(_ctypes.Structure):

                _fields_ = [

                    ("dwLength", _ctypes.c_ulong),

                    ("dwMemoryLoad", _ctypes.c_ulong),

                    ("ullTotalPhys", _ctypes.c_ulonglong),

                    ("ullAvailPhys", _ctypes.c_ulonglong),

                    ("ullTotalPageFile", _ctypes.c_ulonglong),

                    ("ullAvailPageFile", _ctypes.c_ulonglong),

                    ("ullTotalVirtual", _ctypes.c_ulonglong),

                    ("ullAvailVirtual", _ctypes.c_ulonglong),

                    ("sullAvailExtendedVirtual", _ctypes.c_ulonglong),

                ]

            _mem = _MEMORYSTATUSEX()

            _mem.dwLength = _ctypes.sizeof(_MEMORYSTATUSEX)

            _ctypes.windll.kernel32.GlobalMemoryStatusEx(_ctypes.byref(_mem))

            mem_avail = _mem.ullAvailPhys

        elif _sys.platform == "linux":

            with open("/proc/meminfo") as _f:

                for _line in _f:

                    if _line.startswith("MemAvailable:"):

                        mem_avail = int(_line.split()[1]) * 1024

                        break

    except Exception:

        pass

    return {

        "status": "ok",

        "vault_initialized": _VAULT_PATH.exists(),

        "vault_locked": _session["vault"] is None,

        "uptime_seconds": uptime,

        "version": _wireseal_version,

        "disk_free_bytes": disk_free,

        "memory_available_bytes": mem_avail,

    }


def _h_ready(req: "_Handler", _groups: tuple) -> dict:

    """Readiness probe — is the vault unlocked and WireGuard running?

    Separate from /api/health (which is purely about process liveness).
    Monitoring tools should check this before routing traffic.
    """

    vault_unlocked = _session["vault"] is not None

    wg_running = False
    if vault_unlocked:
        try:
            import subprocess as _sp
            _sp.run(
                ["wg", "show", _WG_IFACE],
                capture_output=True, timeout=5, check=True,
            )
            wg_running = True
        except Exception:
            pass

    return {
        "ready": vault_unlocked and wg_running,
        "vault_unlocked": vault_unlocked,
        "wg_running": wg_running,
    }



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

        audit = AuditLog(_AUDIT_PATH)

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

                except Exception:

                    pass  # Audit failures never crash the status endpoint

        _peer_handshake_cache = new_cache

    except Exception:

        pass  # Never crash _h_status due to audit/cache logic





def _h_status(req: "_Handler", _groups: tuple) -> dict:

    _require_unlocked()

    with _lock:

        cache = _session["cache"] or {}



    running = False

    peers: list[dict] = []

    try:

        result = subprocess.run(

            _sudo(["wg", "show", _WG_IFACE]), capture_output=True, text=True, timeout=5,

            creationflags=_SP_FLAGS,

        )

        # wg show <iface> returns 0 only if the interface exists and is active.

        # wg show (no args) returns 0 even with no interfaces.

        if result.returncode == 0 and result.stdout.strip():

            running = True

            peers = _parse_wg_show(result.stdout)

    except (FileNotFoundError, subprocess.TimeoutExpired):

        pass



    # Windows fallback: wg CLI may not be in PATH; check service status instead

    if not running and sys.platform == "win32":

        try:

            sc_result = subprocess.run(

                ["sc.exe", "query", f"WireGuardTunnel${_WG_IFACE}"],

                capture_output=True, text=True, timeout=5,

                creationflags=_SP_FLAGS,

            )

            if sc_result.returncode == 0 and "RUNNING" in sc_result.stdout:

                running = True

        except (FileNotFoundError, subprocess.TimeoutExpired):

            pass



    ip_to_name = {

        data["ip"].split("/")[0]: name

        for name, data in cache.get("clients", {}).items()

    }

    for p in peers:

        ip = p.get("allowed_ips", "").split("/")[0]

        p["name"] = ip_to_name.get(ip, "unknown")



    # DASH-06: Detect new handshake events by comparing against previous poll.

    _detect_new_handshakes(peers)



    return {

        "running":       running,

        "interface":     _WG_IFACE,

        "server_ip":     cache.get("server", {}).get("ip", ""),

        "endpoint":      cache.get("server", {}).get("endpoint", ""),

        "port":          cache.get("server", {}).get("port", 51820),

        "lan_subnet":    cache.get("server", {}).get("lan_subnet", ""),

        "peers":         peers,

        "total_clients": len(cache.get("clients", {})),

    }



















































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































_ROUTES: list[tuple[str, re.Pattern, Any]] = [

    ("GET",    re.compile(r"^/api/health$"),                 _h_health),

    ("GET",    re.compile(r"^/api/ready$"),                  _h_ready),

    ("GET",    re.compile(r"^/api/vault-info$"),             _h_vault_info),

    ("POST",   re.compile(r"^/api/init$"),                   _h_init),

    ("POST",   re.compile(r"^/api/unlock$"),                 _h_unlock),

    ("POST",   re.compile(r"^/api/lock$"),                   _h_lock),

    ("GET",    re.compile(r"^/api/status$"),                 _h_status),

    ("GET",    re.compile(r"^/api/admins$"),                                     _h_list_admins),

    ("POST",   re.compile(r"^/api/admins$"),                                     _h_add_admin),

    ("GET",    re.compile(r"^/api/admins/totp-status$"),                         _h_admins_totp_status),

    ("POST",   re.compile(r"^/api/admins/([^/]+)/change-passphrase$"),           _h_change_admin_passphrase),

    ("DELETE", re.compile(r"^/api/admins/([^/]+)$"),                             _h_remove_admin),

    ("GET",    re.compile(r"^/api/clients$"),                _h_list_clients),

    ("POST",   re.compile(r"^/api/clients$"),                _h_add_client),

    # QR must come before the generic DELETE so GET .../qr is matched first

    ("GET",    re.compile(r"^/api/clients/([^/]+)/qr$"),     _h_client_qr),

    ("GET",    re.compile(r"^/api/clients/([^/]+)/config/download$"), _h_client_config_download),

    ("GET",    re.compile(r"^/api/clients/([^/]+)/config$"), _h_client_config),

    ("POST",   re.compile(r"^/api/clients/([^/]+)/rotate$"), _h_rotate_client_keys),

    ("POST",   re.compile(r"^/api/clients/([^/]+)/ttl$"),       _h_set_client_ttl),

    ("GET",    re.compile(r"^/api/clients/([^/]+)/details$"), _h_get_client_details),

    ("PUT",    re.compile(r"^/api/clients/([^/]+)$"),         _h_edit_client),

    ("POST",   re.compile(r"^/api/clients/([^/]+)/extend$"),  _h_extend_client),

    ("POST",   re.compile(r"^/api/clients/([^/]+)/revoke$"),  _h_revoke_client),

    ("POST",   re.compile(r"^/api/clients/([^/]+)/suspend$"), _h_suspend_client),

    ("DELETE", re.compile(r"^/api/clients/([^/]+)$"),         _h_remove_client),

    ("POST",   re.compile(r"^/api/heartbeat/([^/]+)$"),      _h_heartbeat),

    # Self-service: client fetches its own config using heartbeat token (no TOTP required)

    ("GET",    re.compile(r"^/api/client/self/config$"),     _h_client_self_config),

    ("GET",    re.compile(r"^/api/audit-log$"),              _h_audit_log),

    ("GET",    re.compile(r"^/api/session-summary$"),         _h_session_summary),

    ("GET",    re.compile(r"^/api/file-activity$"),           _h_file_activity),

    ("GET",    re.compile(r"^/api/security-status$"),        _h_security_status),

    ("POST",   re.compile(r"^/api/harden-server$"),          _h_harden_server),

    ("POST",   re.compile(r"^/api/change-passphrase$"),      _h_change_passphrase),

    ("POST",   re.compile(r"^/api/start$"),                  _h_start_server),

    ("POST",   re.compile(r"^/api/terminate$"),              _h_terminate),

    ("POST",   re.compile(r"^/api/fresh-start/challenge$"),         _h_fresh_start_challenge),

    ("GET",    re.compile(r"^/api/fresh-start/challenge-token$"),   _h_fresh_start_challenge_read),

    ("POST",   re.compile(r"^/api/fresh-start$"),                   _h_fresh_start),

    ("POST",   re.compile(r"^/api/update-endpoint$"),        _h_update_endpoint),

    ("POST",   re.compile(r"^/api/change-port$"),            _h_change_port),

    ("GET",    re.compile(r"^/api/port-policy$"),            _h_port_policy),

    ("GET",    re.compile(r"^/api/service/status$"),         _h_service_status),

    ("POST",   re.compile(r"^/api/service/install$"),        _h_service_install),

    ("POST",   re.compile(r"^/api/service/uninstall$"),      _h_service_uninstall),

    ("POST",   re.compile(r"^/api/service/start$"),          _h_service_start),

    ("POST",   re.compile(r"^/api/service/stop$"),           _h_service_stop),

    ("POST",   re.compile(r"^/api/uninstall$"),              _h_uninstall),

    ("POST",   re.compile(r"^/api/rotate-server-keys$"),                    _h_rotate_server_keys),

    # Admin mode

    ("POST",   re.compile(r"^/api/admin/authenticate$"),                 _h_admin_authenticate),

    ("POST",   re.compile(r"^/api/admin/deactivate$"),                   _h_admin_deactivate_endpoint),

    ("GET",    re.compile(r"^/api/admin/status$"),                       _h_admin_status),

    ("POST",   re.compile(r"^/api/admin/exec$"),                         _h_admin_exec),

    ("GET",    re.compile(r"^/api/admin/services$"),                     _h_admin_services),

    ("POST",   re.compile(r"^/api/admin/services/([^/]+)/([^/]+)$"),    _h_admin_service_action),

    ("POST",   re.compile(r"^/api/admin/file/read$"),                    _h_admin_read_file),

    ("POST",   re.compile(r"^/api/admin/file/write$"),                   _h_admin_write_file),

    ("POST",   re.compile(r"^/api/set-pin$"),               _h_set_pin),

    ("POST",   re.compile(r"^/api/remove-pin$"),            _h_remove_pin),

    ("POST",   re.compile(r"^/api/unlock-pin$"),            _h_unlock_pin),

    ("GET",    re.compile(r"^/api/pin-info$"),              _h_pin_info),

    # TOTP 2FA

    ("POST",   re.compile(r"^/api/totp/enroll/begin$"),     _h_totp_enroll_begin),

    ("POST",   re.compile(r"^/api/totp/enroll/confirm$"),   _h_totp_enroll_confirm),

    ("POST",   re.compile(r"^/api/totp/disable$"),          _h_totp_disable),

    ("POST",   re.compile(r"^/api/totp/reset$"),            _h_totp_reset),

    ("POST",   re.compile(r"^/api/totp/verify-backup$"),    _h_totp_verify_backup),

    # DNS (7.4 split-DNS)

    ("GET",    re.compile(r"^/api/dns$"),                   _h_get_dns),

    ("POST",   re.compile(r"^/api/dns$"),                   _h_set_dns),

    ("POST",   re.compile(r"^/api/dns/([^/]+)$"),           _h_add_dns_mapping),

    ("DELETE", re.compile(r"^/api/dns/([^/]+)$"),           _h_remove_dns_mapping),

    # Backup (7.5 encrypted local backup)

    ("GET",    re.compile(r"^/api/backup/config$"),         _h_backup_config_get),

    ("POST",   re.compile(r"^/api/backup/config$"),         _h_backup_config_set),

    ("POST",   re.compile(r"^/api/backup/trigger$"),        _h_backup_trigger),

    ("GET",    re.compile(r"^/api/backup/list$"),           _h_backup_list),

    ("POST",   re.compile(r"^/api/backup/restore$"),        _h_backup_restore),

    # Auto-update

    ("GET",    re.compile(r"^/api/update/check$"),          _h_update_check),

    ("POST",   re.compile(r"^/api/update/install$"),        _h_update_install),

    # Client mode ΓÇö config management + tunnel

    ("GET",    re.compile(r"^/api/client/configs$"),                     _h_client_list_configs),

    ("POST",   re.compile(r"^/api/client/configs$"),                     _h_client_import_config),

    ("GET",    re.compile(r"^/api/client/configs/([^/]+)$"),             _h_client_get_config),

    ("DELETE", re.compile(r"^/api/client/configs/([^/]+)$"),             _h_client_delete_config),

    ("PUT",    re.compile(r"^/api/client/configs/([^/]+)$"),             _h_client_update_config),

    ("POST",   re.compile(r"^/api/client/tunnel/up/([^/]+)$"),          _h_client_tunnel_up),

    ("POST",   re.compile(r"^/api/client/tunnel/down$"),                _h_client_tunnel_down),

    ("GET",    re.compile(r"^/api/client/tunnel/status$"),              _h_client_tunnel_status),

    # Client settings

    ("GET",    re.compile(r"^/api/client/settings$"),                   _h_client_settings_get),

    ("PUT",    re.compile(r"^/api/client/settings$"),                   _h_client_settings_put),

    # SSH bridge

    ("GET",    re.compile(r"^/api/ssh/targets$"),                       _h_ssh_targets_get),

    ("POST",   re.compile(r"^/api/ssh/targets$"),                       _h_ssh_targets_set),

    ("POST",   re.compile(r"^/api/ssh/token$"),                         _h_ssh_token),

    ("POST",   re.compile(r"^/api/ssh/accept-host-key$"),               _h_ssh_accept_host_key),

    ("GET",    re.compile(r"^/api/ssh/sessions$"),                      _h_ssh_sessions),

    # SSH key management (Phase 2)

    ("GET",    re.compile(r"^/api/ssh/keys$"),                          _h_ssh_keys_list),

    ("POST",   re.compile(r"^/api/ssh/keys$"),                          _h_ssh_keys_generate),

    ("GET",    re.compile(r"^/api/ssh/keys/([^/]+)/public$"),           _h_ssh_keys_public),

    ("DELETE", re.compile(r"^/api/ssh/keys/([^/]+)$"),                  _h_ssh_keys_delete),

    # SFTP file browser

    ("POST",   re.compile(r"^/api/sftp/connect$"),                        _h_sftp_connect),

    ("POST",   re.compile(r"^/api/sftp/disconnect$"),                     _h_sftp_disconnect),

    ("POST",   re.compile(r"^/api/sftp/list$"),                           _h_sftp_list),

    ("POST",   re.compile(r"^/api/sftp/read$"),                           _h_sftp_read),

    ("POST",   re.compile(r"^/api/sftp/write$"),                          _h_sftp_write),

    ("POST",   re.compile(r"^/api/sftp/delete$"),                         _h_sftp_delete),

    ("POST",   re.compile(r"^/api/sftp/mkdir$"),                          _h_sftp_mkdir),

    ("POST",   re.compile(r"^/api/sftp/rename$"),                         _h_sftp_rename),

    ("POST",   re.compile(r"^/api/sftp/copy$"),                           _h_sftp_copy),

]



# ---------------------------------------------------------------------------

# HTTP handler

# ---------------------------------------------------------------------------





class _Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):  # silence default access log

        pass



    def _cors(self) -> None:

        origin = self.headers.get("Origin", "")

        _allowed = {

            "http://127.0.0.1",  "https://127.0.0.1",

            "http://localhost",  "https://localhost",

        }

        if origin and not any(origin == a or origin.startswith(a + ":") for a in _allowed):

            return

        if any(origin == a or origin.startswith(a + ":") for a in _allowed):

            self.send_header("Access-Control-Allow-Origin", origin)

        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")

        self.send_header("Access-Control-Allow-Headers", "Content-Type")



    def _json(self) -> dict:

        # SEC-004: enforce Content-Length cap BEFORE reading. A single request

        # with Content-Length=4 GiB would otherwise OOM the server thread.

        raw = self.headers.get("Content-Length", "0").strip()

        try:

            length = int(raw)

        except ValueError:

            raise _ApiError("Invalid Content-Length header.", 400)

        if length < 0:

            raise _ApiError("Invalid Content-Length header.", 400)

        if length > _MAX_BODY_SIZE:

            raise _ApiError(

                f"Request body too large (max {_MAX_BODY_SIZE} bytes).", 413

            )

        if length == 0:

            return {}

        try:

            return json.loads(self.rfile.read(length))

        except json.JSONDecodeError as exc:

            raise _ApiError("Invalid JSON in request body.", 400)



    def _send(self, data: Any, status: int = 200) -> None:

        body = json.dumps(data, default=str).encode()

        self.send_response(status)

        self.send_header("Content-Type",   "application/json")

        self.send_header("Content-Length", str(len(body)))

        self._cors()

        self.end_headers()

        self.wfile.write(body)



    # SEC-003: methods that MUST be rejected before the handler runs when the

    # request carries a cross-origin ``Origin`` header. GET is intentionally

    # excluded ΓÇö browser CORS prevents an attacker from reading the response

    # of a cross-origin GET, and some endpoints (/api/health) must remain

    # callable from monitoring tooling.

    _STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})



    def _enforce_same_origin(self) -> bool:

        origin = self.headers.get("Origin", "")

        if not origin:

            return False

        allowed = {"http://127.0.0.1", "http://localhost",

                   "https://127.0.0.1", "https://localhost"}

        if any(origin == a or origin.startswith(a + ":") for a in allowed):

            return False

        self._send(

            {"error": "Cross-origin request rejected by server CSRF filter."},

            403,

        )

        return True



    def _dispatch(self, method: str) -> None:

        # SEC-003: block cross-origin mutations BEFORE the handler executes.

        # The previous CORS logic only set response headers ΓÇö which the

        # browser respects, but by the time it arrived the server had already

        # mutated state (deleted the vault, rotated a key, etc).

        if method in self._STATE_CHANGING_METHODS and self._enforce_same_origin():

            return



        path = self.path.split("?")[0]

        for route_method, pattern, handler in _ROUTES:

            if route_method != method:

                continue

            m = pattern.match(path)

            if m:

                try:

                    result = handler(self, m.groups())

                    if result is not None:

                        self._send(result)

                except _ApiError as exc:

                    self._send({"error": str(exc)}, exc.status)

                except Exception as exc:

                    import traceback

                    traceback.print_exc()

                    self._send({"error": "Internal server error. Check the server logs."}, 500)

                return

        self._send({"error": "Not found"}, 404)



    def _serve_static(self, path: str) -> None:

        """Serve a file from the bundled React dist directory.



        SEC-022: resolves the requested path and verifies it stays inside

        the bundled dist tree (following symlinks). Anything that escapes

        (via ``..``, symlinks, encoded traversal, etc.) falls back to the

        SPA index, which is safe to serve.

        """

        dist = _get_dist_dir()

        if dist is None:

            body = b"Dashboard not bundled. Run 'npm run build' in Dashboard/."

            self.send_response(404)

            self.send_header("Content-Type", "text/plain")

            self.send_header("Content-Length", str(len(body)))

            self.end_headers()

            self.wfile.write(body)

            return



        try:

            dist_resolved = dist.resolve(strict=False)

        except (OSError, RuntimeError):

            self.send_response(500)

            self.end_headers()

            return



        rel = path.lstrip("/")

        # Reject any literal traversal component before touching the FS.

        if rel and any(part == ".." for part in Path(rel).parts):

            file_path = dist_resolved / "index.html"

        else:

            candidate = (dist_resolved / rel) if rel else (dist_resolved / "index.html")

            try:

                # strict=False so missing files still resolve (SPA fallback

                # handles non-existence). symlinks ARE followed.

                resolved_candidate = candidate.resolve(strict=False)

            except (OSError, RuntimeError):

                resolved_candidate = dist_resolved / "index.html"



            try:

                resolved_candidate.relative_to(dist_resolved)

                file_path = resolved_candidate

            except ValueError:

                # Escape attempt ΓÇö fall back to SPA index.

                file_path = dist_resolved / "index.html"



        # SPA fallback: unknown paths (e.g. /clients, /about) ΓåÆ index.html

        if not file_path.exists() or file_path.is_dir():

            file_path = dist_resolved / "index.html"



        if not file_path.exists():

            self.send_response(404)

            self.end_headers()

            return



        # Final belt-and-braces: after the SPA fallback, verify once more

        # that the served path is still inside the dist tree.

        try:

            file_path.resolve(strict=False).relative_to(dist_resolved)

        except ValueError:

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

    def do_PUT(self):    self._dispatch("PUT")





# ---------------------------------------------------------------------------

# Server entry point

# ---------------------------------------------------------------------------





_cleaned_up = False





def _cleanup_session(server: ThreadingHTTPServer) -> None:

    """Wipe vault state and shut down the HTTP server.



    Guarded by _cleaned_up flag to prevent double-cleanup when both

    atexit and signal handlers fire.

    """

    global _cleaned_up

    if _cleaned_up:

        return

    _cleaned_up = True

    _admin_deactivate()

    with _lock:

        if _session["passphrase"]:

            _session["passphrase"].wipe()

        _session.update(vault=None, passphrase=None, cache=None)

    try:

        from wireseal.security.audit import AuditLog

        AuditLog(_AUDIT_PATH).log("shutdown", {}, actor="system")

    except Exception:

        pass

    try:

        from wireseal.sftp.bridge import get_manager as _get_sftp_mgr

        _get_sftp_mgr().disconnect_all()

    except Exception:

        pass

    try:

        from wireseal.dns.dnsmasq import DnsmasqManager as _DnsMgr

        _DnsMgr(_WG_IFACE).remove_config()

    except Exception:

        pass

    try:

        from wireseal.platform.detect import get_adapter as _get_adapter

        _get_adapter().wg_down(_WG_IFACE)

    except Exception:

        pass

    server.server_close()

    print("\n[wireseal] Server stopped. Vault state wiped.")





def serve(host: str = "127.0.0.1", port: int = 8080, gui: bool = True) -> None:

    """Start the WireSeal API server.



    gui=True  (default): opens a native pywebview desktop window.

    gui=False (headless): binds the server and blocks; no window opened.

    Falls back to the system browser if pywebview is unavailable.



    On Linux, if gui=True but no DISPLAY/WAYLAND_DISPLAY is set (headless

    server, SSH session, Raspberry Pi), automatically falls back to headless.

    """

    import threading

    import webbrowser



    # Auto-detect headless Linux (SSH, no display, Raspberry Pi, etc.)

    if gui and sys.platform == "linux":

        has_display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")

        if not has_display:

            print("[wireseal] No display detected ΓÇö switching to headless mode.")

            print(f"[wireseal] Open http://{host}:{port}/ in your browser.")

            gui = False



    global _cleaned_up, _server_start_time

    import time as _time

    _cleaned_up = False

    _server_start_time = _time.monotonic()



    server = ThreadingHTTPServer((host, port), _Handler)

    url = f"http://{host}:{port}/"



    # Upgrade migration: reconfigure any v0.7.10-era tunnel service from

    # start=auto to start=demand, and stop it if it's running (user never

    # clicked Start ΓÇö it autostarted at boot). Best-effort, never fatal.

    try:

        from wireseal.platform.detect import get_adapter as _get_adapter

        _adapter = _get_adapter()

        if hasattr(_adapter, "migrate_tunnel_startup"):

            _mig = _adapter.migrate_tunnel_startup(_WG_IFACE)

            if _mig.get("migrated"):

                print(

                    f"[wireseal] Migrated {_mig['service']} from auto-start "

                    f"to manual-start (was_running={_mig['was_running']})."

                )

    except Exception as _exc:  # noqa: BLE001

        print(f"[wireseal] Tunnel-startup migration skipped: {_exc}")



    # Start SSH WebSocket bridge in a daemon thread (best-effort; optional)

    try:

        from wireseal.ssh.ws_bridge import start_bridge_thread as _start_ssh_bridge

        _ssh_log_dir = _VAULT_DIR / "ssh-sessions"

        _start_ssh_bridge(_ssh_log_dir)

    except Exception as _exc:  # noqa: BLE001

        print(f"[wireseal] SSH bridge failed to start: {_exc}")



    # Register signal handlers for graceful shutdown (wipe secrets on exit)

    import atexit

    import signal as _signal

    atexit.register(lambda: _cleanup_session(server))



    def _signal_handler(signum, frame):

        _cleanup_session(server)

        sys.exit(0)



    _signal.signal(_signal.SIGTERM, _signal_handler)

    if hasattr(_signal, "SIGHUP"):

        _signal.signal(_signal.SIGHUP, _signal_handler)



    # In GUI mode on Windows (console=False binary), suppress prints to avoid

    # allocating a console window.  Headless mode keeps prints for terminal use.

    _quiet = gui and sys.platform == "win32"

    if not _quiet:

        print(f"[wireseal] Serving on {url}")



    if not gui:

        if not _quiet:

            print("[wireseal] Headless mode ΓÇö press Ctrl+C to stop.")

        # Start TTL expiry watcher daemon thread (ZTNA-7.3)

        from wireseal.core.expiry import ExpiryWatcher

        _expiry_watcher = ExpiryWatcher(

            get_session=lambda: _session,

            session_lock=_lock,

            wg_iface=_WG_IFACE,

            audit_path=_AUDIT_PATH,

        )

        _expiry_watcher.start()

        try:

            server.serve_forever()

        except KeyboardInterrupt:

            pass

        finally:

            _cleanup_session(server)

        return



    # GUI mode: server runs in a daemon thread; pywebview owns the main thread.

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)

    server_thread.start()

    # Start TTL expiry watcher daemon thread (ZTNA-7.3)

    from wireseal.core.expiry import ExpiryWatcher

    _expiry_watcher = ExpiryWatcher(

        get_session=lambda: _session,

        session_lock=_lock,

        wg_iface=_WG_IFACE,

        audit_path=_AUDIT_PATH,

    )

    _expiry_watcher.start()



    # Auto-lock daemon: wipes vault after SESSION_TIMEOUT seconds of inactivity

    def _auto_lock_loop():

        global _last_activity

        import time as _t

        while True:

            _t.sleep(60)

            with _lock:

                if _session["vault"] is None:

                    continue

                if _last_activity and (_t.monotonic() - _last_activity > _SESSION_TIMEOUT):

                    if _session["passphrase"]:

                        _session["passphrase"].wipe()

                    _session.update(vault=None, passphrase=None, cache=None)

            # Audit log OUTSIDE the lock to avoid deadlock

            if _last_activity and (_t.monotonic() - _last_activity > _SESSION_TIMEOUT + 60):

                continue  # Already logged

            try:

                from wireseal.security.audit import AuditLog

                AuditLog(_AUDIT_PATH).log("auto-lock", {"reason": "inactivity"}, actor="system")

            except Exception:

                pass

            if not _quiet:

                print("[wireseal] Vault auto-locked after inactivity.")



    _autolock_thread = threading.Thread(target=_auto_lock_loop, daemon=True)

    _autolock_thread.start()



    # Start system tray icon (best-effort ΓÇö runs even if pywebview fails)

    _tray_thread = None

    try:

        from wireseal.tray import run_tray



        def _tray_stop_server() -> None:

            try:

                from wireseal.platform.detect import get_adapter

                adapter = get_adapter()

                adapter.wg_down("wg0")

            except Exception:

                pass



        def _tray_quit() -> None:

            server.shutdown()



        def _tray_status() -> str:

            try:

                from wireseal.platform.detect import get_adapter

                adapter = get_adapter()

                peers = adapter.wg_show("wg0")

                if peers is None:

                    return "Tunnel: stopped"

                return f"Tunnel: running ({len(peers)} peers)"

            except Exception:

                return "Tunnel: unknown"



        _tray_thread = run_tray(

            dashboard_url=url,

            on_stop=_tray_stop_server,

            on_quit=_tray_quit,

            status_getter=_tray_status,

        )

    except Exception:

        pass  # Tray is optional ΓÇö never block startup



    try:

        # On Linux, ensure GI_TYPELIB_PATH includes system typelib dirs.

        # PyInstaller's runtime hook sets it to only the bundled dir; append system paths.

        if sys.platform == "linux":

            _sys_typelib_dirs = [

                "/usr/lib/girepository-1.0",

                "/usr/lib64/girepository-1.0",

                "/usr/lib/x86_64-linux-gnu/girepository-1.0",

                "/usr/lib/aarch64-linux-gnu/girepository-1.0",

                "/usr/lib/arm-linux-gnueabihf/girepository-1.0",

            ]

            existing = os.environ.get("GI_TYPELIB_PATH", "")

            extra = [d for d in _sys_typelib_dirs if os.path.isdir(d) and d not in existing]

            if extra:

                parts = ([existing] if existing else []) + extra

                os.environ["GI_TYPELIB_PATH"] = os.pathsep.join(parts)



        import webview  # pywebview ΓÇö WinForms on Windows, WKWebView on macOS, WebKitGTK on Linux

        window = webview.create_window(

            "WireSeal", url, width=1200, height=800, min_size=(900, 600),

        )

        webview.start()  # blocks until the native window is closed

    except (ImportError, Exception) as exc:

        # Always log to file ΓÇö in quiet/GUI mode on Windows there is no console,

        # so this is the only way to see what went wrong.

        try:

            import datetime, traceback

            _log_dir = os.path.join(

                os.environ.get("APPDATA", os.path.expanduser("~")), "WireSeal"

            )

            os.makedirs(_log_dir, exist_ok=True)

            with open(os.path.join(_log_dir, "wireseal-gui.log"), "a", encoding="utf-8") as _lf:

                _lf.write(f"\n[{datetime.datetime.now().isoformat()}] GUI fallback\n")

                _lf.write(traceback.format_exc())

                # Diagnostic: log frozen state, extraction directory contents

                _lf.write(f"sys.frozen={getattr(sys, 'frozen', 'N/A')}\n")

                _meipass = getattr(sys, '_MEIPASS', None)

                _lf.write(f"sys._MEIPASS={_meipass}\n")

                _lf.write(f"sys.path={sys.path}\n")

                if _meipass and os.path.isdir(_meipass):

                    _top = sorted(os.listdir(_meipass))

                    _lf.write(f"_MEIPASS top-level ({len(_top)} entries): {_top[:50]}\n")

                    # Onedir (Windows) puts packages under _internal/, onefile

                    # puts them at _MEIPASS root. Check both.

                    for _wv_dir in (

                        os.path.join(_meipass, 'webview'),

                        os.path.join(_meipass, '_internal', 'webview'),

                    ):

                        _exists = os.path.isdir(_wv_dir)

                        _lf.write(f"{_wv_dir} exists: {_exists}\n")

                        if _exists:

                            _wv_init = os.path.join(_wv_dir, '__init__.py')

                            _lf.write(

                                f"  __init__.py exists: {os.path.isfile(_wv_init)}\n"

                            )

                            _lf.write(

                                f"  contents: {sorted(os.listdir(_wv_dir))[:30]}\n"

                            )

        except Exception:

            pass

        if not _quiet:

            print(f"[wireseal] GUI failed ({exc}) ΓÇö falling back to system browser.")

            if sys.platform == "linux" and not isinstance(exc, ImportError):

                pass

            elif sys.platform == "linux":

                print("[wireseal] Install GUI dependencies for a native window:")

                print("[wireseal]   Arch:   sudo pacman -S python-gobject webkit2gtk")

                print("[wireseal]   Debian: sudo apt install python3-gi gir1.2-webkit2-4.1")

                print("[wireseal]   Fedora: sudo dnf install python3-gobject webkit2gtk4.1")

            print("[wireseal] Press Ctrl+C to stop.")

        webbrowser.open(url)

        try:

            server_thread.join()

        except KeyboardInterrupt:

            pass

    finally:

        _cleanup_session(server)

