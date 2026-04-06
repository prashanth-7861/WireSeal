"""Background thread that evicts WireGuard peers whose TTL has expired."""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable


class ExpiryWatcher(threading.Thread):
    """Polls vault every `interval` seconds and removes expired peers.

    Thread-safety contract:
    - Reads _session["vault"] + _session["passphrase"] under the provided lock (brief hold).
    - Releases lock before Argon2id (vault.open is ~3s).
    - Re-acquires lock only for vault.save() + cache refresh.
    - Skips cycle entirely when vault is locked (no active session).
    - Skips cycle when no non-permanent clients exist (avoids needless vault.open).
    """

    def __init__(
        self,
        get_session: Callable[[], dict],
        session_lock: threading.RLock,
        wg_iface: str,
        audit_path: Path,
        interval: int = 60,
    ):
        super().__init__(daemon=True, name="ExpiryWatcher")
        self._get_session = get_session
        self._lock = session_lock
        self._wg_iface = wg_iface
        self._audit_path = audit_path
        self._interval = interval
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        import logging
        _log = logging.getLogger(__name__)
        while not self._stop_event.wait(self._interval):
            try:
                self._check_expiry()
            except Exception as exc:
                _log.warning("ExpiryWatcher: unhandled error in _check_expiry: %s", exc)

    def _check_expiry(self):
        import time as _time
        # Quick read under lock — reference copies only, no Argon2id yet
        with self._lock:
            session = self._get_session()
            vault = session.get("vault")
            passphrase = session.get("passphrase")
            cache = session.get("cache") or {}
            admin_id = session.get("admin_id", "owner")

        if vault is None or passphrase is None:
            return  # Vault locked — skip cycle

        # Check if any non-permanent clients have TTL set
        clients = cache.get("clients", {})
        now = _time.time()
        candidates = [
            (name, info) for name, info in clients.items()
            if not info.get("permanent", True)
            and info.get("ttl_expires_at") is not None
            and info["ttl_expires_at"] <= now
        ]
        if not candidates:
            return  # Nothing to evict — skip vault.open

        # Open vault outside lock (Argon2id takes ~3s)
        expired_names = []
        try:
            with vault.open(passphrase, admin_id=admin_id) as state:
                for name, info in candidates:
                    # Re-check inside vault (race: heartbeat may have reset it)
                    client = state.clients.get(name)
                    if client and not client.get("permanent", True):
                        expires_at = client.get("ttl_expires_at")
                        if expires_at is not None and expires_at <= _time.time():
                            pubkey = client.get("public_key", "")
                            self._remove_peer(pubkey, name)
                            del state.clients[name]
                            # Release IP back to pool
                            ip = client.get("ip", "")
                            allocated = state.ip_pool.get("allocated", {})
                            if ip and name in allocated:
                                del allocated[name]
                            expired_names.append(name)
                if expired_names:
                    vault.save(state, passphrase)
        except Exception:
            return

        # Log audit events and refresh cache under lock
        if expired_names:
            from wireseal.security.audit import AuditLog
            audit = AuditLog(self._audit_path)
            for name in expired_names:
                try:
                    audit.log("peer-expired", {"name": name, "reason": "ttl"}, actor="system")
                except Exception:
                    pass
            # Refresh in-memory cache
            with self._lock:
                session = self._get_session()
                if session.get("vault") is vault:  # Same session still active
                    try:
                        from wireseal.api import _refresh_cache
                        with vault.open(passphrase, admin_id=admin_id) as state:
                            session["cache"] = _refresh_cache(state)
                    except Exception:
                        pass

    def _remove_peer(self, pubkey: str, name: str):
        """Remove peer from WireGuard via wg set (fast, no full reload)."""
        import subprocess, sys
        if not pubkey:
            return
        # pubkey may be a SecretBytes — extract the string value
        try:
            from wireseal.security.secret_types import SecretBytes
            if isinstance(pubkey, SecretBytes):
                pubkey = pubkey.expose_secret().decode("ascii")
        except Exception:
            pass
        cmd = ["wg", "set", self._wg_iface, "peer", str(pubkey), "remove"]
        if sys.platform != "win32":
            cmd = ["sudo", "-n"] + cmd
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass
