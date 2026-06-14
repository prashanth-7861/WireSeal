"""Security handlers: TOTP, PIN, audit log."""
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

from . import admin as _admin_module
for _admin_name in dir(_admin_module):
    if not _admin_name.startswith("__"):
        globals()[_admin_name] = getattr(_admin_module, _admin_name)


def _h_admins_totp_status(req: "_Handler", _groups: tuple) -> dict:
    """GET /api/admins/totp-status — List admin IDs that have TOTP enabled.

    Requires an unlocked vault. Moved out of /api/vault-info to prevent
    unauthenticated admin enumeration (SEC-FIX-3).
    """
    _require_unlocked()
    admins_data = _session["cache"].get("admins", {}) if _session["cache"] else {}
    totp_required_for = [
        aid for aid, info in admins_data.items()
        if info.get("totp_secret_b32") is not None
    ]
    return {"totp_required_for": totp_required_for}


def _h_audit_log(req: "_Handler", _groups: tuple) -> dict:
    """Return the last 100 audit log entries.

    SEC-001: requires vault unlock. The audit log leaks admin identities,
    peer names, IP addresses, and operation timing — exactly the
    reconnaissance information a local attacker needs. Other processes on
    the machine (or a CSRF-capable tab) must not be able to read this
    without proving they hold the vault passphrase.
    """
    _require_unlocked()
    from urllib.parse import urlsplit, parse_qs
    raw_path = getattr(req, "path", "")
    path_str = raw_path if isinstance(raw_path, str) else ""
    try:
        qs = parse_qs(urlsplit(path_str).query)
        limit = int(qs.get("limit", ["100"])[0])
    except (ValueError, TypeError):
        limit = 100
    limit = max(1, min(limit, 2000))

    if not _s._AUDIT_PATH.exists():
        return {"entries": [], "total": 0, "returned": 0}
    try:
        # SEC (F6): memory-bounded tail read — never load a huge audit log
        # fully into memory. One pass, keeping only the last `limit` lines.
        from collections import deque
        total = 0
        tail: deque = deque(maxlen=limit)
        with open(_s._AUDIT_PATH, "r", encoding="utf-8", errors="replace") as _f:
            for _line in _f:
                _line = _line.strip()
                if not _line:
                    continue
                total += 1
                tail.append(_line)
        entries = []
        for line in tail:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                logging.getLogger("wireseal.audit").warning("Malformed audit log entry skipped")
        return {
            "entries": list(reversed(entries)),
            "total": total,
            "returned": len(entries),
        }
    except OSError:
        logging.getLogger("wireseal").warning("Failed to read audit log")
        return {"entries": [], "total": 0, "returned": 0, "error": "Failed to read audit log"}


def _h_audit_verify(req: "_Handler", _groups: tuple) -> dict:
    """Verify the tamper-evident hash chain of the on-disk audit log.

    SEC-025: each entry chains to the previous via
    ``chain_hash = sha256(prev_hash + canonical_body)``. A modified, deleted,
    or reordered entry breaks the chain. Requires vault unlock (same
    reconnaissance-sensitivity as reading the log).
    """
    _require_unlocked()
    from wireseal.security.audit import AuditLog
    try:
        ok, count, err = AuditLog(_s._AUDIT_PATH).verify_chain()
    except Exception as exc:  # never 500 the page over a verify failure
        logging.getLogger("wireseal.audit").warning("Chain verify failed: %s", exc)
        return {"valid": False, "verified": 0, "error": str(exc)}
    return {"valid": ok, "verified": count, "error": err}


def _h_session_summary(req: "_Handler", _groups: tuple) -> dict:
    """Build a session summary from audit log entries."""
    _require_unlocked()
    if not _s._AUDIT_PATH.exists():
        return {"sessions": [], "summary": {}}

    try:
        lines = _s._AUDIT_PATH.read_text().strip().splitlines()
    except OSError:
        logging.getLogger("wireseal").warning("Failed to read audit log")
        return {"sessions": [], "summary": {}, "error": "Failed to read audit log"}

    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            logging.getLogger("wireseal.audit").warning("Malformed audit log entry skipped")

    # Build session list (unlock → lock pairs)
    sessions = []
    current_session: dict | None = None
    action_counts: dict[str, int] = {}
    total_actions = 0

    for entry in entries:
        action = entry.get("action", "")
        total_actions += 1
        action_counts[action] = action_counts.get(action, 0) + 1

        if action in ("unlock-web", "init"):
            current_session = {
                "start": entry.get("timestamp", ""),
                "end": None,
                "events": [entry],
            }
        elif action == "lock" and current_session:
            current_session["end"] = entry.get("timestamp", "")
            current_session["events"].append(entry)
            sessions.append(current_session)
            current_session = None
        elif current_session:
            current_session["events"].append(entry)

    # If there's an active session (no lock yet), include it
    if current_session:
        current_session["end"] = None
        sessions.append(current_session)

    # Build session summaries (last 10)
    session_summaries = []
    for sess in sessions[-10:]:
        event_types: dict[str, int] = {}
        for ev in sess["events"]:
            a = ev.get("action", "unknown")
            event_types[a] = event_types.get(a, 0) + 1
        session_summaries.append({
            "start": sess["start"],
            "end": sess["end"],
            "event_count": len(sess["events"]),
            "event_types": event_types,
        })

    return {
        "sessions": list(reversed(session_summaries)),
        "summary": {
            "total_sessions": len(sessions),
            "total_events": total_actions,
            "action_counts": action_counts,
            "clients_added": action_counts.get("add-client", 0),
            "clients_removed": action_counts.get("remove-client", 0),
            "configs_exported": action_counts.get("export-config", 0),
            "qr_codes_generated": action_counts.get("export-qr", 0),
        },
    }


def _h_security_status(req: "_Handler", _groups: tuple) -> dict:
    """Return server security posture (cross-platform)."""
    _require_unlocked()
    _empty: dict = {
        "ssh_hardened": False, "kernel_hardened": False,
        "fail2ban_active": False, "fail2ban_bans": 0,
        "firewall_active": False, "ip_forwarding": False,
        "auto_updates": False, "open_ports": [], "checks": [],
    }
    try:
        from wireseal.platform.detect import get_adapter
        adapter = get_adapter()
        if hasattr(adapter, "get_security_status"):
            return adapter.get_security_status()
        return _empty
    except Exception:
        logging.getLogger("wireseal").warning("Security check failed")
        result = dict(_empty)
        result["error"] = "Security check failed"
        return result


def _h_harden_server(req: "_Handler", _groups: tuple) -> dict:
    """Apply server hardening (cross-platform)."""
    _require_unlocked()
    # SEC-028: server hardening mutates firewall/sysctl/system state — gate it
    # behind admin role so a read-only admin cannot trigger it.
    _mod._require_admin_role()
    try:
        from wireseal.platform.detect import get_adapter
        adapter = get_adapter()
        if hasattr(adapter, "harden_server"):
            actions = adapter.harden_server()
            from wireseal.security.audit import AuditLog
            AuditLog(_s._AUDIT_PATH).log("harden-server", {"actions_count": len(actions)},
                                          actor=_session.get("admin_id", "owner"))
            return {"ok": True, "actions": actions}
        return {"ok": True, "actions": ["Hardening not available on this platform"]}
    except Exception as exc:
        return {"ok": False, "actions": [], "error": str(exc)}


def _h_file_activity(req: "_Handler", _groups: tuple) -> dict:
    """Return recent SFTP/SSH file activity from system logs."""
    _require_unlocked()

    events: list[dict] = []

    if sys.platform != "win32":
        # Parse SFTP activity from journalctl (sshd internal-sftp logs)
        try:
            result = subprocess.run(
                ["journalctl", "-u", "sshd", "--no-pager", "-n", "500",
                 "--output=short-iso", "--grep=sftp-server"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                # Try ssh.service (Debian/Ubuntu)
                result = subprocess.run(
                    ["journalctl", "-u", "ssh", "--no-pager", "-n", "500",
                     "--output=short-iso", "--grep=sftp-server"],
                    capture_output=True, text=True, timeout=10,
                )

            for line in result.stdout.strip().splitlines():
                if not line:
                    continue
                event = _parse_sftp_log_line(line)
                if event:
                    events.append(event)
        except Exception as _e:
            logging.getLogger("wireseal").warning("File activity check failed: %s", _e)

        # Also check auth.log if journalctl didn't find anything
        if not events:
            for log_path in ["/var/log/auth.log", "/var/log/secure"]:
                try:
                    with open(log_path, "r") as f:
                        lines = f.readlines()[-500:]
                    for line in lines:
                        if "sftp-server" in line:
                            event = _parse_sftp_log_line(line)
                            if event:
                                events.append(event)
                    if events:
                        break
                except (OSError, PermissionError):
                    continue

    # Return most recent 100
    return {"events": events[-100:]}


def _parse_sftp_log_line(line: str) -> dict | None:
    """Parse an SFTP log line into a structured event."""
    import re as _re

    # Common SFTP operations in log lines
    sftp_ops = {
        "open": "file_open",
        "close": "file_close",
        "read": "file_read",
        "write": "file_write",
        "opendir": "dir_open",
        "closedir": "dir_close",
        "mkdir": "dir_create",
        "rmdir": "dir_remove",
        "remove": "file_remove",
        "rename": "file_rename",
        "stat": "file_stat",
        "lstat": "file_stat",
        "fstat": "file_stat",
        "setstat": "file_permissions",
        "fsetstat": "file_permissions",
        "symlink": "file_symlink",
        "readlink": "file_readlink",
        "realpath": "file_realpath",
    }

    for op, event_type in sftp_ops.items():
        pattern = _re.compile(
            rf'{op}\s+"([^"]+)"', _re.IGNORECASE
        )
        match = pattern.search(line)
        if match:
            filepath = match.group(1)
            # Extract timestamp from beginning of line
            ts_match = _re.match(r'(\d{4}-\d{2}-\d{2}T[\d:]+[+-]\d{4}|\w+\s+\d+\s+[\d:]+)', line)
            timestamp = ts_match.group(1) if ts_match else ""

            # For rename, try to find the second path
            details: dict[str, Any] = {"path": filepath}
            if op == "rename":
                rename_match = _re.search(rf'rename\s+"([^"]+)"\s+"([^"]+)"', line)
                if rename_match:
                    details["from"] = rename_match.group(1)
                    details["to"] = rename_match.group(2)

            # Extract user if possible
            user_match = _re.search(r'session opened for.*user\s+(\w+)|user\s+(\w+)', line)
            if user_match:
                details["user"] = user_match.group(1) or user_match.group(2)

            return {
                "timestamp": timestamp,
                "type": event_type,
                "operation": op,
                "details": details,
            }

    return None


def _h_port_policy(req: "_Handler", _groups: tuple) -> dict:
    """Public-readable port policy used by the UI to colour-code port input.

    No vault unlock required — same trust level as `/api/health`. Returns
    blocklisted, warn-listed, and the WireGuard default port. Keys are
    integers in JSON.
    """
    return {
        "default":   51820,
        "min":       1,
        "max":       65535,
        "privileged_max":      1023,
        "ephemeral_min":       49152,
        "blocked": [
            {"port": p, "reason": r}
            for p, r in sorted(_PORT_BLOCKLIST_UDP.items())
        ],
        "warnings": [
            {"port": p, "reason": r}
            for p, r in sorted(_PORT_WARN_UDP.items())
        ],
        "recommended": [
            {"port": 51820, "label": "WireGuard default"},
            {"port": 51821, "label": "WireGuard alt #1"},
            {"port": 51822, "label": "WireGuard alt #2"},
            {"port": 4500,  "label": "IPsec NAT-T (firewall-friendly)"},
            {"port": 443,   "label": "QUIC/HTTP-3 (bypass restrictive networks)"},
        ],
    }


def _h_set_pin(req: "_Handler", _groups: tuple) -> dict:
    """Set a quick-unlock PIN. Requires vault to be unlocked."""
    _require_unlocked()
    body = req._json()
    pin = body.get("pin", "")
    if not pin or not pin.isdigit() or len(pin) < 4 or len(pin) > 8:
        raise _ApiError("PIN must be 4–8 digits.", 400)

    with _lock:
        passphrase = _session["passphrase"]

    if passphrase is None:
        raise _ApiError("No passphrase in session.", 500)

    # Encrypt the passphrase with the PIN and save to disk
    passphrase_bytes = passphrase.expose_secret()
    _pin_save(passphrase_bytes, pin)

    from wireseal.security.audit import AuditLog
    AuditLog(_s._AUDIT_PATH).log("set-pin", {}, actor=_session.get("admin_id", "owner"))
    return {"ok": True}


def _h_remove_pin(req: "_Handler", _groups: tuple) -> dict:
    """Remove the quick-unlock PIN.

    SEC-024: requires an unlocked vault. Previously any process on the
    machine could POST here and DoS legitimate PIN-based unlock. Now the
    caller must already hold the vault passphrase.
    """
    _require_unlocked()
    _pin_wipe()
    from wireseal.security.audit import AuditLog
    AuditLog(_s._AUDIT_PATH).log("remove-pin", {}, actor=_session.get("admin_id", "owner"))
    return {"ok": True}


def _h_unlock_pin(req: "_Handler", _groups: tuple) -> dict:
    """Unlock the vault using a PIN instead of the full passphrase.

    SEC-014 / SEC-023: PIN attempts are tracked per-IP (not globally) and
    the check-then-increment sequence is atomic under ``_lock`` so two
    concurrent wrong PINs from different IPs cannot both slip past the
    5-attempt threshold, and a global counter cannot be abused to lock
    legitimate users out via a separate attacker.
    """
    global _pin_fail_count
    client_ip = req.client_address[0]
    if _check_rate_limit(client_ip, "unlock"):
        raise _ApiError("Too many unlock attempts. Try again later.", 429)

    if not _s._PIN_PATH.exists():
        raise _ApiError("No PIN set. Use passphrase to unlock.", 400)

    # Pre-check the per-IP counter (fast path — allows us to reject before
    # parsing the body). If already over threshold, wipe the PIN atomically
    # and bail out.
    with _lock:
        if _pin_fail_by_ip.get(client_ip, 0) >= _PIN_MAX_ATTEMPTS:
            _pin_wipe()
            _pin_fail_by_ip.pop(client_ip, None)
            _pin_fail_count = 0
            raise _ApiError("Too many wrong PIN attempts. PIN removed — use your passphrase.", 403)

    body = req._json()
    pin = body.get("pin", "")
    if not pin:
        raise _ApiError("pin is required", 400)

    passphrase_bytes = _pin_load(pin)
    if passphrase_bytes is None:
        # Atomic check-then-act: increment counter, decide whether to wipe,
        # all while holding _lock. This prevents a race where two wrong PINs
        # could each see count < MAX, both increment, and both skip the wipe.
        wipe_pin = False
        with _lock:
            current_fails = _pin_fail_by_ip.get(client_ip, 0) + 1
            _pin_fail_by_ip[client_ip] = current_fails
            # Keep legacy global counter in sync for any test/consumer that
            # still reads it, but decisions are driven by the per-IP count.
            _pin_fail_count = max(_pin_fail_count, current_fails)
            if current_fails >= _PIN_MAX_ATTEMPTS:
                wipe_pin = True
                _pin_fail_by_ip.pop(client_ip, None)
                _pin_fail_count = 0

        _record_unlock_failure(client_ip)
        _record_rate_limit_failure(client_ip, "unlock")
        if wipe_pin:
            _pin_wipe()
            raise _ApiError("Wrong PIN. PIN removed after too many attempts — use your passphrase.", 403)
        remaining = _PIN_MAX_ATTEMPTS - current_fails
        raise _ApiError(f"Wrong PIN. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", 401)

    # PIN correct — decrypt passphrase and unlock the vault
    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.vault import Vault
    from wireseal.security.audit import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_bytes))
    try:
        vault = Vault(_VAULT_PATH)
        try:
            with vault.open(passphrase) as st:
                cache = _refresh_cache(st)
        except Exception:
            passphrase.wipe()
            # PIN decrypted something but it doesn't unlock the vault —
            # passphrase may have changed since PIN was set.
            _pin_wipe()
            raise _ApiError("PIN is stale — passphrase was changed. Use your passphrase to unlock.", 401)

        with _lock:
            if _session["passphrase"]:
                _session["passphrase"].wipe()
            _session.update(vault=vault, passphrase=passphrase, cache=cache)
            _pin_fail_by_ip.pop(client_ip, None)  # Reset per-IP counter on success
            _pin_fail_count = 0  # Keep legacy counter consistent
        _clear_unlock_failures(client_ip)
        _clear_rate_limit(client_ip, "unlock")
        AuditLog(_s._AUDIT_PATH).log("unlock-pin", {}, actor="system")

        # Tunnel is NOT auto-started on unlock — user starts explicitly
        # from the Dashboard Start button (POST /api/start).
        return {"ok": True}
    except _ApiError:
        raise
    except Exception:
        passphrase.wipe()
        raise _ApiError("Unlock failed.", 500)


def _h_pin_info(req: "_Handler", _groups: tuple) -> dict:
    """Check if a PIN is configured."""
    return {"pin_set": _s._PIN_PATH.exists()}


def _h_totp_enroll_begin(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/enroll/begin — generate a new TOTP secret for enrollment.

    Requires unlocked vault + passphrase re-confirmation.
    Body: {confirm_passphrase: "..."} — verifies the vault passphrase before
    allowing enrollment. PIN-only auth is insufficient (SEC-018).
    Stores a pending enrollment entry in ``_pending_totp`` keyed by admin_id.
    Returns: {otpauth_uri, secret_b32, ...}
    """
    _require_unlocked()
    if _check_rate_limit(req.client_address[0], "totp_enroll"):
        raise _ApiError("Too many enrollment attempts. Try again later.", 429)
    body = req._json()
    # Require passphrase re-entry (SEC-018: PIN-only not sufficient)
    try:
        _require_confirmation(body)
    except _ApiError:
        _record_rate_limit_failure(req.client_address[0], "totp_enroll")
        raise
    with _lock:
        session_admin = _session.get("admin_id", "owner")
    admin_id = str(body.get("admin_id", session_admin)) if isinstance(body, dict) else session_admin

    secret = generate_totp_secret()
    uri = totp_uri(secret, admin_id)
    _pending_totp[admin_id] = {"secret": secret, "used_codes": set()}

    result: dict = {
        "otpauth_uri": uri,
        "secret_b32": secret_to_b32(secret),
    }

    # Generate a base64-encoded QR image so the dashboard can display it
    # without a client-side QR library.  Gracefully degrades if qrcode
    # package is not installed.
    try:
        import qrcode as _qr
        import qrcode.image.svg as _qr_svg

        qr = _qr.QRCode(error_correction=_qr.constants.ERROR_CORRECT_L)
        qr.add_data(uri)
        qr.make(fit=True)

        try:
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            result["qr_b64"] = base64.b64encode(buf.getvalue()).decode()
            result["qr_format"] = "png"
        except Exception:
            img = qr.make_image(image_factory=_qr_svg.SvgPathFillImage)
            buf = io.BytesIO()
            img.save(buf)
            result["qr_b64"] = base64.b64encode(buf.getvalue()).decode()
            result["qr_format"] = "svg+xml"
    except ImportError:
        pass  # qrcode not installed — frontend falls back to JS rendering

    return result


def _h_totp_enroll_confirm(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/enroll/confirm — verify code and commit TOTP enrollment.

    Body: {totp_code: "123456"}
    Returns: {ok: true, backup_codes: [...8 plaintext codes...]}

    The 8 backup codes are shown once and never stored in plaintext.
    The vault stores only their SHA-256 hashes.
    """
    _require_unlocked()
    if _check_rate_limit(req.client_address[0], "totp_confirm"):
        raise _ApiError("Too many enrollment confirmation attempts. Try again later.", 429)
    body = req._json()
    with _lock:
        session_admin = _session.get("admin_id", "owner")
        vault     = _session["vault"]
        sess_pass = _session["passphrase"]
    admin_id = str(body.get("admin_id", session_admin)) if isinstance(body, dict) else session_admin
    totp_code = str(body.get("totp_code", "")).strip()

    _check_totp_rate_limit(admin_id)

    pending = _pending_totp.get(admin_id)
    if pending is None:
        _record_rate_limit_failure(req.client_address[0], "totp_confirm")
        raise _ApiError("No pending enrollment. Call /api/totp/enroll/begin first.", 400)

    if not verify_totp(pending["secret"], totp_code, used_codes=pending["used_codes"]):
        _record_totp_failure(admin_id)
        _record_rate_limit_failure(req.client_address[0], "totp_confirm")
        raise _ApiError("invalid_code", 400)

    # Enrollment verified — clear rate limit and generate backup codes
    _clear_totp_failures(admin_id)
    _clear_rate_limit(req.client_address[0], "totp_confirm")
    backup_codes  = generate_backup_codes(8)
    hashed_codes  = [hash_backup_code(c) for c in backup_codes]
    b32           = secret_to_b32(pending["secret"])

    try:
        with vault.open(sess_pass, admin_id=admin_id) as state:
            admins_dict = state.data.setdefault("admins", {})
            if admin_id not in admins_dict:
                admins_dict[admin_id] = {
                    "role": "owner",
                    "created_at": _utcnow_iso(),
                    "totp_secret_b32": None,
                    "totp_enrolled_at": None,
                    "backup_codes": [],
                    "last_unlock": None,
                }
            admins_dict[admin_id]["totp_secret_b32"]  = b32
            admins_dict[admin_id]["totp_enrolled_at"] = _utcnow_iso()
            admins_dict[admin_id]["backup_codes"]     = hashed_codes
            with _lock:
                _session["cache"] = _refresh_cache(state)
            # Persist to disk (v2 vaults don't auto-save)
            vault.save(state, sess_pass)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(str(exc), 500)

    _pending_totp.pop(admin_id, None)

    from wireseal.security.audit import AuditLog
    AuditLog(_s._AUDIT_PATH).log("totp-enrolled", {"admin_id": admin_id}, actor=admin_id)

    return {"ok": True, "backup_codes": backup_codes}


def _h_totp_disable(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/disable — disable TOTP for an admin.

    Body (optional): {admin_id: "alice", totp_code|confirm_passphrase}
    Owner can disable any admin's TOTP; non-owner can only disable their own.
    Requires TOTP or passphrase re-confirmation.
    """
    _require_unlocked()
    if _check_rate_limit(req.client_address[0], "totp_disable"):
        raise _ApiError("Too many TOTP disable attempts. Try again later.", 429)
    with _lock:
        acting_id   = _session.get("admin_id", "owner")
        acting_role = _session.get("admin_role", "owner")
        vault       = _session["vault"]
        sess_pass   = _session["passphrase"]

    body      = req._json()
    target_id = body.get("admin_id", acting_id).strip() or acting_id

    try:
        _require_confirmation(body)
    except _ApiError:
        _record_rate_limit_failure(req.client_address[0], "totp_disable")
        raise

    if acting_role != "owner" and target_id != acting_id:
        raise _ApiError("may only disable your own TOTP", 403)

    try:
        with vault.open(sess_pass, admin_id=acting_id) as state:
            admins_dict = state.data.setdefault("admins", {})
            if target_id not in admins_dict:
                _record_rate_limit_failure(req.client_address[0], "totp_disable")
                raise _ApiError(f"Admin '{target_id}' not found", 404)
            admins_dict[target_id]["totp_secret_b32"]  = None
            admins_dict[target_id]["totp_enrolled_at"] = None
            admins_dict[target_id]["backup_codes"]     = []
            with _lock:
                _session["cache"] = _refresh_cache(state)
            vault.save(state, sess_pass)
    except _ApiError:
        raise
    except Exception as exc:
        _record_rate_limit_failure(req.client_address[0], "totp_disable")
        raise _ApiError(str(exc), 500)

    _clear_rate_limit(req.client_address[0], "totp_disable")
    _pending_totp.pop(target_id, None)

    from wireseal.security.audit import AuditLog
    AuditLog(_s._AUDIT_PATH).log("totp-disabled", {
        "target": target_id, "actor": acting_id,
    })
    return {"ok": True}


def _h_totp_reset(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/reset — owner-only: force-clear TOTP for any admin.

    Body: {admin_id: "alice", totp_code|confirm_passphrase}
    Requires TOTP or passphrase re-confirmation.
    """
    _require_unlocked()
    _require_owner()
    with _lock:
        acting_id = _session.get("admin_id", "owner")
        vault     = _session["vault"]
        sess_pass = _session["passphrase"]

    body      = req._json()
    _require_confirmation(body)
    target_id = body.get("admin_id", "").strip()
    if not target_id:
        raise _ApiError("admin_id is required", 400)

    try:
        with vault.open(sess_pass, admin_id=acting_id) as state:
            admins_dict = state.data.setdefault("admins", {})
            if target_id not in admins_dict:
                raise _ApiError(f"Admin '{target_id}' not found", 404)
            admins_dict[target_id]["totp_secret_b32"]  = None
            admins_dict[target_id]["totp_enrolled_at"] = None
            admins_dict[target_id]["backup_codes"]     = []
            with _lock:
                _session["cache"] = _refresh_cache(state)
            vault.save(state, sess_pass)
    except _ApiError:
        raise
    except Exception as exc:
        raise _ApiError(str(exc), 500)

    _pending_totp.pop(target_id, None)

    from wireseal.security.audit import AuditLog
    AuditLog(_s._AUDIT_PATH).log("totp-reset", {
        "target": target_id, "actor": acting_id,
    })
    return {"ok": True}


def _h_totp_verify_backup(req: "_Handler", _groups: tuple) -> dict:
    """POST /api/totp/verify-backup — unlock using a passphrase + backup code.

    This replaces the normal unlock flow when the user has lost their TOTP
    device.  Does not require an unlocked session.

    Body: {admin_id: "owner", passphrase: "...", backup_code: "ABCDEFGHIJ"}
    Returns: {ok: true, role: "owner"} on success.
    """
    body          = req._json()
    admin_id      = _validate_admin_id(body.get("admin_id", "owner"))
    passphrase_str = body.get("passphrase", "")
    backup_code   = body.get("backup_code", "").upper().strip()
    client_ip     = req.client_address[0]

    if not passphrase_str:
        raise _ApiError("passphrase is required", 400)
    if not backup_code:
        raise _ApiError("backup_code is required", 400)

    if _check_rate_limit(client_ip, "unlock"):
        raise _ApiError("Too many unlock attempts. Try again later.", 429)
    _check_totp_backup_rate_limit(admin_id)

    from wireseal.security.secret_types import SecretBytes
    from wireseal.security.secrets_wipe import wipe_string
    from wireseal.security.vault        import Vault
    from wireseal.security.audit        import AuditLog

    passphrase = SecretBytes(bytearray(passphrase_str.encode()))
    try:
        vault = Vault(_VAULT_PATH)
        try:
            with vault.open(passphrase, admin_id=admin_id) as st:
                admins_dict = st.data.setdefault("admins", {})
                # SEC-013: reject unknown admin_id even with valid passphrase.
                if admin_id not in admins_dict:
                    raise _ApiError("Unknown admin_id.", 401)
                admins_dict[admin_id]["last_unlock"] = _utcnow_iso()
                admin_role   = admins_dict[admin_id].get("role", "admin")
                hashed_codes = admins_dict[admin_id].get("backup_codes", [])

                # Verify backup code (constant-time)
                matched = verify_backup_code(backup_code, hashed_codes)
                if matched is None:
                    _record_unlock_failure(client_ip)
                    _record_rate_limit_failure(client_ip, "unlock")
                    raise _ApiError("invalid_backup_code", 401)

                # Consume the matched code (single-use)
                # h may be SecretBytes (wrapped by VaultState) or str — compare as str
                matched_str: str | None = matched
                admins_dict[admin_id]["backup_codes"] = [
                    h for h in hashed_codes
                    if (bytes(h.expose_secret()).decode("utf-8") if isinstance(h, SecretBytes) else h) != matched_str
                ]
                cache = _refresh_cache(st)
                # Persist consumed code to disk (v2 vaults don't auto-save)
                save_pass = SecretBytes(bytearray(passphrase_str.encode()))
                try:
                    vault.save(st, save_pass)
                finally:
                    save_pass.wipe()
        except _ApiError:
            passphrase.wipe()
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
        AuditLog(_s._AUDIT_PATH).log("unlock-backup-code", {"admin_id": admin_id}, actor=admin_id)
        return {"ok": True, "role": admin_role}
    finally:
        wipe_string(passphrase_str)
