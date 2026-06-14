"""Notification configuration + test-send handlers."""
from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name

import copy

# Secret fields (per channel) never returned to the client in cleartext.
_SECRET_KEYS = {"token", "pass"}
# Sentinel the GET returns for a set secret; SET preserves the stored value
# when it receives this sentinel back (so secrets survive an edit-save round
# trip without being re-typed).
_SECRET_SENTINEL = "__SET__"

_CHANNELS = ("ntfy", "webhook", "smtp")


def _redact(cfg: dict) -> dict:
    safe = copy.deepcopy(cfg or {})
    for ch in (safe.get("channels") or {}).values():
        if not isinstance(ch, dict):
            continue
        for k in list(ch.keys()):
            if k in _SECRET_KEYS:
                ch[k] = _SECRET_SENTINEL if ch.get(k) else ""
    return safe


def _merge_notifications(cur: dict, incoming: dict) -> dict:
    """Merge client-supplied config over the stored one, preserving secrets.

    Only known keys are accepted. A secret arriving as the sentinel keeps the
    stored value; empty clears it; anything else replaces it.
    """
    from wireseal.notify.dispatch import EVENTS

    merged: dict = {
        "enabled": bool(incoming.get("enabled", cur.get("enabled", False))),
        "events": {},
        "channels": {},
    }
    in_events = incoming.get("events", {}) or {}
    cur_events = cur.get("events", {}) or {}
    for ev in EVENTS:
        merged["events"][ev] = bool(in_events.get(ev, cur_events.get(ev, False)))

    in_channels = incoming.get("channels", {}) or {}
    cur_channels = cur.get("channels", {}) or {}
    for name in _CHANNELS:
        in_ch = in_channels.get(name, {}) or {}
        cur_ch = cur_channels.get(name, {}) or {}
        out_ch = dict(cur_ch)
        for k, v in in_ch.items():
            if k in _SECRET_KEYS:
                if v == _SECRET_SENTINEL:
                    continue  # keep stored secret
                out_ch[k] = v  # set or clear
            else:
                out_ch[k] = v
        merged["channels"][name] = out_ch
    return merged


def _h_notifications_get(req, _groups):
    """GET /api/notifications — config (secrets redacted) + event catalogue."""
    _require_unlocked()
    from wireseal.notify.dispatch import EVENTS
    with _lock:
        cache = _session["cache"] or {}
    cfg = cache.get("notifications", {}) or {}
    return {"notifications": _redact(cfg), "events": list(EVENTS)}


def _h_notifications_set(req, _groups):
    """POST /api/notifications — update config (admin only)."""
    _require_admin_role()
    body = req._json()
    incoming = body.get("notifications", body)
    if not isinstance(incoming, dict):
        raise _ApiError("notifications object required.", 400)
    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        admin_id = _session.get("admin_id", "owner")
    with vault.open(passphrase, admin_id=admin_id) as state:
        cur = state.data.get("notifications", {}) or {}
        state.data["notifications"] = _merge_notifications(cur, incoming)
        vault.save(state, passphrase)
    _refresh_cache_unlocked(vault, passphrase, admin_id)
    return {"ok": True}


def _h_notifications_test(req, _groups):
    """POST /api/notifications/test — send a test message to enabled channels."""
    _require_admin_role()
    with _lock:
        cache = _session["cache"] or {}
    cfg = cache.get("notifications", {}) or {}
    from wireseal.notify.dispatch import notify
    res = notify(
        cfg, "test", "WireSeal test",
        "If you can read this, WireSeal notifications are working.",
        priority="default", force=True,
    )
    return {"sent": res["sent"], "errors": res["errors"]}
