"""Per-client ACL handlers (resource access control)."""
from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name


def _h_client_acl_get(req, groups):
    """GET /api/clients/<name>/acl — current ACL for a client."""
    _require_unlocked()
    name = groups[0]
    with _lock:
        cache = _session["cache"] or {}
    clients = cache.get("clients", {})
    if name not in clients:
        raise _ApiError("Client not found.", 404)
    from wireseal.core.acl import ALLOW_ALL
    acl = clients[name].get("acl") or {}
    return {"acl": {"mode": acl.get("mode", ALLOW_ALL), "rules": acl.get("rules", [])}}


def _h_client_acl_set(req, groups):
    """PUT /api/clients/<name>/acl — set ACL mode + rules, then apply firewall."""
    _require_admin_role()
    name = groups[0]
    body = req._json()
    from wireseal.core.acl import (
        ALLOW_ALL, RESTRICTED, AclError, apply_client_acls, validate_rule,
    )

    mode = body.get("mode", ALLOW_ALL)
    if mode not in (ALLOW_ALL, RESTRICTED):
        raise _ApiError("mode must be 'allow_all' or 'restricted'.", 400)

    norm: list[dict] = []
    if mode == RESTRICTED:
        for r in (body.get("rules") or []):
            try:
                norm.append(validate_rule(r))
            except AclError as exc:
                raise _ApiError(str(exc), 400)

    with _lock:
        vault = _session["vault"]
        passphrase = _session["passphrase"]
        admin_id = _session.get("admin_id", "owner")
    with vault.open(passphrase, admin_id=admin_id) as state:
        if name not in state.clients:
            raise _ApiError("Client not found.", 404)
        state.clients[name]["acl"] = {"mode": mode, "rules": norm}
        vault.save(state, passphrase)
    _refresh_cache_unlocked(vault, passphrase, admin_id)

    with _lock:
        cache = _session["cache"] or {}
    ok, warning = apply_client_acls(cache.get("clients", {}))

    from wireseal.security.audit import AuditLog
    AuditLog(_s._AUDIT_PATH).log("acl-update", {
        "client": name, "mode": mode, "rules": len(norm),
        "applied": ok, "actor": admin_id,
    })

    resp = {"ok": True, "applied": ok}
    if warning:
        resp["warning"] = warning
    return resp
