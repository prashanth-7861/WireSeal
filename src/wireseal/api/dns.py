from . import _shared as _mod
for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
_s = _mod
del _mod, _name

def _h_get_dns(req, _groups):

    _require_unlocked()

    with _lock:

        cache = _session["cache"] or {}

    from wireseal.dns.dnsmasq import DnsmasqManager

    mgr = DnsmasqManager(_WG_IFACE)

    return {

        "mappings": cache.get("dns_mappings", {}),

        "dnsmasq_available": mgr.is_available(),

        "dnsmasq_running": mgr.is_running(),

        "platform": sys.platform,  # "win32" | "linux" | "darwin"

    }






def _h_set_dns(req, _groups):

    _require_unlocked()

    body = req._json()

    mappings = body.get("mappings", {})

    if not isinstance(mappings, dict):

        raise _ApiError("mappings must be an object.", 400)

    from wireseal.dns.dnsmasq import DnsmasqManager, validate_hostname, validate_ip

    for hostname, ip in mappings.items():

        validate_hostname(hostname)

        validate_ip(ip)

    with _lock:

        vault = _session["vault"]

        passphrase = _session["passphrase"]

        admin_id = _session.get("admin_id", "owner")

    with vault.open(passphrase, admin_id=admin_id) as state:

        state.data["dns_mappings"] = mappings

        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, admin_id)

    mgr = DnsmasqManager(_WG_IFACE)

    reloaded = False

    if mgr.is_available():

        mgr.write_config(mappings)

        reloaded = mgr.reload()

    return {"ok": True, "reloaded": reloaded}






def _h_add_dns_mapping(req, groups):

    _require_unlocked()

    hostname = groups[0]

    body = req._json()

    ip = body.get("ip", "")

    from wireseal.dns.dnsmasq import DnsmasqManager, validate_hostname, validate_ip

    validate_hostname(hostname)

    validate_ip(ip)

    with _lock:

        vault = _session["vault"]

        passphrase = _session["passphrase"]

        admin_id = _session.get("admin_id", "owner")

    with vault.open(passphrase, admin_id=admin_id) as state:

        state.data.setdefault("dns_mappings", {})[hostname] = ip

        mappings = dict(state.data["dns_mappings"])

        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, admin_id)

    mgr = DnsmasqManager(_WG_IFACE)

    if mgr.is_available():

        mgr.write_config(mappings)

        mgr.reload()

    return {"ok": True}






def _h_remove_dns_mapping(req, groups):

    _require_unlocked()

    hostname = groups[0]

    with _lock:

        vault = _session["vault"]

        passphrase = _session["passphrase"]

        admin_id = _session.get("admin_id", "owner")

    with vault.open(passphrase, admin_id=admin_id) as state:

        if hostname not in state.data.get("dns_mappings", {}):

            raise _ApiError(f"Hostname '{hostname}' not found.", 404)

        del state.data["dns_mappings"][hostname]

        mappings = dict(state.data.get("dns_mappings", {}))

        vault.save(state, passphrase)

    _refresh_cache_unlocked(vault, passphrase, admin_id)

    from wireseal.dns.dnsmasq import DnsmasqManager

    mgr = DnsmasqManager(_WG_IFACE)

    if mgr.is_available():

        mgr.write_config(mappings)

        mgr.reload()

    return {"ok": True}





# ---------------------------------------------------------------------------

# Backup handlers (7.5 encrypted local backup)

# ---------------------------------------------------------------------------



