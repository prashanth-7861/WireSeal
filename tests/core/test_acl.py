"""Unit tests for per-client ACL validation + nftables ruleset generation."""

import pytest

from wireseal.core.acl import (
    AclError, build_ruleset, validate_rule, ALLOW_ALL, RESTRICTED,
)


@pytest.mark.unit
def test_validate_rule_host():
    r = validate_rule({"dest": "10.0.0.10", "port": 32400, "proto": "tcp"})
    assert r == {"dest": "10.0.0.10", "port": 32400, "proto": "tcp"}


@pytest.mark.unit
def test_validate_rule_cidr_no_port():
    r = validate_rule({"dest": "10.0.0.0/24"})
    assert r["dest"] == "10.0.0.0/24"
    assert r["port"] is None
    assert r["proto"] == "any"


@pytest.mark.unit
@pytest.mark.parametrize("bad", [
    {"dest": ""},
    {"dest": "not-an-ip"},
    {"dest": "10.0.0.1", "port": 70000, "proto": "tcp"},
    {"dest": "10.0.0.1", "port": 80, "proto": "any"},   # port needs tcp/udp
    {"dest": "10.0.0.1", "proto": "icmp"},
])
def test_validate_rule_rejects(bad):
    with pytest.raises(AclError):
        validate_rule(bad)


@pytest.mark.unit
def test_build_ruleset_restricted_and_allowall():
    clients = {
        "Phone":  {"ip": "10.0.0.5/32", "acl": {"mode": RESTRICTED,
                    "rules": [{"dest": "10.0.0.10", "port": 32400, "proto": "tcp"}]}},
        "Laptop": {"ip": "10.0.0.6", "acl": {"mode": ALLOW_ALL}},
    }
    out = build_ruleset(clients)
    # restricted client: explicit accept then catch-all drop
    assert "ip saddr 10.0.0.5 ip daddr 10.0.0.10 tcp dport 32400 accept" in out
    assert "ip saddr 10.0.0.5 drop" in out
    # allow_all client: no saddr rules at all
    assert "10.0.0.6" not in out
    # always allow established/related
    assert "ct state established,related accept" in out
    # idempotent shape
    assert "flush table inet wg_acl" in out


@pytest.mark.unit
def test_build_ruleset_skips_client_without_ip():
    clients = {"Ghost": {"ip": "", "acl": {"mode": RESTRICTED, "rules": []}}}
    out = build_ruleset(clients)
    assert "drop" not in out  # no valid saddr → no drop rule emitted


@pytest.mark.unit
def test_build_ruleset_empty_is_safe():
    out = build_ruleset({})
    assert "add table inet wg_acl" in out
    assert "policy accept" in out
