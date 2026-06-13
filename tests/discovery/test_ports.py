"""Unit tests for TCP port scanning + LAN-only guard."""

import socket
import threading

import pytest

from wireseal.discovery import ports as ports_mod
from wireseal.discovery.ports import COMMON_PORTS, is_scannable_ip, scan_ports


@pytest.mark.unit
@pytest.mark.parametrize(
    "ip,expected",
    [
        ("192.168.1.10", True),
        ("10.0.0.5", True),
        ("172.16.4.2", True),
        ("169.254.1.1", True),   # link-local
        ("8.8.8.8", False),      # public
        ("127.0.0.1", False),    # loopback
        ("224.0.0.1", False),    # multicast
        ("0.0.0.0", False),      # unspecified
        ("not-an-ip", False),
    ],
)
def test_is_scannable_ip(ip, expected):
    assert is_scannable_ip(ip) is expected


@pytest.mark.unit
def test_scan_refuses_non_lan_ip():
    assert scan_ports("8.8.8.8") == []
    assert scan_ports("127.0.0.1") == []


@pytest.mark.unit
def test_common_ports_have_labels():
    assert COMMON_PORTS[22] == "SSH"
    assert COMMON_PORTS[9100] == "Printer (Raw)"
    assert COMMON_PORTS[32400] == "Plex"


@pytest.mark.unit
def test_scan_detects_open_port(monkeypatch):
    """Bind a listener on loopback, allow it via monkeypatch, confirm detection."""
    monkeypatch.setattr(ports_mod, "is_scannable_ip", lambda ip: True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    stop = threading.Event()

    def _accept():
        srv.settimeout(2.0)
        try:
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass
        stop.set()

    threading.Thread(target=_accept, daemon=True).start()
    try:
        result = scan_ports("127.0.0.1", ports=[port], timeout=1.0)
    finally:
        srv.close()

    assert any(p["port"] == port for p in result)


@pytest.mark.unit
def test_scan_closed_port_returns_empty(monkeypatch):
    monkeypatch.setattr(ports_mod, "is_scannable_ip", lambda ip: True)
    # Port 1 on loopback is almost certainly closed.
    result = scan_ports("127.0.0.1", ports=[1], timeout=0.3)
    assert result == []
