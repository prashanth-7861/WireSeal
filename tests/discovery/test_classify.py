"""Unit tests for device-type classification heuristics."""

import pytest

from wireseal.discovery.classify import (
    COMPUTER,
    MEDIA,
    NAS,
    PRINTER,
    ROUTER,
    UNKNOWN,
    classify_device,
)


@pytest.mark.unit
def test_gateway_flag_always_router():
    assert classify_device(vendor="Apple", is_gateway=True) == ROUTER


@pytest.mark.unit
def test_vendor_synology_is_nas():
    assert classify_device(vendor="Synology Incorporated") == NAS


@pytest.mark.unit
def test_vendor_netgear_is_router():
    assert classify_device(vendor="NETGEAR") == ROUTER


@pytest.mark.unit
def test_vendor_hp_is_printer():
    assert classify_device(vendor="Hewlett Packard") == PRINTER


@pytest.mark.unit
def test_printer_ports_win_over_unknown_vendor():
    assert classify_device(vendor="Unknown", open_ports=[80, 9100]) == PRINTER


@pytest.mark.unit
def test_media_ports_detected():
    assert classify_device(open_ports=[32400]) == MEDIA


@pytest.mark.unit
def test_computer_ports_detected():
    assert classify_device(open_ports=[22]) == COMPUTER


@pytest.mark.unit
def test_service_types_take_priority_over_ports():
    # Plex service type should win over a generic SSH port.
    result = classify_device(open_ports=[22], service_types=["Plex"])
    assert result == MEDIA


@pytest.mark.unit
def test_no_signal_is_unknown():
    assert classify_device() == UNKNOWN
    assert classify_device(vendor="Unknown") == UNKNOWN


@pytest.mark.unit
def test_apple_vendor_alone_is_unknown():
    # Apple is ambiguous (phone/computer/TV) — needs another signal.
    assert classify_device(vendor="Apple, Inc.") == UNKNOWN
