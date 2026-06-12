"""Unit tests for the DuckDNS HTTPS updater (wireseal.dns.duckdns).

Focus: the response parser must treat DuckDNS's success signal (first line
'OK') as success even when the body is verbose ("OK\\n<ip>\\n\\nUPDATED"), and
must still reject genuine failures ('KO', empty). The HTTP call is mocked so
no network access occurs.
"""

from __future__ import annotations

import io
from contextlib import contextmanager
from unittest import mock

import pytest

from wireseal.dns.duckdns import update_dns, DuckDNSError
from wireseal.security.secret_types import SecretBytes


def _token() -> SecretBytes:
    return SecretBytes(bytearray(b"test-token-1234567890"))


@contextmanager
def _mock_response(body: bytes):
    """Patch urlopen to return a context manager yielding *body*."""
    resp = mock.MagicMock()
    resp.read.return_value = body
    cm = mock.MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    with mock.patch("wireseal.dns.duckdns.urllib.request.urlopen", return_value=cm):
        yield


def test_bare_ok_is_success():
    # Arrange
    with _mock_response(b"OK"):
        # Act
        result = update_dns("myhome", _token(), "203.0.113.5")
    # Assert
    assert result["success"] is True
    assert result["error"] is None
    assert result["ip"] == "203.0.113.5"


def test_verbose_ok_with_ip_is_success():
    # Regression: verbose body "OK\n<ip>\n\nUPDATED" must not be a failure.
    with _mock_response(b"OK\n203.0.113.5\n\nUPDATED"):
        result = update_dns("myhome", _token(), "203.0.113.5")
    assert result["success"] is True
    assert result["error"] is None


def test_verbose_ok_nochange_is_success():
    with _mock_response(b"OK\n203.0.113.5\n\nNOCHANGE"):
        result = update_dns("myhome", _token(), "203.0.113.5")
    assert result["success"] is True


def test_ko_first_line_is_failure():
    with _mock_response(b"KO"):
        with pytest.raises(DuckDNSError):
            update_dns("myhome", _token(), "203.0.113.5")


def test_empty_body_is_failure():
    with _mock_response(b""):
        with pytest.raises(DuckDNSError):
            update_dns("myhome", _token(), "203.0.113.5")


def test_error_message_does_not_leak_token():
    # The token must never appear in a raised error message.
    with _mock_response(b"KO\nsome detail"):
        with pytest.raises(DuckDNSError) as exc_info:
            update_dns("myhome", _token(), "203.0.113.5")
    assert "test-token" not in str(exc_info.value)
