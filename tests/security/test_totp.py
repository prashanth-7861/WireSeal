"""Security tests for the TOTP module (07-03)."""
import time
import pytest
from unittest.mock import patch
from wireseal.security.totp import (
    generate_totp_secret, secret_to_b32, b32_to_secret,
    totp_uri, verify_totp, generate_backup_codes,
    hash_backup_code, verify_backup_code, _hotp,
)


def test_secret_b32_round_trip():
    secret = generate_totp_secret()
    assert len(secret) == 20
    b32 = secret_to_b32(secret)
    assert b32_to_secret(b32) == secret


def test_totp_uri_format():
    secret = generate_totp_secret()
    uri = totp_uri(secret, "owner", issuer="WireSeal")
    assert uri.startswith("otpauth://totp/")
    assert "secret=" in uri
    assert "issuer=WireSeal" in uri


def test_verify_totp_current_window():
    secret = generate_totp_secret()
    t = int(time.time()) // 30
    code = f"{_hotp(secret, t):06d}"
    assert verify_totp(secret, code, window=1)


def test_verify_totp_previous_window():
    secret = generate_totp_secret()
    t = int(time.time()) // 30
    code = f"{_hotp(secret, t - 1):06d}"
    assert verify_totp(secret, code, window=1)


def test_verify_totp_wrong_code():
    secret = generate_totp_secret()
    assert not verify_totp(secret, "000000", window=0)


def test_verify_totp_anti_replay():
    secret = generate_totp_secret()
    t = int(time.time()) // 30
    code = f"{_hotp(secret, t):06d}"
    used = set()
    assert verify_totp(secret, code, window=1, used_codes=used)
    assert not verify_totp(secret, code, window=1, used_codes=used)


def test_backup_code_single_use():
    codes = generate_backup_codes(8)
    hashed = [hash_backup_code(c) for c in codes]
    # First use: match found
    matched = verify_backup_code(codes[0], hashed)
    assert matched is not None
    # Remove matched hash (simulating vault update)
    hashed.remove(matched)
    # Second use: no match
    assert verify_backup_code(codes[0], hashed) is None


def test_backup_code_wrong_code():
    codes = generate_backup_codes(4)
    hashed = [hash_backup_code(c) for c in codes]
    assert verify_backup_code("WRONGCODE1", hashed) is None


def test_backup_code_generation_uniqueness():
    codes = generate_backup_codes(8)
    assert len(set(codes)) == 8  # all unique
    assert all(len(c) == 10 for c in codes)
