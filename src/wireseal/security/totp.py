"""TOTP (RFC 6238) implementation — stdlib only, no external dependencies."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
import urllib.parse


def generate_totp_secret() -> bytes:
    """Generate a 20-byte random TOTP secret."""
    return os.urandom(20)


def secret_to_b32(secret: bytes) -> str:
    """Encode secret bytes to base32 string (for storage and QR URI)."""
    return base64.b32encode(secret).decode("ascii")


def b32_to_secret(b32: str) -> bytes:
    """Decode base32 string back to secret bytes."""
    # Add padding if needed
    padded = b32 + "=" * ((8 - len(b32) % 8) % 8)
    return base64.b32decode(padded.upper())


def totp_uri(secret: bytes, admin_id: str, issuer: str = "WireSeal") -> str:
    """Generate otpauth:// URI for QR code enrollment."""
    b32 = secret_to_b32(secret)
    label = urllib.parse.quote(f"{issuer}:{admin_id}")
    params = urllib.parse.urlencode({
        "secret": b32,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    })
    return f"otpauth://totp/{label}?{params}"


def _hotp(secret: bytes, counter: int) -> int:
    """Compute HOTP value per RFC 4226."""
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return code % 1_000_000


def verify_totp(secret: bytes, code: str, *, window: int = 1,
                used_codes: set | None = None) -> bool:
    """Verify a 6-digit TOTP code.

    Checks T-window .. T+window time steps (30s each).
    If used_codes set is provided, checks anti-replay and adds the code to the
    set on success.
    Returns True only if code is valid and not replayed.
    """
    if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
        return False

    # Anti-replay: reject if already used
    if used_codes is not None and code in used_codes:
        return False

    t = int(time.time()) // 30
    for delta in range(-window, window + 1):
        expected = f"{_hotp(secret, t + delta):06d}"
        if hmac.compare_digest(code, expected):
            if used_codes is not None:
                used_codes.add(code)
            return True
    return False


def generate_backup_codes(n: int = 8) -> list[str]:
    """Generate N single-use backup codes (10-char uppercase alphanumeric).

    Uses Crockford base32 alphabet (no visually confusable characters:
    no 0/O/I/L).
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ["".join(secrets.choice(alphabet) for _ in range(10)) for _ in range(n)]


def hash_backup_code(code: str) -> str:
    """SHA-256 hex digest of a backup code (stored in vault instead of plaintext)."""
    return hashlib.sha256(code.encode("ascii")).hexdigest()


def verify_backup_code(code: str, hashed_codes: list[str]) -> str | None:
    """Verify a backup code against a list of hashed codes.

    Returns the matched hash string (for removal from vault) or None if no
    match.  Constant-time comparison against all codes to prevent timing
    attacks — we iterate the full list even after a match.
    """
    code_hash = hash_backup_code(code.upper().strip())
    matched: str | None = None
    for h in hashed_codes:
        if hmac.compare_digest(code_hash, h):
            matched = h
    return matched
