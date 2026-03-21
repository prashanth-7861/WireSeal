"""Pre-shared key generation for WireGuard.

Generates 256-bit cryptographically random PSKs using os.urandom.
PSKs are unique per peer (KEYGEN-03) and wrapped in SecretBytes.
Intermediate raw bytes are wiped after base64 encoding (KEYGEN-04).
"""

import base64
import os

from wireseal.security.secret_types import SecretBytes
from wireseal.security.secrets_wipe import wipe_bytes


def generate_psk() -> SecretBytes:
    """Generate a WireGuard pre-shared key (PSK).

    Returns:
        SecretBytes containing the base64-encoded 32-byte PSK.

    The PSK is 256 bits from os.urandom (KEYGEN-03: cryptographically random).
    Intermediate raw bytes are wiped after base64 encoding (KEYGEN-04).
    """
    # KEYGEN-03: 256-bit cryptographically random, unique per peer
    raw_psk = bytearray(os.urandom(32))

    # Base64-encode (standard base64, not url-safe -- matches wg format)
    psk_b64 = base64.b64encode(bytes(raw_psk))

    # KEYGEN-04: wipe intermediate raw bytes immediately after encoding
    wipe_bytes(raw_psk)

    result = SecretBytes(bytearray(psk_b64))
    return result
