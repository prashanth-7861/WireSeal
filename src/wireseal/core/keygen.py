# KEYGEN-01: Never call wg genkey subprocess -- keys visible in ps aux
"""X25519 key pair generation for WireGuard.

Generates key pairs in-process using the cryptography library.
Private keys are immediately wrapped in SecretBytes and intermediate
raw bytes are wiped after use.
"""

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from wireseal.security.secret_types import SecretBytes
from wireseal.security.secrets_wipe import wipe_bytes


def generate_keypair() -> tuple[SecretBytes, bytes]:
    """Generate an X25519 key pair for WireGuard.

    Returns:
        (private_key_b64, public_key_b64) where private_key_b64 is
        a SecretBytes containing the base64-encoded private key and
        public_key_b64 is plain bytes containing the base64-encoded
        public key.

    The private key is generated in-process (KEYGEN-01), stored
    immediately in a mutable bytearray (KEYGEN-02), and the raw
    intermediate bytes are wiped after base64 encoding (KEYGEN-04).
    """
    # KEYGEN-01: in-process generation, never via subprocess
    private_key = X25519PrivateKey.generate()

    # KEYGEN-02: extract raw bytes into a mutable bytearray immediately
    raw_private = bytearray(private_key.private_bytes_raw())
    raw_public = private_key.public_key().public_bytes_raw()  # plain bytes, not secret

    # Base64-encode both keys (standard base64, not url-safe -- matches wg format)
    private_b64 = base64.b64encode(bytes(raw_private))
    public_b64 = base64.b64encode(raw_public)

    # KEYGEN-04: wipe intermediate raw private key bytes immediately after encoding
    wipe_bytes(raw_private)

    # Wrap private key in SecretBytes (SecretBytes accepts bytearray)
    secret_private = SecretBytes(bytearray(private_b64))

    return (secret_private, public_b64)
