"""Verify downloaded update assets before applying them.

SEC-005 / SEC-010: an attacker who can intercept the GitHub release download
(or compromise the release pipeline) must not be able to swap the binary for
one under their control. Two independent defenses are layered here:

1. **SHA-256 digest pinning** — the release publishes ``<asset>.sha256`` which
   is fetched from the same URL path; the digest is compared in
   constant-time against the computed digest of the downloaded file. This
   catches naive tampering and partial downloads.
2. **Ed25519 signature verification** — the release publishes ``<asset>.sig``
   containing a detached Ed25519 signature. The signature is verified against
   a public key pinned in this module at release-build time. An attacker who
   can replace the GitHub asset cannot forge a valid signature without the
   offline signing key.

Fails closed: if either the digest file or signature file is missing, or if
the pinned public key has not been configured, ``verify_release_asset``
raises :class:`UpdateVerificationError`. Callers MUST NOT proceed to extract
or execute an unverified asset.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class UpdateVerificationError(Exception):
    """Raised when an update asset fails integrity or authenticity checks."""


# ---------------------------------------------------------------------------
# Pinned Ed25519 public key
# ---------------------------------------------------------------------------
#
# The signing key is held offline by the release maintainer. Its 32-byte raw
# public key is embedded here at build time. Until the release pipeline wires
# up signing, this constant stays ``None`` and signature verification refuses
# to accept any asset — the update handler must also surface a clear error.
#
# To populate: set the environment variable WIRESEAL_UPDATE_PUBKEY_HEX at
# release-build time (64 hex chars = 32 bytes) and the installer embeds it,
# OR commit the hex constant directly in this file for audited builds.

_PINNED_PUBKEY_HEX: str | None = os.environ.get("WIRESEAL_UPDATE_PUBKEY_HEX")


def _load_pinned_pubkey() -> Ed25519PublicKey | None:
    """Load the pinned Ed25519 public key, or ``None`` if not configured."""
    if not _PINNED_PUBKEY_HEX:
        return None
    try:
        raw = bytes.fromhex(_PINNED_PUBKEY_HEX.strip())
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Verification API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedAsset:
    """Result of a successful verification."""

    path: Path
    sha256_hex: str
    signature_verified: bool


def _sha256_file(path: Path, chunk_size: int = 1 << 20) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.digest()


def verify_release_asset(
    asset_path: Path,
    expected_sha256_hex: str,
    signature: bytes,
    *,
    require_signature: bool = True,
) -> VerifiedAsset:
    """Verify that ``asset_path`` matches the pinned digest and signature.

    Parameters
    ----------
    asset_path:
        Path to the downloaded tarball / installer on local disk.
    expected_sha256_hex:
        Lowercase hex string of the SHA-256 digest published alongside the
        release asset (e.g. contents of ``<asset>.sha256``).
    signature:
        Raw 64-byte Ed25519 signature over the *bytes of the asset*
        (not the digest).
    require_signature:
        When ``True`` (default and required for production) the absence of a
        pinned public key or a failed signature check raises
        :class:`UpdateVerificationError`. Set ``False`` only for explicit
        pre-release / developer builds.

    Raises
    ------
    UpdateVerificationError
        if any check fails.
    """
    if not asset_path.exists() or not asset_path.is_file():
        raise UpdateVerificationError("Asset file missing.")

    # ---- SHA-256 ----
    expected = expected_sha256_hex.strip().lower()
    if len(expected) != 64 or not all(c in "0123456789abcdef" for c in expected):
        raise UpdateVerificationError("Malformed SHA-256 digest.")
    computed = _sha256_file(asset_path).hex()
    if not hmac.compare_digest(computed, expected):
        raise UpdateVerificationError(
            "SHA-256 mismatch — downloaded asset has been tampered with or is corrupt."
        )

    # ---- Ed25519 signature ----
    pubkey = _load_pinned_pubkey()
    if pubkey is None:
        if require_signature:
            raise UpdateVerificationError(
                "No pinned update-signing key is configured in this build; "
                "refusing to install unverified update."
            )
        return VerifiedAsset(asset_path, computed, signature_verified=False)

    if len(signature) != 64:
        raise UpdateVerificationError("Signature must be 64 raw bytes (Ed25519).")

    # Verify over the *file bytes*, not the digest — the digest is already
    # pinned but signing over the raw file prevents length-extension style
    # confusion and matches minisign / signify conventions.
    data = asset_path.read_bytes()
    try:
        pubkey.verify(signature, data)
    except InvalidSignature:
        raise UpdateVerificationError("Ed25519 signature verification failed.")
    except Exception as exc:
        raise UpdateVerificationError(f"Signature verification error: {exc}")

    return VerifiedAsset(asset_path, computed, signature_verified=True)
