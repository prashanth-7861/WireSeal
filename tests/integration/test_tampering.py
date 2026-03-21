"""
Config tampering detection tests (TEST-03).

These tests verify that compute_config_hash and verify_config_integrity correctly
detect post-deployment modification of WireGuard config files.

No Docker required -- operates purely on the filesystem using tmp_path.
Not marked @pytest.mark.integration; runs in the default pytest suite.
"""

from pathlib import Path

import pytest

from wireseal.security.integrity import compute_config_hash, verify_config_integrity


def test_config_tampering_detected(tmp_path):
    """Modify a deployed config and confirm verification detects it (TEST-03)."""
    config_file = tmp_path / "wg0.conf"
    config_file.write_text(
        "[Interface]\nPrivateKey = AAAA...base64key...\nListenPort = 51820\n"
    )

    stored_hash = compute_config_hash(config_file)

    # Tamper: append a rogue peer section
    original = config_file.read_text()
    config_file.write_text(original + "\n[Peer]\n# injected line\nPublicKey = BBBB\n")

    result = verify_config_integrity(config_file, stored_hash)
    assert not result, (
        "verify_config_integrity must return False when the config has been tampered. "
        "Security invariant CONFIG-04: any post-deployment modification must be detected."
    )


def test_unchanged_config_passes_verification(tmp_path):
    """An unmodified config must pass integrity verification."""
    config_file = tmp_path / "wg0.conf"
    config_file.write_text("[Interface]\nPrivateKey = AAAA\nListenPort = 51820\n")
    stored_hash = compute_config_hash(config_file)
    assert verify_config_integrity(config_file, stored_hash), (
        "verify_config_integrity must return True for an unmodified config."
    )


def test_wrong_stored_hash_fails_verification(tmp_path):
    """A mismatched stored hash must fail verification even if the file is intact."""
    config_file = tmp_path / "wg0.conf"
    config_file.write_text("[Interface]\nListenPort = 51820\n")
    wrong_hash = "a" * 64  # 64 hex chars but wrong value
    assert not verify_config_integrity(config_file, wrong_hash), (
        "verify_config_integrity must return False when the stored hash does not match "
        "the current file hash."
    )
