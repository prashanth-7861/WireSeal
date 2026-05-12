"""Unit and security tests for wireseal.security.totp (TOTP Plan §12.1)."""
from __future__ import annotations

import math
import time
from collections import Counter

import pytest

from wireseal.security.totp import (
    _hotp,
    b32_to_secret,
    generate_backup_codes,
    generate_totp_secret,
    hash_backup_code,
    secret_to_b32,
    totp_uri,
    verify_backup_code,
    verify_totp,
)


# ---------------------------------------------------------------------------
# §12.1 — Secret Generation
# ---------------------------------------------------------------------------
class TestGenerateSecret:
    def test_returns_bytes_correct_length(self):
        secret = generate_totp_secret()
        assert isinstance(secret, bytes)
        assert len(secret) == 32

    def test_unique_per_call(self):
        assert generate_totp_secret() != generate_totp_secret()

    def test_cryptographically_random_entropy(self):
        """Shannon entropy across 100 secrets should exceed 7.0 bits/byte."""
        all_bytes = b"".join(generate_totp_secret() for _ in range(100))
        counts = Counter(all_bytes)
        total = len(all_bytes)
        entropy = -sum(
            (c / total) * math.log2(c / total) for c in counts.values() if c > 0
        )
        assert entropy > 7.0

    def test_b32_round_trip(self):
        secret = generate_totp_secret()
        assert b32_to_secret(secret_to_b32(secret)) == secret


# ---------------------------------------------------------------------------
# §12.1 — TOTP URI
# ---------------------------------------------------------------------------
class TestTotpUri:
    def test_format(self):
        secret = generate_totp_secret()
        uri = totp_uri(secret, "admin@example.com", issuer="WireSeal")
        assert uri.startswith("otpauth://totp/")
        assert "secret=" in uri
        assert "issuer=WireSeal" in uri

    def test_contains_admin_id(self):
        uri = totp_uri(generate_totp_secret(), "myuser")
        assert "myuser" in uri

    def test_contains_b32_secret(self):
        secret = generate_totp_secret()
        uri = totp_uri(secret, "admin")
        b32 = secret_to_b32(secret).rstrip("=")
        assert b32 in uri

    def test_default_issuer(self):
        uri = totp_uri(generate_totp_secret(), "admin")
        assert "issuer=WireSeal" in uri


# ---------------------------------------------------------------------------
# §12.1 — TOTP Verification
# ---------------------------------------------------------------------------
class TestVerifyTotp:
    def test_correct_code_current_window(self):
        secret = generate_totp_secret()
        t = int(time.time()) // 30
        code = f"{_hotp(secret, t):06d}"
        assert verify_totp(secret, code, window=1) is True

    def test_correct_code_previous_window(self):
        secret = generate_totp_secret()
        t = int(time.time()) // 30
        code = f"{_hotp(secret, t - 1):06d}"
        assert verify_totp(secret, code, window=1) is True

    def test_wrong_code(self):
        secret = generate_totp_secret()
        assert verify_totp(secret, "000000", window=0) is False

    def test_non_digit_code_rejected(self):
        assert verify_totp(generate_totp_secret(), "abcdef") is False

    def test_wrong_length_rejected(self):
        secret = generate_totp_secret()
        assert verify_totp(secret, "12345") is False
        assert verify_totp(secret, "1234567") is False

    def test_outside_window_rejected(self):
        """Code for T-2 should fail with window=0."""
        secret = generate_totp_secret()
        t = int(time.time()) // 30
        code = f"{_hotp(secret, t - 2):06d}"
        assert verify_totp(secret, code, window=0) is False

    def test_anti_replay(self):
        secret = generate_totp_secret()
        t = int(time.time()) // 30
        code = f"{_hotp(secret, t):06d}"
        used: set[str] = set()
        assert verify_totp(secret, code, window=1, used_codes=used) is True
        assert verify_totp(secret, code, window=1, used_codes=used) is False

    def test_anti_replay_tracks_in_set(self):
        secret = generate_totp_secret()
        t = int(time.time()) // 30
        code = f"{_hotp(secret, t):06d}"
        used: set[str] = set()
        verify_totp(secret, code, window=1, used_codes=used)
        assert code in used

    def test_no_anti_replay_without_set(self):
        secret = generate_totp_secret()
        t = int(time.time()) // 30
        code = f"{_hotp(secret, t):06d}"
        assert verify_totp(secret, code, window=1) is True
        assert verify_totp(secret, code, window=1) is True


# ---------------------------------------------------------------------------
# §12.1 — Backup Codes
# ---------------------------------------------------------------------------
class TestBackupCodes:
    def test_count(self):
        assert len(generate_backup_codes(8)) == 8

    def test_custom_count(self):
        for n in (1, 4, 12):
            assert len(generate_backup_codes(n)) == n

    def test_unique(self):
        codes = generate_backup_codes(10)
        assert len(set(codes)) == 10

    def test_correct_length(self):
        assert all(len(c) == 10 for c in generate_backup_codes(8))

    def test_uppercase_alphanumeric(self):
        """Crockford base32 alphabet — no O/0/I/1/L."""
        alphabet = set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        for code in generate_backup_codes(20):
            assert set(code).issubset(alphabet), f"Bad char in {code}"

    def test_hash_deterministic_but_salted(self):
        code = "ABCDE12345"
        h1 = hash_backup_code(code)
        h2 = hash_backup_code(code)
        assert h1.startswith("pbkdf2:sha256:")
        assert h2.startswith("pbkdf2:sha256:")
        # Different salts produce different hashes, both still verify
        assert h1 != h2
        assert verify_backup_code(code, [h1]) is not None
        assert verify_backup_code(code, [h2]) is not None

    def test_verify_valid(self):
        code = "TESTCODE99"
        hashed = hash_backup_code(code)
        assert verify_backup_code(code, [hashed]) == hashed

    def test_verify_invalid(self):
        assert verify_backup_code("WRONGCODE1", [hash_backup_code("REALCODE11")]) is None

    def test_verify_case_insensitive(self):
        code = "ABCDE12345"
        hashed = hash_backup_code(code)
        assert verify_backup_code(code.lower(), [hashed]) is not None

    def test_verify_returns_matched_hash(self):
        codes = generate_backup_codes(4)
        hashed = [hash_backup_code(c) for c in codes]
        assert verify_backup_code(codes[2], hashed) == hashed[2]

    def test_single_use_after_removal(self):
        codes = generate_backup_codes(4)
        hashed = [hash_backup_code(c) for c in codes]
        matched = verify_backup_code(codes[0], hashed)
        hashed.remove(matched)
        assert verify_backup_code(codes[0], hashed) is None

    def test_not_stored_plaintext(self):
        code = "PLAINTEXT1"
        stored = hash_backup_code(code)
        assert stored != code
        assert code not in stored


# ---------------------------------------------------------------------------
# §12.3 — Security-Focused Tests
# ---------------------------------------------------------------------------
class TestTotpSecurity:
    """Security tests per TOTP-plan.md §12.3."""

    def test_timing_consistency(self):
        """verify_totp runtime for valid and invalid codes within 5x."""
        import statistics

        secret = generate_totp_secret()
        t = int(time.time()) // 30
        valid_code = f"{_hotp(secret, t):06d}"
        invalid_code = f"{(_hotp(secret, t) + 1) % 1_000_000:06d}"

        samples = 30

        valid_times: list[float] = []
        for _ in range(samples):
            start = time.perf_counter()
            verify_totp(secret, valid_code, window=1)
            valid_times.append(time.perf_counter() - start)

        invalid_times: list[float] = []
        for _ in range(samples):
            start = time.perf_counter()
            verify_totp(secret, invalid_code, window=0)
            invalid_times.append(time.perf_counter() - start)

        median_valid = statistics.median(valid_times)
        median_invalid = statistics.median(invalid_times)

        ratio = max(median_valid, median_invalid) / max(
            min(median_valid, median_invalid), 1e-9
        )
        assert ratio < 5.0, (
            f"Timing ratio {ratio:.2f}x exceeds 5x threshold "
            f"(valid median={median_valid * 1e6:.1f}us, "
            f"invalid median={median_invalid * 1e6:.1f}us) — "
            "possible timing side-channel"
        )

    def test_secret_entropy_uniqueness(self):
        """50 generated secrets must all be unique and exactly 32 bytes."""
        secrets_batch = [generate_totp_secret() for _ in range(50)]
        assert all(len(s) == 32 for s in secrets_batch)
        assert len(set(secrets_batch)) == 50

    def test_anti_replay_independent_sets(self):
        """Same code accepted in two separate used_codes sets."""
        secret = generate_totp_secret()
        t = int(time.time()) // 30
        code = f"{_hotp(secret, t):06d}"

        set_a: set[str] = set()
        set_b: set[str] = set()

        assert verify_totp(secret, code, window=1, used_codes=set_a) is True
        assert verify_totp(secret, code, window=1, used_codes=set_a) is False
        assert verify_totp(secret, code, window=1, used_codes=set_b) is True

    def test_backup_code_format(self):
        """Backup codes must be 10 chars from Crockford alphabet."""
        crockford_alphabet = frozenset("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        excluded_chars = frozenset("01IOL")

        codes = generate_backup_codes(20)
        for code in codes:
            assert len(code) == 10, f"Code {code!r} wrong length {len(code)}"
            invalid = set(code) - crockford_alphabet
            assert not invalid, f"Code {code!r} has disallowed chars: {invalid}"
            ambiguous = set(code) & excluded_chars
            assert not ambiguous, f"Code {code!r} has ambiguous chars: {ambiguous}"

    def test_backup_code_uniqueness_large_batch(self):
        """100 batches of 8 codes — no intra-batch duplicates."""
        duplicate_batches = 0
        for _ in range(100):
            codes = generate_backup_codes(8)
            if len(set(codes)) != len(codes):
                duplicate_batches += 1
        assert duplicate_batches == 0
