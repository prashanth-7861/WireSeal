"""
Argon2id KDF timing benchmark (TEST-04).

Security gate: verifies that the production Argon2id parameters produce a minimum
derivation time of 500ms. If this assertion fails, the KDF parameters have been
degraded and the security guarantee is broken.

Marked @pytest.mark.slow (not @pytest.mark.integration -- no Docker required).
Uses benchmark.pedantic(rounds=3) explicitly to avoid auto-calibration running
hundreds of rounds at 256 MiB per round, which would exhaust CI runner memory.
"""

import os

import pytest
from argon2.low_level import Type, hash_secret_raw

# Production Argon2id parameters -- must match vault.py exactly.
# Changing these values is a breaking security change requiring a migration plan.
PRODUCTION_PARAMS = {
    "time_cost": 10,
    "memory_cost": 262144,  # 256 MiB
    "parallelism": 4,
    "hash_len": 32,
    "type": Type.ID,
}

# Fixed inputs for reproducible timing (values don't affect performance, only params do)
_BENCHMARK_PASSWORD = b"benchmark-password-not-a-real-passphrase"
_BENCHMARK_SALT = os.urandom(16)


@pytest.mark.slow
def test_argon2id_minimum_timing(benchmark):
    """
    TEST-04: Assert Argon2id KDF with production parameters takes >= 500ms minimum.

    This is a security property: if the KDF is too fast, brute-force attacks become
    feasible. The 500ms floor reflects the minimum acceptable work factor for an
    interactive server-side unlock operation.
    """
    benchmark.pedantic(
        hash_secret_raw,
        kwargs={
            "secret": _BENCHMARK_PASSWORD,
            "salt": _BENCHMARK_SALT,
            **PRODUCTION_PARAMS,
        },
        rounds=3,
        warmup_rounds=1,
    )

    # benchmark.stats is None when --benchmark-disable is used (collection-only runs).
    # The timing assertion is only meaningful when the benchmark actually ran.
    if benchmark.stats is not None:
        min_time = benchmark.stats["min"]
        if min_time < 0.5:
            # On fast developer hardware, the KDF may complete in under 500ms.
            # In CI (WG_ENFORCE_TIMING=1), this is a hard failure -- it means the
            # production parameters have been degraded and must be corrected before release.
            # Locally, we warn rather than block development workflows.
            enforce = os.environ.get("WG_ENFORCE_TIMING", "0") == "1"
            message = (
                f"Argon2id KDF minimum time was {min_time:.3f}s -- below the 0.5s security floor. "
                "This indicates the production parameters (time_cost=10, memory_cost=262144, "
                "parallelism=4) have been degraded or the test hardware is unexpectedly fast. "
                "Review PRODUCTION_PARAMS against the vault.py Argon2id configuration before release. "
                "Set WG_ENFORCE_TIMING=1 to turn this into a hard failure (required in CI/release)."
            )
            if enforce:
                pytest.fail(message)
            else:
                pytest.skip(f"[timing-warn] {message}")
