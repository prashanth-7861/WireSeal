# Phase 5: Tests and Packaging - Research

**Researched:** 2026-03-20
**Domain:** pytest security testing, Docker WireGuard CI, PyInstaller binary packaging, pip-tools hash pinning, GPG/Sigstore artifact signing
**Confidence:** HIGH (core technical claims verified; PyInstaller/Python 3.14 interaction verified; Docker WireGuard userspace approach verified)

---

## Summary

Phase 5 closes the release loop: a comprehensive security-focused test suite plus verified standalone binaries. The codebase already has all the hard work done — vault, keygen, config builder, platform adapters, CLI commands. What remains is exercising those in an automated way and distributing the result.

The test suite has three layers: pure unit tests (no I/O, no subprocess) for the cryptographic primitives; Docker-based integration tests for the full WireGuard lifecycle; and a KDF benchmark that asserts Argon2id derivation exceeds 500 ms. pytest is the right runner for all three layers — unit tests via `pytest`, integration tests via `pytest` with a Docker fixture, and benchmarks via `pytest-benchmark`.

For packaging, PyInstaller 6.19+ fully supports Python 3.14, and the community hooks package (`pyinstaller-hooks-contrib` 2026.x) provides working hooks for both `cryptography` and `argon2-cffi`. The ctypes/mlock calls in `SecretBytes` are best-effort and will silently fail in environments where they are restricted — this is the correct behavior and requires no special PyInstaller treatment. Artifacts are signed using Sigstore's `gh-action-sigstore-python` (keyless, no long-lived secrets in CI), and SHA-256 checksums are published alongside binaries.

**Primary recommendation:** Use `pytest` + `pytest-benchmark` + `tmp_path` for tests; `pyinstaller-hooks-contrib` managed hooks for packaging; Sigstore `gh-action-sigstore-python` for signing.

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TEST-01 | Unit tests — vault round-trip, wrong passphrase rejection, tampered ciphertext rejection, atomic write on crash, key validity, validator rejection, permission enforcement, memory wipe, IP pool collision prevention, config builder completeness | pytest + `tmp_path` fixture provides isolated tmpdir with 0o700 permissions; each test gets a fresh vault path; no process-level state leaks |
| TEST-02 | Docker integration — full init → add-client → verify WireGuard interface up → remove-client → verify peer gone | `masipcat/wireguard-go` userspace Docker image enables WireGuard without kernel module; `subprocess.run(["docker", ...])` drives the lifecycle from a pytest fixture |
| TEST-03 | Config tampering test — modify deployed config, run verify, confirm detection | Pure filesystem test; `integrity.py` already has `verify_config_integrity`; test writes config, stores hash, mutates file, asserts `verify_config_integrity` returns False |
| TEST-04 | Argon2id benchmark — KDF time must exceed 500ms on target hardware | `pytest-benchmark` 5.2.3 with `benchmark.stats['min'] >= 0.5` assertion; uses `--benchmark-min-rounds=3` to prevent one-shot fluke |
| TEST-05 | All tests pass with zero failures before any release | CI workflow gate: `pytest --tb=short -q` exits non-zero on any failure; release job has `needs: [test]` dependency |
| PKG-01 | pyproject.toml with pinned deps and SHA-256 hashes | `pip-compile --generate-hashes` from `pyproject.toml`; stores as `requirements.txt` and `requirements-dev.txt` with per-package hashes |
| PKG-02 | PyInstaller standalone binaries for Linux/macOS/Windows via CI matrix | GitHub Actions matrix on `ubuntu-latest`, `macos-latest`, `windows-latest`; PyInstaller 6.19+ supports Python 3.14; `pyinstaller-hooks-contrib` handles cryptography + argon2 hooks |
| PKG-03 | GPG-signed release artifacts; checksums published | Use `sigstore/gh-action-sigstore-python` (keyless Sigstore signing, no stored secrets); generate `sha256sums.txt` with `sha256sum` step; upload both to GitHub Release |
| PKG-04 | README.md documents security model, threat model, installation with hash verification | Security README structure: What/Why/Threat Model/Installation/Verification/Limitations |
</phase_requirements>

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| pytest | >=8.3.5,<9 | Test runner | Established, broad plugin ecosystem; 8.3.x is battle-tested; 9.x is too new for a security tool |
| pytest-benchmark | >=5.1,<6 | Argon2 KDF timing assertions | `benchmark.stats['min']` assertions enforce minimum execution time as a security property |
| pytest-mock | >=3.14,<4 | Platform-specific mock (mlock, icacls) | Prevents tests from requiring root or Windows admin rights |
| PyInstaller | >=6.19,<7 | Standalone binary packaging | Supports Python 3.8–3.14; native hooks for cryptography + argon2 via hooks-contrib |
| pyinstaller-hooks-contrib | >=2026.0 | Hooks for cryptography + argon2 | Automatically installed with PyInstaller; contains `hook-cryptography.py` and `hook-argon2` |
| pip-tools | >=7.5,<8 | Hash-pinned requirements generation | `pip-compile --generate-hashes` is the gold standard for Python supply-chain security |
| pip-audit | >=2.10,<3 | Dependency vulnerability scan | Checks pinned deps against OSV (GHSA, CVE); run in CI on every PR |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pytest-cov | >=6,<7 | Coverage reporting | Run on CI; fail build if coverage drops below threshold |
| masipcat/wireguard-go | Docker image | Userspace WireGuard for Docker integration tests | Use when kernel WireGuard module is unavailable (all CI runners) |
| sigstore/gh-action-sigstore-python | v3+ | Keyless artifact signing | On release tag events; signs `.exe`, ELF, and Mach-O binaries |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| pytest-benchmark | manual `time.perf_counter()` | pytest-benchmark provides statistical rigor (min/max/stddev) and calibrates round counts automatically; manual timing is fragile on loaded CI runners |
| Sigstore keyless | Traditional GPG key pair | GPG requires managing a long-lived private key in CI secrets; Sigstore uses ephemeral OIDC credentials — no key storage risk |
| `masipcat/wireguard-go` Docker | Real WireGuard kernel module | Kernel module requires privileged CI runner or nested virtualization; wireguard-go works in standard GitHub Actions Ubuntu runners with `NET_ADMIN` capability |

**Installation (dev dependencies):**
```bash
pip install pytest>=8.3.5 pytest-benchmark>=5.1 pytest-mock>=3.14 pytest-cov>=6 pyinstaller>=6.19 pip-tools>=7.5 pip-audit>=2.10
```

---

## Architecture Patterns

### Recommended Test Structure
```
tests/
├── conftest.py               # Shared fixtures: vault factory, tmp passphrase, docker lifecycle
├── security/
│   ├── __init__.py
│   ├── test_vault.py         # TEST-01: round-trip, wrong passphrase, tampered ciphertext
│   ├── test_atomic.py        # TEST-01: atomic write crash safety
│   ├── test_secret_types.py  # TEST-01: memory wipe, repr/hash/pickle protection
│   ├── test_permissions.py   # TEST-01: file permission enforcement
│   └── test_integrity.py     # TEST-03: config tampering detection
├── core/
│   ├── __init__.py
│   ├── test_keygen.py        # TEST-01: key validity (44-char base64, 32-byte decode)
│   ├── test_validator.py     # TEST-01: validator rejection cases
│   ├── test_ip_pool.py       # TEST-01: IP pool collision prevention
│   └── test_config_builder.py # TEST-01: config builder completeness
├── benchmarks/
│   ├── __init__.py
│   └── test_argon2_timing.py # TEST-04: KDF >= 500ms assertion
└── integration/
    ├── __init__.py
    └── test_wireguard_lifecycle.py  # TEST-02: Docker full lifecycle
```

### Pattern 1: Vault Test Isolation with `tmp_path`

**What:** Each vault test creates its own isolated directory using pytest's `tmp_path` fixture. No shared state between tests.
**When to use:** All tests that touch the filesystem (vault, config files, atomic write).

```python
# Source: pytest docs https://docs.pytest.org/en/stable/how-to/tmp_path.html
import pytest
from pathlib import Path
from wg_automate.security.vault import Vault
from wg_automate.security.secret_types import SecretBytes

@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    """Return a fresh vault path in an isolated tmp dir per test."""
    return tmp_path / "vault.enc"

@pytest.fixture
def passphrase() -> SecretBytes:
    return SecretBytes(bytearray(b"correct-horse-battery-staple"))

def test_vault_round_trip(vault_path, passphrase):
    initial = {"schema_version": 1, "server": {}, "clients": {}, "ip_pool": {}, "integrity": {}}
    vault = Vault.create(vault_path, passphrase, initial)
    with vault.open(passphrase) as state:
        assert state._data["schema_version"] == 1
```

**Key point:** `tmp_path` creates a directory with mode `0o700` automatically (pytest 6.2.3+). No manual cleanup needed.

### Pattern 2: Wrong Passphrase and Tampered Ciphertext

**What:** Test that failure modes are indistinguishable (no oracle).
**When to use:** Vault security property tests.

```python
from wg_automate.security.vault import Vault
from wg_automate.security.exceptions import VaultUnlockError, VaultTamperedError

def test_wrong_passphrase_raises_unlock_error(vault_path, passphrase, tmp_path):
    wrong = SecretBytes(bytearray(b"wrong-passphrase-12"))
    Vault.create(vault_path, passphrase, {"schema_version": 1, ...})
    vault = Vault(vault_path)
    with pytest.raises(VaultUnlockError):
        vault.open(wrong)

def test_tampered_ciphertext_raises(vault_path, passphrase):
    Vault.create(vault_path, passphrase, {"schema_version": 1, ...})
    data = vault_path.read_bytes()
    # Flip a byte in the ciphertext region (after 51-byte header)
    corrupted = data[:51] + bytes([data[51] ^ 0xFF]) + data[52:]
    vault_path.write_bytes(corrupted)
    with pytest.raises(VaultUnlockError):
        Vault(vault_path).open(passphrase)

def test_bad_magic_raises_tampered(vault_path, passphrase):
    Vault.create(vault_path, passphrase, {"schema_version": 1, ...})
    data = vault_path.read_bytes()
    vault_path.write_bytes(b"XXXX" + data[4:])  # overwrite WGAV magic
    with pytest.raises(VaultTamperedError):
        Vault(vault_path).open(passphrase)
```

### Pattern 3: Atomic Write Crash Safety

**What:** Test that a partial write followed by simulated crash leaves no corrupted file at the destination.
**When to use:** `atomic.py` tests.

```python
import os
from unittest.mock import patch
from wg_automate.security.atomic import atomic_write

def test_atomic_write_no_partial_on_crash(tmp_path):
    dest = tmp_path / "output.bin"
    data = b"hello world"

    # Simulate crash during fsync by raising after write
    with patch("os.fsync", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            atomic_write(dest, data)

    # Destination must not exist — tmp file was cleaned up
    assert not dest.exists()
    # No leftover tmp files in directory
    tmp_files = list(tmp_path.glob(".tmp_wga_*"))
    assert len(tmp_files) == 0
```

### Pattern 4: Argon2 KDF Timing Benchmark

**What:** Assert that key derivation with production parameters takes >= 500ms.
**When to use:** TEST-04.

```python
# Source: pytest-benchmark docs https://pytest-benchmark.readthedocs.io/en/latest/usage.html
import pytest
from argon2.low_level import Type, hash_secret_raw

PRODUCTION_PARAMS = dict(
    time_cost=4,
    memory_cost=262144,  # 256 MiB
    parallelism=4,
    hash_len=32,
    type=Type.ID,
)

def test_argon2_kdf_minimum_500ms(benchmark):
    """Argon2id with production parameters must take >= 500ms.

    This is a security property: if derivation is too fast, the parameters
    have been degraded and the vault is vulnerable to brute-force attacks.
    """
    salt = b"A" * 16
    passphrase = b"benchmark-passphrase-test"

    benchmark.pedantic(
        hash_secret_raw,
        kwargs={"secret": passphrase, "salt": salt, **PRODUCTION_PARAMS},
        rounds=3,
        warmup_rounds=1,
    )

    # Assert minimum execution time as a security property
    assert benchmark.stats["min"] >= 0.5, (
        f"Argon2id derivation too fast: {benchmark.stats['min']:.3f}s < 0.5s. "
        "Parameters may have been weakened."
    )
```

**Note:** Use `benchmark.pedantic(..., rounds=3)` not `benchmark(fn)` — `pedantic` avoids pytest-benchmark's automatic calibration which can run the KDF hundreds of times, exhausting memory on constrained CI runners.

### Pattern 5: Docker WireGuard Integration Test

**What:** Full lifecycle test using wireguard-go userspace Docker image.
**When to use:** TEST-02 — requires Docker daemon available.

```python
# Mark integration tests separately so they can be skipped without Docker
pytestmark = pytest.mark.integration

import subprocess
import pytest

WIREGUARD_GO_IMAGE = "masipcat/wireguard-go:latest"

@pytest.fixture(scope="module")
def wireguard_container(tmp_path_factory):
    """Start a wireguard-go container for integration tests."""
    wg_dir = tmp_path_factory.mktemp("wg_config")
    # Write a minimal server config
    # ...

    cid = subprocess.run(
        ["docker", "run", "-d",
         "--cap-add", "NET_ADMIN",
         "-v", f"{wg_dir}:/etc/wireguard",
         WIREGUARD_GO_IMAGE],
        capture_output=True, text=True, check=True
    ).stdout.strip()

    yield cid

    subprocess.run(["docker", "rm", "-f", cid], check=True)
```

**CI note:** Integration tests require `--cap-add NET_ADMIN` and Docker. Run on `ubuntu-latest` only in CI. Mark with `@pytest.mark.integration` and run separately from unit tests: `pytest -m "not integration"` for fast CI, `pytest -m integration` for release validation.

### Pattern 6: Config Tampering Detection (TEST-03)

**What:** Write a config, record its hash in vault integrity, mutate the file, assert verification fails.

```python
from wg_automate.security.integrity import compute_config_hash, verify_config_integrity

def test_config_tampering_detected(tmp_path):
    config_file = tmp_path / "wg0.conf"
    config_file.write_text("[Interface]\nPrivateKey = ...\n")

    stored_hash = compute_config_hash(config_file)

    # Tamper: append a line
    config_file.write_text("[Interface]\nPrivateKey = ...\n# injected line\n")

    assert not verify_config_integrity(config_file, stored_hash)
```

### Anti-Patterns to Avoid
- **Using `monkeypatch.setenv("WG_PASSPHRASE", ...)` in tests:** Never put actual passphrase material in env vars, even in tests. Always use SecretBytes constructed from test literals.
- **Sharing a single `tmp_path` across multiple tests:** Each test must get its own isolated dir. Use `tmp_path` (function scope), not a module-scoped vault fixture.
- **Calling `benchmark(fn)` with Argon2 production params:** Benchmark's auto-calibration runs the function many times. Use `benchmark.pedantic(..., rounds=3)` to limit memory consumption.
- **Writing to real `/etc/wireguard` in integration tests:** Always use the container's mounted path, never the host's WireGuard config directory.
- **Testing mlock success:** `mlock` is best-effort and may silently fail (RLIMIT_MEMLOCK, non-root). Never assert that mlock succeeded — only assert that the SecretBytes object was created and wiped without error.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Timing assertions on benchmarks | Custom `time.perf_counter()` wrapper | `pytest-benchmark` | Statistical calibration, min/max/stddev, auto-warmup, CI-friendly output |
| Hash-pinned lockfiles | Manual `pip freeze` + sha256sum per package | `pip-compile --generate-hashes` | pip-compile handles transitive deps, platform markers, and hash generation atomically |
| Artifact signing with stored keys | GPG key pair in GitHub Secrets | `sigstore/gh-action-sigstore-python` | Sigstore uses ephemeral OIDC creds; no long-lived secret to exfiltrate from CI |
| PyInstaller hooks for cryptography | Custom `hook-cryptography.py` | `pyinstaller-hooks-contrib` (auto-installed with PyInstaller) | Community hooks already handle OpenSSL bundling, static vs dynamic linking detection |
| Docker WireGuard test environment | Kernel module dependency | `masipcat/wireguard-go` Docker image | Userspace WireGuard works on all CI runners without kernel module support |

**Key insight:** PyInstaller's community hooks (`pyinstaller-hooks-contrib`) handle the cryptography OpenSSL bundling complexity. The hook detects whether the `cryptography` wheel ships with OpenSSL statically linked (PyPI wheels do) vs dynamically linked (system installs may not). Do not override or replace this hook.

---

## Common Pitfalls

### Pitfall 1: Argon2 Benchmark OOM on CI Runners
**What goes wrong:** `benchmark(hash_secret_raw, ...)` auto-calibrates by running the function many times. Argon2id with 256 MiB memory cost × many rounds = OOM on runners with limited RAM.
**Why it happens:** pytest-benchmark's default mode runs enough iterations to get statistical confidence, which is fine for fast functions but catastrophic for memory-heavy KDFs.
**How to avoid:** Always use `benchmark.pedantic(..., rounds=3, warmup_rounds=1)`. This runs exactly 3 measurement rounds plus 1 warmup. Total memory: ~1 GiB across 4 rounds — within the 7 GiB available on `ubuntu-latest`.
**Warning signs:** CI runner killing pytest with OOM error, or benchmark taking >10 minutes.

### Pitfall 2: PyInstaller Python 3.14 + pyinstaller-hooks-contrib 2024.5 Regression
**What goes wrong:** Build fails with `ImportError: cannot import name 'isolated' from 'PyInstaller'`.
**Why it happens:** `pyinstaller-hooks-contrib` 2024.5 introduced a dependency on `PyInstaller.isolated` which was present in PyInstaller 5.0+. If hooks-contrib is pinned to an older version that had this bug, builds break.
**How to avoid:** Pin `pyinstaller-hooks-contrib>=2026.0` (current is 2026.3). The regression was fixed in 2024.7+.
**Warning signs:** Build failure mentioning `isolated` import in the cryptography hook.

### Pitfall 3: Vault Test Fixtures Leaking State
**What goes wrong:** Tests pass individually but fail when run together. A vault created in one test influences another because both use the same path.
**Why it happens:** Accidentally using a module-scoped or session-scoped path fixture instead of function-scoped `tmp_path`.
**How to avoid:** Every test that creates a vault must use `tmp_path` (function scope). Never use `tmp_path_factory` for vault paths — that gives the same directory to all tests in the module.
**Warning signs:** `VaultTamperedError` or `VaultUnlockError` in tests that don't intentionally tamper.

### Pitfall 4: SecretBytes mlock Failure on Windows CI Runners
**What goes wrong:** Tests that test mlock behavior fail on Windows CI because `VirtualLock` requires the process to hold `SeLockMemoryPrivilege`.
**Why it happens:** GitHub Actions Windows runners run as a standard user without `SeLockMemoryPrivilege`.
**How to avoid:** Never assert that mlock succeeded. Test only that `SecretBytes.__init__` completes without error and that `wipe()` zeroes the buffer. The mlock is best-effort and its failure is swallowed silently by design.
**Warning signs:** Tests passing locally (admin) but failing on CI (non-admin Windows).

### Pitfall 5: Integration Tests Running on Every PR
**What goes wrong:** Docker integration tests add 2-5 minutes per CI run and require Docker daemon. Running them on every PR slows the feedback loop.
**Why it happens:** No test marking strategy to separate unit from integration.
**How to avoid:** Mark all Docker tests with `@pytest.mark.integration`. In `pyproject.toml` set `addopts = ["-m", "not integration"]` for default runs. Add a separate CI job `test-integration` that runs `pytest -m integration` only on `main` branch pushes and release tags.

### Pitfall 6: pip-compile Generating Platform-Specific Hashes
**What goes wrong:** `requirements.txt` generated on Windows has different hashes than on Linux because some packages have platform-specific wheels.
**Why it happens:** pip-compile resolves dependencies for the current platform unless told otherwise.
**How to avoid:** Generate `requirements.txt` on Linux (the primary deployment target). Use `pip-compile --python-version 3.12 --platform linux-x86_64` if cross-compiling hashes. For CI, always regenerate from Linux.

### Pitfall 7: PyInstaller --onefile Antivirus False Positives on Windows
**What goes wrong:** Windows Defender flags the `wg-automate.exe` as malicious.
**Why it happens:** PyInstaller's bootloader extraction pattern matches known malware signatures.
**How to avoid:** Use `--onedir` instead of `--onefile` for the Windows build. Bundle as a zip archive containing the directory. Document "Run as Administrator" in the README. Code signing certificate ($200-400/year) eliminates most AV alerts but is optional.

---

## Code Examples

Verified patterns from official sources and the project's existing code:

### pip-compile with pyproject.toml (PKG-01)
```bash
# Source: https://pip-tools.readthedocs.io/en/stable/
# Generate production requirements with SHA-256 hashes from pyproject.toml
pip-compile --generate-hashes --output-file requirements.txt pyproject.toml

# Generate dev requirements (includes test + packaging deps)
pip-compile --generate-hashes --extra dev --output-file requirements-dev.txt pyproject.toml

# Install with hash verification (supply chain security)
pip install --require-hashes -r requirements.txt

# Audit for known vulnerabilities
pip-audit -r requirements.txt
```

Add `[tool.pip-tools]` to `pyproject.toml` to make hash generation the default:
```toml
[tool.pip-tools]
generate-hashes = true
strip-extras = true
```

### PyInstaller Spec File (PKG-02)
```python
# wg-automate.spec
# Source: PyInstaller docs https://pyinstaller.org/en/stable/
# pyinstaller-hooks-contrib handles cryptography and argon2 automatically

a = Analysis(
    ["src/wg_automate/main.py"],
    pathex=[],
    binaries=[],
    datas=[("src/wg_automate/templates", "wg_automate/templates")],
    hiddenimports=[
        "wg_automate.platform.linux",
        "wg_automate.platform.macos",
        "wg_automate.platform.windows",
        # argon2 and cryptography hooks are in pyinstaller-hooks-contrib
        # No manual hidden imports needed for them IF hooks-contrib >= 2024.7
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="wg-automate",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,            # UPX triggers more AV false positives, skip it
    console=True,          # CLI tool; must not use --windowed
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
```

### GitHub Actions Matrix Build (PKG-02)
```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - "v*"

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"
      - run: pip install --require-hashes -r requirements-dev.txt
      - run: pytest --tb=short -q -m "not integration"
      - run: pytest --tb=short -q -m integration
        env:
          DOCKER_BUILDKIT: "1"

  build:
    needs: test
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-latest
            artifact_name: wg-automate-linux-x86_64
            asset_name: wg-automate-linux-x86_64
          - os: macos-latest
            artifact_name: wg-automate-macos-arm64
            asset_name: wg-automate-macos-arm64
          - os: windows-latest
            artifact_name: wg-automate-windows-x86_64.exe
            asset_name: wg-automate-windows-x86_64.exe

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"
      - run: pip install --require-hashes -r requirements-dev.txt
      - run: pyinstaller wg-automate.spec
      - name: Rename binary
        shell: bash
        run: |
          mkdir -p dist/release
          find dist -maxdepth 1 -name "wg-automate*" -not -type d | \
            xargs -I{} cp {} dist/release/${{ matrix.artifact_name }}
      - uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.artifact_name }}
          path: dist/release/${{ matrix.artifact_name }}

  release:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write   # Required for Sigstore keyless signing
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: dist/release
          merge-multiple: true
      - name: Generate SHA-256 checksums
        run: |
          cd dist/release
          sha256sum * > sha256sums.txt
          cat sha256sums.txt
      - name: Sign with Sigstore
        uses: sigstore/gh-action-sigstore-python@v3
        with:
          inputs: dist/release/*
      - name: Upload to GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/release/*
            dist/release/sha256sums.txt
```

### pytest Configuration (pyproject.toml additions)
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = [
    "--import-mode=importlib",
    "-ra",
    "--tb=short",
    "-m", "not integration",    # exclude Docker tests by default
]
markers = [
    "integration: requires Docker daemon",
    "slow: marks tests as slow (benchmark etc.)",
]

[tool.pip-tools]
generate-hashes = true
strip-extras = true
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| GPG key pair stored in CI secrets | Sigstore keyless signing (OIDC ephemeral certs) | 2022-2024 | No long-lived key to exfiltrate; verified against Rekor transparency log |
| `tmpdir` fixture (py.path.local) | `tmp_path` fixture (pathlib.Path) | pytest 6.0 (2020) | Sunsetted `tmpdir`; `tmp_path` is the standard |
| PyInstaller 5.x (Python 3.8-3.11) | PyInstaller 6.x (Python 3.8-3.14) | 2023-2025 | Python 3.14 now fully supported; hooks managed via pyinstaller-hooks-contrib |
| Manual `pip freeze` with no hashes | `pip-compile --generate-hashes` | 2019+ | Supply-chain attacks countered by hash verification at install time |
| `pytest-benchmark(fn)` for timing | `benchmark.pedantic(fn, rounds=N)` | pytest-benchmark 3.x | Prevents auto-calibration from running memory-heavy functions hundreds of times |
| GitHub Actions: manually upload SHA256 | GitHub Releases native digest display | June 2025 | GitHub now auto-computes SHA256 for release assets; still publish explicit `sha256sums.txt` for scripting |

**Deprecated/outdated:**
- `tmpdir` fixture: use `tmp_path` instead; `tmpdir` is flagged as legacy in pytest 8.x
- `--onefile` PyInstaller on Windows: causes more AV false positives; use `--onedir` + zip
- Traditional GPG key in GitHub Secrets: replaced by Sigstore OIDC for open source projects

---

## Open Questions

1. **Python 3.14 PyInstaller mlock behavior**
   - What we know: PyInstaller 6.19+ supports Python 3.14 (confirmed). ctypes calls in `SecretBytes._mlock()` are best-effort and silently caught on failure.
   - What's unclear: Whether Python 3.14's ctypes changes affect the `ctypes.addressof(ctypes.c_char.from_buffer(bytearray))` pattern used in `SecretBytes`. Python 3.14 does not deprecate this pattern as of March 2026.
   - Recommendation: Add a unit test that constructs `SecretBytes`, calls `wipe()`, and asserts `is_wiped == True`. If the ctypes call fails silently (as designed), the test still passes. If PyInstaller breaks ctypes completely, the test will catch it.

2. **wireguard-go image tag stability**
   - What we know: `masipcat/wireguard-go:latest` is the recommended tag. No specific version pinning was found.
   - What's unclear: Whether `latest` is stable enough for CI, or if a pinned digest should be used.
   - Recommendation: Pin to a specific Docker image digest (e.g., `masipcat/wireguard-go@sha256:...`) in the integration test fixture to prevent unexpected breaks from upstream image updates. Update the pin manually as part of regular maintenance.

3. **Windows CI binary signing (code signing certificate)**
   - What we know: Sigstore keyless signing handles integrity (tamper detection). Windows Defender may still flag the unsigned PE binary.
   - What's unclear: Whether the project needs a traditional code signing certificate for the initial release, or whether Sigstore signatures + documentation of this limitation is acceptable.
   - Recommendation: Document the AV false positive risk in README.md. For v1.0, Sigstore signatures + SHA-256 checksums are sufficient. A code signing certificate can be added for v2.0 if AV false positives become a blocker for adoption.

---

## Sources

### Primary (HIGH confidence)
- PyInstaller official docs — Python version support (3.8–3.14), spec files, hooks system: https://pyinstaller.org/en/stable/
- pytest official docs — `tmp_path` fixture, security (0o700 dirs), fixture scopes: https://docs.pytest.org/en/stable/how-to/tmp_path.html
- pytest-benchmark docs — `benchmark.pedantic`, `benchmark.stats['min']`: https://pytest-benchmark.readthedocs.io/en/latest/
- pip-tools docs — `pip-compile --generate-hashes`, pyproject.toml integration: https://pip-tools.readthedocs.io/en/stable/
- sigstore/gh-action-sigstore-python GitHub — keyless signing in GitHub Actions: https://github.com/sigstore/gh-action-sigstore-python
- PyPI: pyinstaller-hooks-contrib 2026.3 — hooks for cryptography and argon2: https://pypi.org/project/pyinstaller-hooks-contrib/

### Secondary (MEDIUM confidence)
- pyinstaller-hooks-contrib Issue #736 — cryptography hook 2024.5 regression and fix: https://github.com/pyinstaller/pyinstaller-hooks-contrib/issues/736
- GitHub Changelog June 2025 — releases now expose SHA-256 digests natively: https://github.blog/changelog/2025-06-03-releases-now-expose-digests-for-release-assets/
- GitHub Actions March 2025 — upload-artifact/download-artifact now compute SHA-256: https://github.blog/changelog/2025-03-18-github-actions-now-supports-a-digest-for-validating-your-artifacts-at-runtime/
- wireguard-go Docker image (masipcat) — userspace WireGuard for Docker without kernel module: https://blog.topli.ch/posts/wireguard-docker/
- pytest CVE-2025-71176 — tmpdir symlink attack (mitigated in pytest 6.2.3+): https://github.com/pytest-dev/pytest/issues/13669

### Tertiary (LOW confidence)
- PyInstaller Python 3.14 ctypes behavior: inferred from Python 3.14 release notes and PyInstaller 6.19 changelog; no specific ctypes/mlock regression documented

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all library versions verified against PyPI and official docs
- Architecture: HIGH — test patterns derived from the actual implemented modules in this codebase
- Pitfalls: HIGH (PyInstaller AV, argon2 OOM, mlock on Windows) / MEDIUM (wireguard-go image pinning)
- Docker integration approach: MEDIUM — wireguard-go userspace confirmed as valid pattern; specific container lifecycle details for this tool are speculative until implemented

**Research date:** 2026-03-20
**Valid until:** 2026-06-20 (90 days; PyInstaller and pytest-benchmark are stable; Sigstore signing approach is settled)
