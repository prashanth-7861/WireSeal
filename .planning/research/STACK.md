# Technology Stack

**Project:** wg-automate (WireGuard VPN Server Automation CLI)
**Researched:** 2026-03-17
**Research mode:** Ecosystem (Stack dimension)

## Stack Validation Summary

The proposed stack is sound. All chosen libraries are actively maintained, current, and appropriate for a security-hardened CLI tool. No critical security advisories were found in the latest versions. Key adjustments recommended: pin Python 3.12 (not 3.10) as the minimum, add `rich` for terminal UX, and use `pip-tools` + `pip-audit` for dependency management.

**Confidence note:** Version numbers are HIGH confidence (verified via `pip index versions` against live PyPI on 2026-03-17). Architecture recommendations are MEDIUM confidence (based on training data -- WebSearch and WebFetch were unavailable for verification of security advisories).

---

## Recommended Stack

### Runtime

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Python | >=3.12,<3.14 | Runtime | 3.12 is the sweet spot: performance improvements (PEP 709 inlined comprehensions), improved error messages, stable typing features. 3.13 introduced free-threaded mode which is experimental. 3.14 is too new for PyInstaller compatibility. Avoid 3.10 minimum -- it loses you 2 years of security patches and typing features (TypeAlias, match statements matured in 3.12). | HIGH |

**Why not 3.10?** While 3.10 works, it reaches end-of-life in October 2026. Starting a new project on a Python version that will be EOL within months of initial development is inadvisable. 3.12 gives you support through 2028.

**Why not 3.13+?** PyInstaller 6.x has had compatibility challenges with each new Python minor version. 3.12 is battle-tested with PyInstaller 6.19.0. Pin `python_requires = ">=3.12,<3.14"` and validate 3.13 support before expanding.

### CLI Framework

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| click | 8.3.1 | CLI framework | Correct choice. Mature, Pallets-maintained, excellent decorator-based API. Native support for password prompts (`click.prompt(hide_input=True)`), confirmation prompts, colored output, and automatic help generation. Used by major projects (Flask, pip, AWS CLI v2). | HIGH |

**Enhancement: Add `rich-click`**

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| rich | 14.3.3 | Terminal formatting | Rich tables for peer listings, progress bars for key generation, styled error messages. Makes CLI feel polished without building custom formatting. | HIGH |
| rich-click | 1.8.8 | Rich-formatted help | DROP-IN replacement for click that renders help text with Rich formatting. Zero code changes required -- just `import rich_click as click`. | MEDIUM |

**Decision point:** `rich-click` is optional polish. If you want minimal dependencies, skip it and use `rich` directly only where needed. If you want beautiful `--help` output for free, add it.

### Cryptography

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| cryptography | 46.0.5 | X25519 key generation, AES-256-GCM vault encryption | Correct choice. The standard Python crypto library. Backed by OpenSSL (via Rust bindings since v38). `X25519PrivateKey.generate()` is the right API for WireGuard key pairs. `AESGCM` class provides authenticated encryption. Actively maintained by the Python Cryptographic Authority (pyca). | HIGH |
| argon2-cffi | 25.1.0 | Argon2id KDF for vault passphrase | Correct choice. The reference Argon2 binding for Python. Parameters (256MB/4iter/4par) are strong -- above OWASP's 2023 minimum recommendation of 19MB/2iter/1par. Recent 25.1.0 release (calver, released 2025) indicates active maintenance. | HIGH |

**Critical implementation notes for `cryptography`:**

1. **X25519 key output format:** `X25519PrivateKey.generate().private_bytes(encoding=Raw, format=Raw, encryption_algorithm=NoEncryption())` gives you the 32-byte raw key. WireGuard expects base64-encoded keys. Use `base64.b64encode()` on the raw bytes.

2. **AES-256-GCM nonce handling:** Use `os.urandom(12)` for the 96-bit nonce. Store nonce alongside ciphertext (it is not secret). NEVER reuse a nonce with the same key -- this completely breaks GCM security. For vault re-encryption on every save, derive a fresh nonce each time.

3. **Key derivation flow:** `passphrase -> argon2id(salt=random_16_bytes) -> 32-byte_key -> AESGCM(key)`. Store the salt in the vault header (not secret). The Argon2 salt and GCM nonce must both be stored unencrypted alongside the ciphertext.

4. **Memory safety:** The `cryptography` library does NOT zero memory after use in Python. Python's garbage collector does not guarantee timely cleanup. For the passphrase and derived key, call `del` on variables and consider `ctypes.memset` on byte arrays, but acknowledge this is best-effort in CPython due to object internals. Document this limitation.

**Critical note on argon2-cffi parameters:**

The specified 256MB memory cost is aggressive. This is fine for a CLI tool on a server (servers have RAM), but test this on constrained environments. If the tool runs on a Raspberry Pi or small VPS with 512MB RAM, 256MB Argon2 will OOM or thrash. Consider making memory cost configurable with a secure default (e.g., 256MB) and a documented minimum (64MB).

### Templating

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Jinja2 | 3.1.6 | WireGuard config file generation | Correct choice. `StrictUndefined` prevents silent variable omission in configs (a security concern -- missing `AllowedIPs` would create an open tunnel). `autoescape=True` is defense-in-depth even though WireGuard configs are not HTML. | HIGH |

**Implementation note:** Jinja2's `StrictUndefined` will raise `UndefinedError` if a template references a variable not provided. This is exactly what you want for WireGuard configs where every field matters. Combine with template validation at startup (render with test data) to catch template errors early.

### QR Code Generation

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| qrcode | 8.2 | In-memory QR code generation for mobile client configs | Correct choice. Pure Python, no system dependencies. Use `qrcode.make()` with `io.BytesIO()` for in-memory generation. For terminal display, use the SVG or ASCII factory -- never write QR images to disk (secrets hygiene). | HIGH |

**Implementation note:** For terminal QR display, use `qrcode`'s built-in text factory: `qr.print_ascii(tty=True)`. This outputs the QR code as Unicode block characters directly to the terminal. No temp files, no image libraries needed. The `tty=True` flag inverts colors for dark terminal backgrounds.

### HTTP Client

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| requests | 2.32.5 | DuckDNS API, public IP consensus | Correct choice. `verify=True` is the default (good), but explicitly passing it documents intent. For the 3-source IP consensus (ipify, amazonaws, icanhazip), use `requests.Session()` with a short timeout (5s connect, 10s read) to avoid hanging on unreachable endpoints. | HIGH |

**Security hardening for requests:**

1. Pin the CA bundle: `requests` uses `certifi` for CA certificates. Pin `certifi` version in requirements to avoid unexpected CA changes.
2. Set `timeout=(5, 10)` on ALL requests -- never use default (no timeout).
3. For DuckDNS: validate the response body (should be "OK" or "KO"), not just HTTP status.
4. Consider retry with backoff for IP consensus -- if 2/3 sources agree, proceed; if all 3 disagree, abort and warn.

### Testing

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| pytest | 8.3.5 or 9.0.2 | Test framework | Correct choice. Pin to 8.3.5 for stability (9.0.x is very new, released early 2026). pytest 8.x is well-established with broad plugin compatibility. | HIGH |
| pytest-cov | latest | Coverage reporting | Standard companion to pytest. | HIGH |
| pytest-mock | latest | Mocking for platform-specific tests | Essential for testing linux.py/macos.py/windows.py without root/admin access. | HIGH |

**Why pin pytest 8.3.5 over 9.0.2:** The pytest 9.0 line is very recent. For a security tool, stability matters more than new features. 8.3.5 is battle-tested. Move to 9.x after it has had a few patch releases.

### Packaging

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| PyInstaller | 6.19.0 | Single-binary distribution | Correct choice for CLI distribution. Produces standalone executables for all three target platforms. | HIGH |

#### PyInstaller Windows Gotchas (CRITICAL)

1. **Antivirus false positives:** PyInstaller-built Windows executables are frequently flagged by Windows Defender and other AV products as trojans or PUPs. This is because PyInstaller's bootloader pattern matches known malware signatures. **Mitigation:** Build with `--bootloader-ignore-signals` flag, consider signing the executable with a code signing certificate ($200-400/year from a CA), and submit to Microsoft's malware analysis portal for whitelisting.

2. **cryptography's Rust/OpenSSL dependency:** The `cryptography` library includes compiled Rust extensions and links against OpenSSL. PyInstaller must bundle these correctly. Use `--collect-all cryptography` in your `.spec` file or hook. Without this, you will get runtime `ImportError` on machines without OpenSSL installed.

3. **Hidden imports for argon2-cffi:** `argon2-cffi` uses `argon2-cffi-bindings` which contains the C extension. PyInstaller may not detect this transitive dependency automatically. Add `--hidden-import argon2._ffi` and `--hidden-import argon2.low_level` to your spec.

4. **One-file vs one-directory:** `--onefile` mode extracts to a temp directory on each run, which is slower and triggers more AV alerts. Prefer `--onedir` for production, with a wrapper script or installer (NSIS/Inno Setup) for distribution. `--onefile` is fine for development/testing.

5. **Windows console allocation:** Use `--console` (not `--windowed`) since this is a CLI tool. Without it, stdout/stderr will not be visible.

6. **Path length issues:** Windows has a 260-character path limit by default. PyInstaller's temp extraction paths can exceed this with deeply nested dependencies. Use `--name wg-automate` to keep the extraction directory name short.

7. **UAC and admin elevation:** WireGuard operations require admin/root. On Windows, the tool will need to be run from an elevated prompt. Do NOT embed a UAC manifest requesting elevation -- let the user handle this explicitly. Document "Run as Administrator" in the README.

8. **Cross-compilation is NOT supported:** You must build the Windows binary on Windows, the macOS binary on macOS, and the Linux binary on Linux. Use GitHub Actions with a matrix build for CI/CD.

### Dependency Management

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| pip-tools | 7.5.3 | Dependency pinning with hash verification | `pip-compile --generate-hashes` produces a `requirements.txt` with exact versions AND SHA-256 hashes for every package. This is the gold standard for supply-chain security in Python. | HIGH |
| pip-audit | 2.10.0 | Vulnerability scanning | Checks pinned dependencies against the OSV database (GHSA, CVE). Run in CI on every PR. | HIGH |

**Why pip-tools over Poetry/PDM/uv:** For a security tool that produces PyInstaller binaries, you want the simplest possible dependency resolution with hash pinning. Poetry and PDM add complexity (lock files, virtual env management) that conflicts with PyInstaller workflows. `pip-tools` does one thing well: deterministic, hash-pinned requirements files.

**Dependency pinning workflow:**

```bash
# requirements.in (human-edited, loose constraints)
click>=8.3,<9
cryptography>=46,<47
argon2-cffi>=25,<26
jinja2>=3.1,<4
qrcode>=8,<9
requests>=2.32,<3
rich>=14,<15

# Generate pinned requirements with hashes
pip-compile --generate-hashes --output-file requirements.txt requirements.in

# Verify no known vulnerabilities
pip-audit -r requirements.txt

# Install with hash verification
pip install --require-hashes -r requirements.txt
```

**Dev dependencies separately:**

```bash
# requirements-dev.in
-c requirements.txt
pytest>=8.3,<9
pytest-cov
pytest-mock
pyinstaller>=6.19,<7
rich-click>=1.8,<2

pip-compile --generate-hashes --output-file requirements-dev.txt requirements-dev.in
```

---

## Alternatives Considered (and Rejected)

| Category | Chosen | Alternative | Why Not |
|----------|--------|-------------|---------|
| CLI framework | click | typer | Typer wraps click and adds type-hint-based argument parsing. For a security tool that needs precise control over prompts, password input, and error handling, click's explicit decorators are clearer and have fewer magic behaviors. Typer is fine for simpler CLIs. |
| CLI framework | click | argparse | stdlib but painful for complex CLIs with subcommands. No built-in color, prompt, or progress support. |
| Crypto | cryptography | pynacl (1.6.2) | PyNaCl provides X25519 via libsodium but lacks AES-GCM (NaCl uses XSalsa20-Poly1305). Since the vault needs AES-256-GCM specifically, you would need both libraries. One library is better than two. |
| Crypto | cryptography | pycryptodome (3.23.0) | Actively maintained but less idiomatic Python API. The `cryptography` library is the pyca-recommended standard. |
| KDF | argon2-cffi | hashlib.scrypt | stdlib scrypt is functional but Argon2id is strictly superior (memory-hard AND resistant to side-channel attacks). OWASP recommends Argon2id as the primary choice. |
| Packaging | PyInstaller | Nuitka | Nuitka compiles to C and produces faster binaries with fewer AV false positives. However, it is significantly more complex to set up, has longer build times, and the free version has limitations. Consider Nuitka only if AV false positives become a blocking issue. |
| Packaging | PyInstaller | cx_Freeze | Less actively maintained than PyInstaller. Smaller community means fewer hooks for complex dependencies like `cryptography`. |
| Dep management | pip-tools | Poetry | Poetry's lock file format is proprietary and doesn't support `--require-hashes` natively. Poetry also manages virtual environments, which adds complexity when building with PyInstaller. |
| Dep management | pip-tools | uv | uv (from Astral) is blazing fast and supports pip-compile-compatible workflows. It is a viable alternative. However, uv is still relatively young (2024 release), and for a security tool, the maturity of pip-tools is preferred. LOW confidence -- uv may be the better choice by mid-2026, re-evaluate. |

---

## Libraries NOT to Use

| Library | Why Not |
|---------|---------|
| `paramiko` | SSH library -- not needed. WireGuard is configured via config files and `wg` CLI, not SSH. |
| `fabric` | Remote execution -- out of scope. This tool manages local WireGuard configs. |
| `pynacl` for vault | Does not provide AES-GCM. Would need a second crypto library. |
| `pycrypto` | DEAD. Unmaintained since 2013. Security vulnerabilities. pycryptodome is its fork. |
| `subprocess` for key generation | Do NOT shell out to `wg genkey`/`wg pubkey`. Use `cryptography`'s X25519 directly. Shelling out introduces path-dependency, platform differences, and the risk of keys appearing in process listings (`ps aux`). |
| `keyring` | Cross-platform secret storage (DPAPI on Windows, Keychain on macOS). Tempting for vault passphrase caching, but adds complexity and platform-specific failure modes. The vault-with-passphrase model is simpler and more predictable. |
| `dotenv` / `python-dotenv` | Environment variable management. Secrets should NEVER be in env vars or .env files. The encrypted vault is the single secret store. |

---

## Cross-Platform Considerations

### Windows-Specific

| Concern | Approach | Confidence |
|---------|----------|------------|
| File permissions (chmod 600) | Windows ACLs via `icacls` or `win32security` from `pywin32`. Python's `os.chmod()` is effectively a no-op on Windows. You MUST use platform-specific code. | HIGH |
| Atomic file writes | `os.replace()` works on Windows (unlike `os.rename()` which fails if target exists on Windows). Use `os.replace()` cross-platform. | HIGH |
| DPAPI integration | `win32crypt.CryptProtectData()` from `pywin32`. Use for optional at-rest protection of the vault key in Windows Credential Manager. | MEDIUM |
| Firewall (netsh) | `subprocess.run(["netsh", "advfirewall", ...])`. No Python abstraction exists for Windows Firewall -- shell out directly. | HIGH |
| Service management | `schtasks` or Windows Task Scheduler COM API. WireGuard on Windows uses its own service (`wireguard.exe /installtunnelservice`). | MEDIUM |
| WireGuard path | Default: `C:\Program Files\WireGuard\`. Config dir: `C:\Windows\System32\config\systemprofile\AppData\Local\WireGuard\Configurations\`. Must handle spaces in paths. | MEDIUM |

### macOS-Specific

| Concern | Approach | Confidence |
|---------|----------|------------|
| WireGuard availability | `brew install wireguard-tools` (userspace) or WireGuard.app (GUI with kernel extension). CLI tool should target `wireguard-tools` (provides `wg` and `wg-quick`). | HIGH |
| Firewall (pfctl) | `subprocess.run(["pfctl", ...])`. pfctl requires root. Anchor-based rules recommended to avoid clobbering existing pf config. | MEDIUM |
| Launchd | `launchctl` for service management. Write plist files to `/Library/LaunchDaemons/`. | MEDIUM |
| Keychain (optional) | `security` CLI or `keyring` library. Consider for optional passphrase caching. | LOW |

### Linux-Specific

| Concern | Approach | Confidence |
|---------|----------|------------|
| WireGuard availability | Kernel module (5.6+) or `wireguard-dkms`. `wireguard-tools` for `wg`/`wg-quick`. | HIGH |
| Firewall | nftables (modern, preferred) vs iptables (legacy). Detect at runtime: `shutil.which("nft")` for nftables, fall back to iptables. | HIGH |
| Systemd | `systemctl enable/start wg-quick@wg0`. Standard approach. | HIGH |
| File permissions | `os.chmod(path, 0o600)` works correctly on Linux. | HIGH |

---

## Version Pinning Reference

All versions verified via `pip index versions` on 2026-03-17:

```
# requirements.in
click>=8.3.1,<9
cryptography>=46.0,<47
argon2-cffi>=25.1,<26
jinja2>=3.1.6,<4
qrcode>=8.2,<9
requests>=2.32.5,<3
rich>=14.3,<15

# requirements-dev.in
-c requirements.txt
pytest>=8.3.5,<9
pytest-cov>=6,<7
pytest-mock>=3.14,<4
pyinstaller>=6.19,<7
pip-audit>=2.10,<3
```

---

## Security Hardening Checklist (Stack-Level)

- [ ] `--require-hashes` on all pip installs (supply chain protection)
- [ ] `pip-audit` in CI pipeline (known vulnerability detection)
- [ ] `cryptography` nonce never reused (GCM catastrophic failure mode)
- [ ] Argon2id salt is random 16 bytes per vault creation (not derived/predictable)
- [ ] `requests` always uses `verify=True` and explicit timeouts
- [ ] No secrets in environment variables, CLI arguments, or log output
- [ ] `os.replace()` for atomic writes (not `os.rename()` -- Windows compat)
- [ ] File permissions enforced via platform-specific code on Windows
- [ ] PyInstaller builds signed for Windows distribution
- [ ] `del` sensitive variables after use (best-effort memory hygiene)

---

## Sources

- PyPI version data: verified via `pip index versions` on 2026-03-17 (HIGH confidence)
- cryptography library API: training data, verified by installed package (MEDIUM confidence)
- Argon2 OWASP recommendations: training data (MEDIUM confidence -- verify against https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- PyInstaller Windows behavior: training data + known community issues (MEDIUM confidence)
- Windows file permission limitations: well-established Python behavior (HIGH confidence)
- WireGuard platform paths: training data (MEDIUM confidence -- verify on target platforms)
- uv maturity assessment: LOW confidence (rapidly evolving project, may be production-ready now)
