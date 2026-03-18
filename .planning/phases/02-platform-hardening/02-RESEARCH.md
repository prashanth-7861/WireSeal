# Phase 2: Platform Hardening - Research

**Researched:** 2026-03-17
**Domain:** Cross-platform system adapter layer — nftables/pfctl/netsh, systemd/launchd/Windows services, privilege drop, subprocess security
**Confidence:** MEDIUM (platform APIs verified via official docs and live sources; Windows WireGuard tunnel service HIGH for core API, LOW for DPAPI flow details)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Privilege Escalation**
- Fail immediately at startup with clear message: `"wg-automate requires root/Administrator privileges. Re-run with: sudo wg-automate"` — no auto-escalation, no sudo re-exec offer
- Privilege check runs at startup, before any vault interaction — fast fail prevents partial state
- Windows UAC and Linux sudo/root handling: Claude's Discretion — pick the cleanest approach per platform
- Linux sudo vs root distinction: Claude's Discretion — decide whether to warn about HOME directory implications

**WireGuard Interface Naming**
- Fixed: always `wg0` — not configurable by user
- Interface name stored in vault (encrypted) — consistent with Phase 1 "all settings in vault" decision
- Existing `wg0` interface detection: Claude's Discretion — decide whether to fail, warn, or overwrite
- Windows: tunnel name = `wg0`, config file = `wg0.conf` — naming consistent across all platforms

**Firewall Approach (Linux)**
- nftables only — no iptables fallback, no autodetection
- Idempotent: check if rules already exist before applying — safe to re-run without duplicating rules
- Firewall rules applied separately by platform adapter, NOT via PostUp/PostDown hooks in wg0.conf — cleaner separation of concerns; rules persist across wg-quick restarts without hook timing dependency
- Missing nftables: Claude's Discretion — decide between fail-with-instructions vs auto-install

**Setup Failure and Progress**
- Partial setup failure: fail with clear message listing what succeeded and what failed, leave state as-is — no automatic rollback
- Prerequisite failures: print exact install command (e.g., `"Run: apt install wireguard nftables"`) — actionable, not vague
- Setup progress: numbered steps with status (e.g., `"[1/5] Installing WireGuard... done"`) — user sees exactly where it is and where it failed
- Re-running init on an already-initialized system: Claude's Discretion — decide between hard fail vs idempotent skip

### Claude's Discretion
- Windows UAC elevation approach (print instructions vs ShellExecuteEx runas)
- Linux sudo vs direct root warning behavior
- Existing wg0 interface detection on init (fail vs warn+confirm vs overwrite)
- Missing nftables: auto-install vs fail-with-instructions
- Re-running init on initialized system (fail vs idempotent)
- Privilege drop mechanism: HARD-04 (DuckDNS non-root user) lives in this phase

### Deferred Ideas (OUT OF SCOPE)
- None — discussion stayed within Phase 2 scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PLAT-01 | Detect OS/version at startup; refuse if not root/admin, unsupported OS, or missing tools | `sys.platform` + `platform.release()` detection; `os.geteuid()==0` on Unix, `ctypes.windll.shell32.IsUserAnAdmin()` on Windows |
| PLAT-02 | `AbstractPlatformAdapter` ABC — all 3 platforms implement same interface; missing methods = import-time failure | Python `abc.ABC` + `@abstractmethod` — `TypeError` raised at instantiation time if any abstract method is unimplemented |
| PLAT-03 | Linux: WireGuard via package manager (GPG sig verify), 600 perms config, IP forwarding via `sysctl.d`, nftables deny-by-default (rate limit 5 new/s burst 10), systemd `wg-quick@wg0`, DuckDNS cron as non-root `wg-automate` user | Full nftables ruleset documented; systemd and non-root user patterns confirmed; `sysctl.d` persistence approach documented |
| PLAT-04 | macOS: Homebrew WireGuard, 600 perms, IP forwarding via `sysctl.conf`, pfctl deny-by-default anchor, launchd plist | pfctl anchor approach confirmed; launchd plist format documented; sysctl persistence issue flagged |
| PLAT-05 | Windows: winget WireGuard (verify installer sig), config to `%ProgramData%\WireGuard\wg0.conf` with SYSTEM+Admins ACL, `IPEnableRouter=1` registry (reboot warning), netsh advfirewall deny-by-default, `wireguard.exe /installtunnelservice`, Task Scheduler for DuckDNS | `/installtunnelservice` API confirmed; DPAPI `.conf.dpapi` flow confirmed; `winreg` for `IPEnableRouter` documented; `netsh advfirewall` syntax confirmed |
| PLAT-06 | `os.chmod(600)` on Unix, `icacls`/`pywin32` on Windows (`os.chmod` is NO-OP on Windows) | Already built in Phase 1: `security/permissions.py` — Phase 2 reuses it unchanged |
| FW-01 | Deny-by-default on WireGuard interface; rate-limited UDP accept | nftables `policy drop` + `limit rate over 5/second burst 10` confirmed; netsh/pfctl equivalents documented |
| FW-02 | NAT masquerade on detected outbound interface via default route only | Default route detection pattern confirmed for all 3 platforms; `ip route get 8.8.8.8` on Linux, `socket.connect()` trick cross-platform |
| FW-03 | Firewall rules validated against deny-by-default templates before application | Template comparison pattern: generate expected ruleset string, compare against what would be applied, fail if mismatch |
| HARD-04 | Process privilege dropped after setup; DuckDNS runs as non-root `wg-automate` user | `adduser --system --no-create-home --shell /usr/sbin/nologin wg-automate`; `/etc/cron.d/wg-automate` pattern; launchd UserName key; Task Scheduler user account |
</phase_requirements>

---

## Summary

Phase 2 delivers the platform adapter library that Phase 4 (`init` command) will call. All three platform adapters (Linux, macOS, Windows) implement the same `AbstractPlatformAdapter` ABC, and incorrect implementations fail at import time. The adapters handle WireGuard installation, firewall configuration, service management, IP forwarding, and privilege drop — nothing about secrets or keys.

The biggest risk area is macOS. On Sequoia 15.x, a SIP bug (partially fixed in 15.1) prevents WireGuard VPN extensions from working when SIP is enabled. Since this project uses `wireguard-tools` (not the App Store WireGuard.app), it relies on `wg-quick` + `utun` interfaces — the SIP issue primarily affects the Network Extension API, not `wg-quick`. However, pfctl behavior changed in Sonoma (first-match regression), and the macOS firewall silently blocks WireGuard without prompting. Additionally, Intel Macs on Sequoia have a missing Homebrew bottle for `wireguard-tools` (arm64 bottle only). These are production caveats the planner must flag in verification steps.

The Windows path is the most complex. `wireguard.exe /installtunnelservice` creates a `WireGuardTunnel$wg0` Windows service; the Manager Service automatically encrypts the `.conf` to `.conf.dpapi` format (DPAPI-bound to Local System). `IPEnableRouter=1` in the registry enables IP routing but requires a reboot. Netsh advfirewall controls the deny-by-default posture. All of this is well-documented in the WireGuard Windows enterprise docs and works via `subprocess.run([...], shell=False)` without any additional Python libraries.

**Primary recommendation:** Build Linux first (testable in Docker), macOS second (fewest users, most caveats), Windows last (most complex but best-documented API). All three share the same ABC interface and the same `security/permissions.py` module from Phase 1.

---

## Standard Stack

### Core (Python stdlib — no new dependencies)

| Module | Purpose | Notes |
|--------|---------|-------|
| `abc` | `AbstractPlatformAdapter` ABC via `ABC` + `@abstractmethod` | Import-time enforcement of all method implementations |
| `subprocess` | Run platform CLI commands (`nft`, `pfctl`, `netsh`, `wireguard.exe`, `systemctl`, `launchctl`, `winget`) | Always `shell=False`, always list args — never string concatenation |
| `sys` | `sys.platform` for OS detection (`linux`, `darwin`, `win32`) | Checked before any adapter import |
| `platform` | `platform.release()`, `platform.version()` for OS version detection | Used to warn on EOL or unsupported versions |
| `os` | `os.geteuid()` (Unix) for root check; `os.environ` for `%ProgramData%` path | `os.geteuid() == 0` means root |
| `ctypes` | `ctypes.windll.shell32.IsUserAnAdmin()` for Windows admin check | Returns non-zero if admin |
| `winreg` | Windows registry: set `IPEnableRouter=1` at `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` | stdlib; Windows-only import inside `platform/windows.py` |
| `shutil` | `shutil.which()` for checking if `nft`, `wireguard`, `brew`, `winget` are on PATH | Cross-platform, stdlib |
| `pathlib` | Config file paths (`/etc/wireguard/wg0.conf`, `%ProgramData%\WireGuard\wg0.conf`, `/usr/local/etc/wireguard/wg0.conf`) | Consistent with Phase 1 |
| `textwrap` | Dedent multi-line nftables/pf ruleset strings for template comparison | Stdlib |
| `re` | Parse `ip route get` output for outbound interface | Stdlib |
| `socket` | Cross-platform UDP connect trick to detect outbound IP | Stdlib |

### No New PyPI Dependencies Required

Phase 1 already provides:
- `security/permissions.py` — `set_file_permissions()`, `set_dir_permissions()` (PLAT-06 done)
- `security/atomic.py` — `atomic_write()` for config file writes (CONFIG-03 done)

Phase 2 adds zero new PyPI packages. All platform interactions use subprocess or stdlib.

### Optional (Claude's Discretion)

| Library | Version | Purpose | When to Add |
|---------|---------|---------|------------|
| `pywin32` | already in requirements (Phase 1 fallback) | Windows ACL via `win32security` | Already available; `windows.py` can use it for ACL verification |

---

## Architecture Patterns

### Recommended Project Structure

```
src/wg_automate/
├── platform/
│   ├── __init__.py
│   ├── base.py          # AbstractPlatformAdapter ABC — 10 abstract methods
│   ├── detect.py        # OS detection + adapter factory function
│   ├── linux.py         # LinuxAdapter (systemd, nftables, sysctl.d, cron user)
│   ├── macos.py         # MacOSAdapter (launchd, pfctl anchor, sysctl, Homebrew)
│   └── windows.py       # WindowsAdapter (wireguard.exe service, netsh, winreg, Task Scheduler)
```

### Pattern 1: AbstractPlatformAdapter ABC

**What:** All three platform adapters subclass one ABC. `@abstractmethod` on every method guarantees that a partially-implemented adapter fails at import time (when Python tries to instantiate it), not at runtime.

**When to use:** This is the only pattern. No duck typing, no `Protocol`.

```python
# platform/base.py
from abc import ABC, abstractmethod
from pathlib import Path

class AbstractPlatformAdapter(ABC):
    """Contract for platform-specific WireGuard operations.
    All methods are abstract. Missing implementations fail at class instantiation.
    """

    @abstractmethod
    def check_privileges(self) -> None:
        """Raise PrivilegeError if not root/admin. Called first, before vault open."""
        ...

    @abstractmethod
    def check_prerequisites(self) -> None:
        """Raise PrerequisiteError listing missing tools with install instructions."""
        ...

    @abstractmethod
    def install_wireguard(self) -> None:
        """Install WireGuard via platform package manager if not present."""
        ...

    @abstractmethod
    def deploy_config(self, config_content: str, interface: str = "wg0") -> Path:
        """Write WireGuard config to platform path with correct permissions. Returns path."""
        ...

    @abstractmethod
    def apply_firewall_rules(self, wg_port: int, wg_iface: str, subnet: str) -> None:
        """Apply deny-by-default + rate-limited WireGuard UDP + NAT masquerade."""
        ...

    @abstractmethod
    def remove_firewall_rules(self, wg_iface: str) -> None:
        """Remove WireGuard-specific firewall rules."""
        ...

    @abstractmethod
    def enable_ip_forwarding(self) -> None:
        """Enable IPv4 forwarding persistently via platform mechanism."""
        ...

    @abstractmethod
    def enable_tunnel_service(self, interface: str = "wg0") -> None:
        """Enable and start tunnel service (systemd/launchd/Windows service)."""
        ...

    @abstractmethod
    def disable_tunnel_service(self, interface: str = "wg0") -> None:
        """Disable and stop tunnel service."""
        ...

    @abstractmethod
    def setup_dns_updater(self, script_path: Path, interval_minutes: int = 5) -> None:
        """Schedule DuckDNS update script to run as non-root/non-SYSTEM user."""
        ...

    @abstractmethod
    def get_config_path(self, interface: str = "wg0") -> Path:
        """Return the platform-canonical config file path for this interface."""
        ...

    @abstractmethod
    def detect_outbound_interface(self) -> str:
        """Return the name of the default outbound network interface."""
        ...
```

**Source:** Python `abc` module docs — https://docs.python.org/3/library/abc.html (HIGH confidence)

### Pattern 2: Platform Factory with Lazy Imports

**What:** `detect.py` checks `sys.platform` and imports only the matching adapter. Platform-specific modules import platform-specific stdlib (e.g., `winreg` on Windows) — eager import would fail on other OSes.

```python
# platform/detect.py
import sys
from .base import AbstractPlatformAdapter

def get_adapter() -> AbstractPlatformAdapter:
    """Detect platform and return the correct adapter instance."""
    if sys.platform == "linux":
        from .linux import LinuxAdapter
        return LinuxAdapter()
    elif sys.platform == "darwin":
        from .macos import MacOSAdapter
        return MacOSAdapter()
    elif sys.platform == "win32":
        from .windows import WindowsAdapter
        return WindowsAdapter()
    else:
        raise RuntimeError(
            f"Unsupported platform: {sys.platform}. "
            "wg-automate supports Linux, macOS, and Windows only."
        )
```

### Pattern 3: Subprocess Safety (No shell=True)

**What:** All subprocess calls use argument lists, never shell strings. This is the only safe pattern for a privileged tool.

```python
# Source: https://semgrep.dev/docs/cheat-sheets/python-command-injection (MEDIUM)
# and https://security.openstack.org/guidelines/dg_avoid-shell-true.html (MEDIUM)

import subprocess

# CORRECT — argument list, no shell, check=True raises on non-zero exit
result = subprocess.run(
    ["nft", "-f", "/etc/nftables.d/wireguard.nft"],
    capture_output=True,
    text=True,
    shell=False,      # explicit, default is False — document intent
    check=True,       # raises CalledProcessError on non-zero exit
    timeout=30,
)

# WRONG — never do this
subprocess.run(f"nft -f {nft_file}", shell=True)  # injection risk
subprocess.run("systemctl enable " + service_name, shell=True)  # injection risk
```

**Key rule:** Every string that touches a subprocess must either be a hardcoded constant or a value validated with allowlist regex before use. Interface names (`wg0`), ports (integers), and paths (validated `Path` objects) are safe. User-supplied strings from the vault are validated in Phase 1 (CONFIG-06: `^[a-zA-Z0-9-]{1,32}$`).

### Pattern 4: Privileged Check First, Before Vault

**What:** The `check_privileges()` call happens in `get_adapter()` or immediately on adapter construction — before the vault passphrase prompt. This avoids collecting a passphrase only to fail seconds later.

```python
# Usage in init command (Phase 4 will call this):
adapter = get_adapter()
adapter.check_privileges()   # fast fail — raises immediately if not root/admin
adapter.check_prerequisites()  # raises with install instructions if tools missing
# ... only now prompt for vault passphrase
```

**Linux privilege check:**
```python
import os
if os.geteuid() != 0:
    raise PrivilegeError(
        "wg-automate requires root privileges. Re-run with: sudo wg-automate"
    )
```

**Windows privilege check:**
```python
import ctypes
if not ctypes.windll.shell32.IsUserAnAdmin():
    raise PrivilegeError(
        "wg-automate requires Administrator privileges. "
        "Re-run from an elevated command prompt (Run as Administrator)."
    )
```

### Pattern 5: Progress Reporting (Locked in CONTEXT.md)

**What:** All multi-step operations emit numbered progress via `print()` to stdout. Format: `[N/TOTAL] Description... done`.

```python
# Step counter helper — lightweight, no dependencies
class Progress:
    def __init__(self, total: int):
        self.total = total
        self.current = 0

    def step(self, description: str):
        self.current += 1
        print(f"[{self.current}/{self.total}] {description}...", end=" ", flush=True)

    def done(self):
        print("done")

    def fail(self, error: str):
        print(f"FAILED\n  Error: {error}")
        print(
            f"Setup failed at step {self.current}/{self.total}. "
            f"Steps 1-{self.current-1} completed successfully. "
            "Fix the error above and re-run."
        )
```

### Anti-Patterns to Avoid

- **`shell=True` in subprocess**: Never. Even with validated inputs. Document why in every subprocess call.
- **Modifying `/etc/pf.conf` on macOS directly**: Gets overwritten on OS updates. Use anchors: `pfctl -a com.apple/wireguard`.
- **Editing `/etc/nftables.conf` directly**: Use a drop-in file at `/etc/nftables.d/wireguard.nft` and `include` it, so the base config is untouched.
- **Storing DPAPI token path assumptions**: On Windows, `wireguard.exe /installtunnelservice` with a `.conf` file; the Manager Service auto-encrypts to `.conf.dpapi`. Do not pre-encrypt or attempt to manage the DPAPI file directly.
- **Using `sysctl.conf` on macOS for persistence**: Not reliably persistent on Sonoma/Sequoia. Use `sysctl -w` at start/stop time (via `PostUp`/`PostDown` or launchd scripts), not persistent file writes.
- **Hardcoding the outbound interface name** (e.g., `eth0`): Detect dynamically at runtime via `ip route get 8.8.8.8` on Linux/macOS, `Get-NetRoute` equivalent on Windows.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Windows admin check | Manual token inspection | `ctypes.windll.shell32.IsUserAnAdmin()` | Direct Windows API, one line, reliable |
| Windows registry write | Win32 API via ctypes | `import winreg` (stdlib) | stdlib, no deps, correct |
| File permissions on Windows | Custom DACL code | `security/permissions.py` (Phase 1 built this) | Already tested, handles icacls + pywin32 fallback |
| Atomic config writes | Custom temp+rename | `security/atomic.py` (Phase 1 built this) | Already tested, cross-platform |
| Windows WireGuard tunnel management | Custom named-pipe IPC | `wireguard.exe /installtunnelservice` + `sc.exe` | Official API, supported by WireGuard team |
| macOS plist generation | String templates | Python stdlib `plistlib` module | Handles escaping, correct XML/binary plist format |
| Cross-platform outbound interface detection | Complex routing table parsing | `socket.connect("8.8.8.8", 80)` UDP trick | Works on all 3 platforms, no subprocess needed for IP |

**Key insight:** Every platform API that exists should be used. The risk of hand-rolling firewall rule management, service registration, or permission-setting is that each has subtle edge cases (interface GUIDs regenerating on Windows, pf.conf overwrite on macOS updates, sysctl.d load ordering on Linux) that the standard tools handle correctly.

---

## Platform-Specific Details

### Linux

**WireGuard config path:** `/etc/wireguard/wg0.conf` (created by `wg-quick`, permissions 600)

**IP forwarding persistence:** Write `/etc/sysctl.d/99-wireguard.conf` with `net.ipv4.ip_forward=1`, then run `sysctl -p /etc/sysctl.d/99-wireguard.conf`. The `sysctl.d` drop-in approach survives OS updates.

**nftables ruleset** (apply to `/etc/nftables.d/wireguard.nft`):

```nft
# /etc/nftables.d/wireguard.nft
# MANAGED BY wg-automate — DO NOT EDIT MANUALLY

define pub_iface = "eth0"  # replaced at runtime with detected outbound interface
define wg_iface = "wg0"
define wg_port = 51820     # replaced at runtime with configured port

table inet wg_filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        meta l4proto { icmp, ipv6-icmp } accept
        ct state { established, related } accept
        ct state invalid drop
        # Rate-limit new UDP connections to WireGuard port
        iifname $pub_iface udp dport $wg_port ct state new limit rate over 5/second burst 10 packets drop
        iifname $pub_iface udp dport $wg_port accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        iifname $wg_iface oifname $pub_iface ct state new accept
        ct state { established, related } accept
    }
}

table ip wg_nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        iifname $wg_iface oifname $pub_iface masquerade
    }
}
```

**Important:** The CONTEXT.md locks firewall rules to be applied separately (NOT via PostUp/PostDown). The nftables table name `wg_filter` should be checked for existence before applying to ensure idempotency.

**Idempotency check:**
```python
result = subprocess.run(["nft", "list", "table", "inet", "wg_filter"],
                        capture_output=True, shell=False)
if result.returncode == 0:
    return  # rules already applied
```

**Systemd service:**
```bash
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
```

**Non-root DuckDNS user (HARD-04):**
```bash
adduser wg-automate --system --no-create-home --shell /usr/sbin/nologin --group
```
Cron entry written to `/etc/cron.d/wg-automate` (permissions 644, owned root):
```
*/5 * * * * wg-automate /usr/local/bin/wg-automate update-dns --non-interactive
```

**Detect outbound interface:**
```python
import subprocess, re

def detect_outbound_interface() -> str:
    result = subprocess.run(
        ["ip", "route", "get", "8.8.8.8"],
        capture_output=True, text=True, shell=False, check=True
    )
    match = re.search(r'\bdev\s+(\S+)', result.stdout)
    if not match:
        raise RuntimeError("Cannot detect outbound interface from routing table")
    return match.group(1)
```

**Source:** https://www.procustodibus.com/blog/2021/11/wireguard-nftables/ (MEDIUM — verified against nftables wiki syntax)

---

### macOS

**WireGuard config path:** `/usr/local/etc/wireguard/wg0.conf` (Homebrew Intel) or `/opt/homebrew/etc/wireguard/wg0.conf` (Homebrew Apple Silicon)

**Homebrew path detection:**
```python
import subprocess, sys
result = subprocess.run(["brew", "--prefix"], capture_output=True, text=True, shell=False)
brew_prefix = result.stdout.strip()  # /usr/local or /opt/homebrew
```

**Homebrew Intel + Sequoia warning:** Fresh install of `wireguard-tools` on Intel Mac running Sequoia fails (arm64-only bottle). Warn user if `platform.machine() == "x86_64"` and macOS version >= 15.

**IP forwarding:** Use runtime `sysctl -w` (no reliable persistence via `sysctl.conf` on Sonoma/Sequoia):
```python
subprocess.run(["/usr/sbin/sysctl", "-w", "net.inet.ip.forwarding=1"],
               shell=False, check=True)
```
**Note:** Since CONTEXT.md says firewall rules are applied by the adapter (not PostUp/PostDown), the `sysctl -w` call is made directly from the macOS adapter's `enable_ip_forwarding()`. IP forwarding will be lost on reboot unless the launchd plist also calls `sysctl -w` at boot time.

**Mitigation for IP forwarding persistence on macOS:** The launchd plist for the WireGuard daemon should be supplemented with a separate launchd plist that runs `sysctl -w net.inet.ip.forwarding=1` at boot. Or: use a `PostUp` in `wg0.conf` specifically for IP forwarding (this is a single system call, not a firewall rule, so it does not violate the CONTEXT.md firewall separation requirement).

**pfctl anchor (deny-by-default + NAT):**

macOS uses PF anchors. Do NOT edit `/etc/pf.conf` directly (overwritten by OS updates). Use the `com.apple/wireguard` sub-anchor:

```python
# Detect outbound interface first (e.g., en0)
outbound_iface = self.detect_outbound_interface()
subnet = "10.0.0.0/24"  # from vault

pf_rules = f"""
pass in on {outbound_iface} proto udp from any to any port {wg_port} keep state
nat on {outbound_iface} from {subnet} to any -> ({outbound_iface})
block drop in on {outbound_iface} all
"""

# Load rules into com.apple/wireguard anchor, save token
proc = subprocess.run(
    ["pfctl", "-a", "com.apple/wireguard", "-Ef", "-"],
    input=pf_rules.encode(),
    capture_output=True,
    shell=False,
    check=True,
)
# Parse token from output for later cleanup
token_match = re.search(r'Token\s*:\s*(\d+)', proc.stderr.decode())
if token_match:
    token_path = Path("/var/run/wg-automate/pf_token")
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(token_match.group(1))
```

**Remove anchor on teardown:**
```python
token = Path("/var/run/wg-automate/pf_token").read_text().strip()
subprocess.run(["pfctl", "-X", token], shell=False, check=True)
```

**launchd plist:** Write to `/Library/LaunchDaemons/com.wg-automate.wg0.plist`:

```python
import plistlib  # stdlib
from pathlib import Path

plist_data = {
    "Label": "com.wg-automate.wg0",
    "ProgramArguments": [
        str(Path(brew_prefix) / "bin/wg-quick"),
        "up",
        str(wg_config_path),
    ],
    "KeepAlive": True,
    "RunAtLoad": True,
    "LaunchOnlyOnce": True,
    "StandardErrorPath": "/var/log/wg-automate.err",
    "EnvironmentVariables": {
        "PATH": f"{brew_prefix}/sbin:{brew_prefix}/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    },
}
plist_path = Path("/Library/LaunchDaemons/com.wg-automate.wg0.plist")
plist_path.write_bytes(plistlib.dumps(plist_data))
subprocess.run(["chown", "root:wheel", str(plist_path)], shell=False, check=True)
subprocess.run(["chmod", "644", str(plist_path)], shell=False, check=True)
subprocess.run(["launchctl", "enable", "system/com.wg-automate.wg0"],
               shell=False, check=True)
subprocess.run(["launchctl", "bootstrap", "system", str(plist_path)],
               shell=False, check=True)
```

**DuckDNS as non-root on macOS (HARD-04):** Use a separate launchd plist with `UserName` key set to a local non-admin user (created by the setup process). The `UserName` key in a LaunchDaemon plist drops privileges to that user.

**Detect outbound interface (macOS):** `route get 8.8.8.8` (same `dev` parsing, or `socket` UDP trick):
```python
import socket
def detect_outbound_interface_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
# Then map IP back to interface name via ifconfig parsing if needed
```

**Source:** barrowclift.me WireGuard Server on macOS (MEDIUM, updated for Sequoia 15.2); scottlowe.org launchd guide (MEDIUM)

---

### Windows

**WireGuard config path:** `%ProgramData%\WireGuard\wg0.conf` = `C:\ProgramData\WireGuard\wg0.conf`

**winget install:**
```python
subprocess.run(
    ["winget", "install", "--id", "WireGuard.WireGuard",
     "--silent", "--accept-package-agreements", "--accept-source-agreements"],
    shell=False, check=True, timeout=120
)
```
winget verifies package signatures automatically against the Windows Package Manager community repository — no manual verification step needed. The package metadata includes SHA-256 hashes.

**WireGuard executable path after install:** `C:\Program Files\WireGuard\wireguard.exe`

**Install tunnel service:**
```python
wg_exe = Path(r"C:\Program Files\WireGuard\wireguard.exe")
config_path = Path(os.environ["ProgramData"]) / "WireGuard" / "wg0.conf"
subprocess.run(
    [str(wg_exe), "/installtunnelservice", str(config_path)],
    shell=False, check=True
)
# Service created: WireGuardTunnel$wg0
# Manager Service auto-encrypts wg0.conf -> wg0.conf.dpapi (DPAPI-bound to LocalSystem)
# The original .conf is deleted after encryption
```

**Service start/stop:**
```python
subprocess.run(["sc.exe", "start", "WireGuardTunnel$wg0"], shell=False, check=True)
subprocess.run(["sc.exe", "stop", "WireGuardTunnel$wg0"], shell=False, check=True)
subprocess.run(["sc.exe", "config", "WireGuardTunnel$wg0", "start=auto"],
               shell=False, check=True)
```

**IPEnableRouter registry key (IP forwarding):**
```python
import winreg  # stdlib, Windows only

key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                    winreg.KEY_SET_VALUE) as key:
    winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
print(
    "[!] IP routing enabled. A system reboot is required for this to take effect. "
    "Reboot now and re-run wg-automate init to complete setup."
)
```
**IMPORTANT:** This requires a reboot. The setup must detect if a reboot is pending and inform the user. Flag this as a two-step process in the init command.

**Detect outbound interface on Windows:**
```python
import subprocess, re

result = subprocess.run(
    ["powershell", "-NoProfile", "-Command",
     "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias"],
    capture_output=True, text=True, shell=False, check=True
)
outbound_iface = result.stdout.strip()  # e.g., "Ethernet" or "Wi-Fi"
```

**netsh advfirewall deny-by-default + WireGuard allow:**

Note: Windows WireGuard creates a virtual interface named `wg0`. Every `wireguard.exe /installtunnelservice` call regenerates the interface GUID, so rules should target interface alias `wg0`, not GUID.

```python
wg_port = 51820  # from vault
# Allow inbound WireGuard UDP
subprocess.run(
    ["netsh", "advfirewall", "firewall", "add", "rule",
     "name=wg-automate-wg0-in",
     "protocol=UDP", "dir=in",
     f"localport={wg_port}",
     "action=allow",
     "profile=any",
     "enable=yes"],
    shell=False, check=True
)
# Block all other inbound on the WG interface by setting profile to public
subprocess.run(
    ["netsh", "interface", "set", "interface", "wg0",
     "admin=enabled"],
    shell=False, check=True
)
# Set WG interface to public profile (most restrictive)
subprocess.run(
    ["powershell", "-NoProfile", "-Command",
     "Set-NetConnectionProfile -InterfaceAlias wg0 -NetworkCategory Public"],
    shell=False, check=True
)
```

**Source:** https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior (HIGH — Microsoft docs)

**DuckDNS via Task Scheduler (HARD-04):**
```python
# Create a low-privilege local user for DuckDNS updates
subprocess.run(
    ["net", "user", "wg-automate-dns", "/add", "/expires:never", "/passwordchg:no"],
    shell=False, check=True
)
# Create scheduled task running as that user (read vault token from credential manager)
subprocess.run(
    ["schtasks", "/create", "/tn", "WgAutomateDNS",
     "/tr", r"C:\Program Files\wg-automate\wg-automate.exe update-dns",
     "/sc", "minute", "/mo", "5",
     "/ru", "wg-automate-dns",
     "/f"],
    shell=False, check=True
)
```

**Source:** WireGuard Windows enterprise.md — https://github.com/WireGuard/wireguard-windows/blob/master/docs/enterprise.md (HIGH)

---

## Common Pitfalls

### Pitfall 1: macOS pf.conf Overwritten by OS Updates
**What goes wrong:** Custom rules in `/etc/pf.conf` are silently replaced on macOS system updates, removing all WireGuard firewall rules.
**Why it happens:** macOS treats `/etc/pf.conf` as system-owned.
**How to avoid:** Use pfctl anchors (`com.apple/wireguard`) exclusively. Never write to `/etc/pf.conf`. The anchor approach persists across updates because anchor files live in `/etc/pf.anchors/` and rules are applied dynamically.
**Warning signs:** After a macOS update, `pfctl -a com.apple/wireguard -sn` returns empty.

### Pitfall 2: macOS IP Forwarding Lost on Reboot
**What goes wrong:** `sysctl -w net.inet.ip.forwarding=1` is runtime-only. After reboot, WireGuard tunnel comes up (launchd starts it) but traffic cannot be forwarded.
**Why it happens:** macOS `/etc/sysctl.conf` is unreliable for persistence on Sonoma/Sequoia.
**How to avoid:** Add a separate launchd plist that executes `sysctl -w net.inet.ip.forwarding=1` at boot, OR accept that the `wg-quick up` call (via PostUp for IP forwarding only, not firewall) handles it. PostUp for `sysctl -w` is acceptable because it's not a firewall rule.
**Warning signs:** Tunnel shows `up` in `wg show` but clients cannot reach internet.

### Pitfall 3: Windows Interface GUID Regeneration
**What goes wrong:** Every `wireguard.exe /installtunnelservice` call generates a new interface GUID. Any firewall rules or profile settings bound to the old GUID are silently abandoned.
**Why it happens:** Windows identifies network interfaces by GUID, not by alias.
**How to avoid:** Write all firewall rules using interface alias (`wg0`) not GUID. Use `Set-NetConnectionProfile -InterfaceAlias wg0` (PowerShell) not GUID-based targeting.
**Warning signs:** After re-running setup, firewall shows duplicate rules or WG traffic is unexpectedly blocked.

### Pitfall 4: Windows IPEnableRouter Requires Reboot
**What goes wrong:** Setup completes, `wireguard.exe /installtunnelservice` succeeds, but clients cannot route through the server.
**Why it happens:** `IPEnableRouter=1` is read by the TCP/IP stack at boot only.
**How to avoid:** Detect if `IPEnableRouter` was just set to 1 (check old value first), and if so, print a clear reboot warning and exit. The `init` command must gracefully handle the two-phase setup scenario: Phase 1 sets IPEnableRouter and exits, user reboots, Phase 2 continues from where it stopped.
**Warning signs:** `IPEnableRouter=1` in registry but `netsh interface ipv4 show interfaces` shows forwarding disabled.

### Pitfall 5: nftables Rules Duplicated on Re-run
**What goes wrong:** Re-running `wg-automate init` on an already-set-up Linux system adds duplicate nftables tables, causing `nft` to fail or apply rules twice.
**Why it happens:** nftables does not deduplicate tables on apply by default.
**How to avoid:** Before applying rules, check if `table inet wg_filter` already exists: `nft list table inet wg_filter`. If it exists and rules match the expected template (FW-03), skip. If it exists but doesn't match, flush and re-apply.
**Warning signs:** `nft list ruleset` shows `wg_filter` appearing twice.

### Pitfall 6: macOS Homebrew Refuses to Run as root
**What goes wrong:** `brew install wireguard-tools` fails with "Running Homebrew as root is extremely dangerous."
**Why it happens:** Homebrew deliberately refuses root execution since version ~3.x.
**How to avoid:** Do NOT run `brew` via `subprocess.run(["brew", ...])` as root. Instead, check if `wg-quick` exists before calling brew. If WireGuard is not installed, print the install command for the user to run themselves (logged-in user, not root), then exit and ask user to re-run after installing. Alternative: use `sudo -u <actual_user> brew install wireguard-tools` — detect the actual user from `SUDO_USER` environment variable.
**Warning signs:** `brew install` returns non-zero exit code with "Running Homebrew as root" message.

### Pitfall 7: DuckDNS User Needs Vault Read Access
**What goes wrong:** `wg-automate` system user runs the DNS update cron job but cannot read the encrypted vault (`~/.wg-automate/vault.enc`, perms 600, owned by root).
**Why it happens:** The DuckDNS token lives in the vault, which is root-owned.
**How to avoid:** The non-root `wg-automate` user should NOT access the vault directly. Instead, the init command extracts the DuckDNS token from the vault and writes it to a separate credential file owned by `wg-automate` (600, owned by `wg-automate`), or uses the OS credential store (Linux keyring, macOS Keychain, Windows Credential Manager). Simplest approach: write the token to `/etc/wg-automate/duckdns.token` with permissions `640`, owned `root:wg-automate`.
**Warning signs:** DNS update cron job fails with "Permission denied" or "Vault unlock failed."

### Pitfall 8: subprocess output on Windows has CRLF line endings
**What goes wrong:** Parsing `netsh` or PowerShell output with `\n.split()` produces lines with trailing `\r` characters.
**Why it happens:** Windows tools use CRLF (`\r\n`) line endings.
**How to avoid:** Always use `.strip()` on subprocess output before parsing. Use `text=True` with `subprocess.run()` which handles encoding, then call `stdout.splitlines()` (handles `\r\n`, `\n`, `\r` uniformly).

---

## Code Examples

### Detect Outbound Interface (Cross-Platform)

```python
# Source: Python socket docs (HIGH) + ip-route parsing (MEDIUM)
import socket
import subprocess
import re
import sys

def detect_outbound_interface_name() -> str:
    """Return the interface name used for default outbound traffic."""
    if sys.platform == "linux":
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, shell=False, check=True
        )
        match = re.search(r'\bdev\s+(\S+)', result.stdout)
        if not match:
            raise RuntimeError("Cannot determine outbound interface")
        return match.group(1)

    elif sys.platform == "darwin":
        result = subprocess.run(
            ["route", "-n", "get", "8.8.8.8"],
            capture_output=True, text=True, shell=False, check=True
        )
        for line in result.stdout.splitlines():
            if "interface:" in line:
                return line.split("interface:")[-1].strip()
        raise RuntimeError("Cannot determine outbound interface")

    elif sys.platform == "win32":
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
             "Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias"],
            capture_output=True, text=True, shell=False, check=True
        )
        iface = result.stdout.strip()
        if not iface:
            raise RuntimeError("Cannot determine outbound interface")
        return iface
```

### FW-03: Validate Rules Against Template Before Apply

```python
# Source: pattern derived from requirements FW-03
def validate_firewall_rules(generated_rules: str, template_rules: str) -> None:
    """Raise if generated rules do not match the deny-by-default template.

    Strips whitespace from both for comparison — protects against
    injection via subnet/port/interface values that alter rule structure.
    """
    import textwrap

    def normalize(rules: str) -> str:
        return "\n".join(
            line.strip() for line in rules.splitlines()
            if line.strip() and not line.strip().startswith("#")
        )

    if normalize(generated_rules) != normalize(template_rules):
        raise FirewallValidationError(
            "Generated firewall rules do not match the expected deny-by-default "
            "template. Refusing to apply. This may indicate a config injection attempt."
        )
```

### Linux: Non-Root User Creation + Cron

```python
# Source: adduser man page (HIGH)
import subprocess
from pathlib import Path

def setup_dns_user_linux() -> None:
    """Create wg-automate system user for DuckDNS cron job."""
    # Check if user already exists
    result = subprocess.run(
        ["id", "wg-automate"], capture_output=True, shell=False
    )
    if result.returncode == 0:
        return  # Already exists

    subprocess.run(
        ["adduser", "wg-automate",
         "--system",
         "--no-create-home",
         "--shell", "/usr/sbin/nologin",
         "--group",
         "--disabled-password"],
        shell=False, check=True
    )

def setup_dns_cron_linux(token_path: Path, wg_automate_bin: Path) -> None:
    """Write /etc/cron.d/wg-automate entry."""
    cron_content = (
        f"*/5 * * * * wg-automate "
        f"{wg_automate_bin} update-dns --token-file {token_path}\n"
    )
    cron_path = Path("/etc/cron.d/wg-automate")
    cron_path.write_text(cron_content)
    cron_path.chmod(0o644)
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| iptables on Linux | nftables | Linux 3.13 kernel (2014), default in Debian 10+ / Ubuntu 20.04+ | CONTEXT.md locks nftables-only; no iptables fallback |
| `wg-quick` PostUp/PostDown for firewall rules | Platform adapter applies rules separately | CONTEXT.md decision | Cleaner separation; rules persist across `wg-quick restart` |
| `/etc/pf.conf` edit on macOS | pfctl anchors (`com.apple/wireguard`) | Established best practice for macOS Monterey+ | Survives OS updates |
| WireGuard Windows GUI only | `wireguard.exe /installtunnelservice` CLI | WireGuard for Windows 0.3.0+ (enterprise.md) | Full CLI automation possible |
| `sysctl.conf` for macOS persistence | Runtime `sysctl -w` per boot via launchd | macOS Ventura/Sonoma | Persistent `sysctl.conf` unreliable on Sonoma/Sequoia |
| `os.chmod()` on Windows | `icacls` / `pywin32` | Always — `os.chmod` never worked on Windows | Phase 1 `permissions.py` handles this correctly |

**Deprecated/outdated:**
- `iptables`: Superseded by nftables. CONTEXT.md prohibits iptables fallback.
- `net.inet.ip.forwarding` via `/etc/sysctl.conf` on macOS: Unreliable since Sonoma. Use runtime or PostUp.
- WireGuard Windows DPAPI manual management: `wireguard.exe /installtunnelservice` handles DPAPI automatically — do not pre-encrypt or manually manage `.conf.dpapi` files.

---

## Open Questions

1. **macOS: IP forwarding persistence without PostUp**
   - What we know: `sysctl.conf` is unreliable on Sonoma/Sequoia; runtime `sysctl -w` works
   - What's unclear: Does the platform adapter directly call `sysctl -w` on every `enable_tunnel_service()`, or is a separate launchd plist needed for boot persistence?
   - Recommendation: Use a companion launchd plist for IP forwarding (`com.wg-automate.sysctl`) that runs `sysctl -w` at boot. This is the cleanest separation.

2. **Windows: Reboot Detection for IPEnableRouter**
   - What we know: Setting `IPEnableRouter=1` requires reboot; reboot detection can read the old value before writing
   - What's unclear: Should `init` exit and wait, or use a reboot sentinel file to resume?
   - Recommendation: Check current `IPEnableRouter` value. If already 1, skip. If 0, set to 1, print reboot warning, write a sentinel file (`%ProgramData%\WireGuard\.needs-reboot`), and exit with non-zero code. On re-run, check for sentinel, delete it, and continue from next step.

3. **macOS: Homebrew runs as root issue**
   - What we know: Homebrew refuses root; `SUDO_USER` env var is available when using sudo
   - What's unclear: Is the setup run as root directly, or via `sudo`?
   - Recommendation: Check `SUDO_USER` env var. If present, use `subprocess.run(["sudo", "-u", os.environ["SUDO_USER"], "brew", "install", "wireguard-tools"])`. If running as root directly (e.g., root login), tell user to install Homebrew/wireguard-tools manually and re-run.

4. **Windows: DuckDNS token access for non-SYSTEM user**
   - What we know: The `wg-automate-dns` Task Scheduler user cannot access the DPAPI-encrypted vault; token needs to be separately accessible
   - What's unclear: Windows Credential Manager vs. plaintext token file with ACL
   - Recommendation: Write DuckDNS token to `%ProgramData%\WireGuard\duckdns.token` with ACL granting read to `wg-automate-dns` user and SYSTEM only. Use `security/permissions.py` pattern adapted for this specific ACL.

5. **FW-03 Template Validation: What exactly constitutes "matching the template"?**
   - What we know: Requirement says validate against deny-by-default templates before application
   - What's unclear: Full structural equality, or just presence of key rules (policy drop, rate limit, NAT)?
   - Recommendation: Validate that generated ruleset contains all three required components: (1) `policy drop` on input chain, (2) rate-limiting rule, (3) NAT masquerade on outbound interface only. Exact whitespace/ordering flexibility is acceptable.

---

## Sources

### Primary (HIGH confidence)
- Python `abc` module — https://docs.python.org/3/library/abc.html — ABC + @abstractmethod behavior
- Python `winreg` module — https://docs.python.org/3/library/winreg.html — IPEnableRouter registry write
- WireGuard Windows enterprise.md — https://github.com/WireGuard/wireguard-windows/blob/master/docs/enterprise.md — `/installtunnelservice`, DPAPI `.conf.dpapi` format, named pipe IPC, service management
- Microsoft `netsh advfirewall` — https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior — deny-by-default syntax
- Microsoft `Get-NetRoute` — https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute — Windows outbound interface detection
- Phase 1 `security/permissions.py` — already implemented, PLAT-06 is done

### Secondary (MEDIUM confidence)
- Pro Custodibus nftables + WireGuard — https://www.procustodibus.com/blog/2021/11/wireguard-nftables/ — complete nftables ruleset
- barrowclift.me WireGuard Server on macOS (updated Sequoia 15.2) — https://barrowclift.me/articles/wireguard-server-on-macos — launchd plist format, pfctl anchor, IP forwarding
- Scott Lowe's WireGuard launchd guide — https://blog.scottlowe.org/2021/08/04/starting-wireguard-interfaces-automatically-launchd-macos/ — verified launchd plist approach
- Semgrep subprocess injection prevention — https://semgrep.dev/docs/cheat-sheets/python-command-injection — subprocess safety patterns
- OpenStack security guidelines — https://security.openstack.org/guidelines/dg_avoid-shell-true.html — no shell=True policy
- adduser man page behavior — multiple sources confirming `--system --no-create-home --shell /usr/sbin/nologin` pattern

### Tertiary (LOW confidence)
- macOS SIP + WireGuard issues — Apple Developer Forums thread — SIP bug on Sequoia 15.0/15.1 affects Network Extension API, NOT `wg-quick` (needs verification per-version)
- Intel Mac Sequoia Homebrew bottle issue — reported by community, not officially documented — flag for testing
- Windows DuckDNS token file via ACL approach — derived from requirements + Phase 1 permissions pattern, not tested

---

## Metadata

**Confidence breakdown:**
- AbstractPlatformAdapter ABC pattern: HIGH — Python stdlib, well-documented
- Linux (nftables + systemd + non-root user): HIGH — all verified against official/authoritative sources
- macOS (pfctl anchor + launchd + Homebrew path): MEDIUM — documented patterns work, but Sequoia-specific caveats need testing
- Windows (wireguard.exe service + netsh + winreg + winget): HIGH for core API; MEDIUM for DuckDNS user token access approach
- Subprocess safety patterns: HIGH — official docs confirm shell=False semantics
- Outbound interface detection: HIGH (Linux/macOS socket trick), MEDIUM (Windows PowerShell cmdlet)

**Research date:** 2026-03-17
**Valid until:** 2026-04-17 (30 days — nftables/Windows APIs are stable; macOS Sequoia caveats may evolve faster, re-check if macOS version >= 15.2)
