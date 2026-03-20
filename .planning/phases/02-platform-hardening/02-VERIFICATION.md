---
phase: 02-platform-hardening
verified: 2026-03-18T16:00:00Z
status: gaps_found
score: 9/10 must-haves verified
re_verification: false
gaps:
  - truth: "validate_firewall_rules raises on rules not matching deny-by-default template (FW-03)"
    status: partial
    reason: >
      The validate_firewall_rules function is correctly implemented and FirewallValidationError
      is properly raised on mismatch. However, in all three adapters (Linux, macOS, Windows),
      both the 'generated' and 'template' arguments are constructed identically within the same
      call scope — meaning the comparison is tautological and will always pass. The function
      cannot catch a real template deviation because there is no independent template string.
      The infrastructure satisfies the letter of FW-03 (function exists, exception raised on
      mismatch) but not the spirit (guard against generated rules diverging from the canonical
      deny-by-default pattern).
    artifacts:
      - path: "src/wg_automate/platform/linux.py"
        issue: "_build_nftables_ruleset() called twice with same args; generated == template always"
      - path: "src/wg_automate/platform/macos.py"
        issue: "rules and template f-strings are byte-for-byte identical in apply_firewall_rules"
      - path: "src/wg_automate/platform/windows.py"
        issue: "generated and template strings are identical literals in apply_firewall_rules"
    missing:
      - "Store an independent module-level TEMPLATE constant (with placeholders) for each adapter"
      - "Generate rules from runtime values, then validate against the filled-in template"
      - "This catches any future code drift where 'policy drop' or rate-limit params are accidentally omitted"
human_verification:
  - test: "Run wg-automate init on a real Linux system (Ubuntu 22.04 or 24.04 with root)"
    expected: >
      All 6 progress steps print [N/6] Description... done. nft list ruleset shows
      wg_filter table with policy drop on input and forward chains, rate-limit rule,
      and wg_nat masquerade on the outbound interface only. systemctl status
      wg-quick@wg0 shows active. /etc/cron.d/wg-automate exists with wg-automate user.
    why_human: "Requires real Linux system with WireGuard kernel module and nftables"
  - test: "Run wg-automate init on macOS 14+ (Sonoma/Sequoia) with sudo"
    expected: >
      pfctl -a com.apple/wireguard -sr shows deny-by-default rules with wg_bruteforce table.
      /Library/LaunchDaemons/com.wg-automate.wg0.plist exists and is loaded.
      sysctl net.inet.ip.forwarding returns 1.
    why_human: "Requires real macOS hardware with WireGuard installed via Homebrew"
  - test: "Run wg-automate init on Windows 10/11 as Administrator"
    expected: >
      netsh advfirewall firewall show rule name=wg-automate-wg0-in shows the allow rule.
      sc query WireGuardTunnel$wg0 shows RUNNING. Registry IPEnableRouter=1 is set.
      Task Scheduler shows WgAutomateDNS task as wg-automate-dns user.
    why_human: "Requires real Windows system with Administrator elevation and WireGuard installed"
---

# Phase 02: Platform Hardening Verification Report

**Phase Goal:** Users can run one-command server setup on Linux, macOS, or Windows with platform-native firewall hardening, service management, and correct file permissions
**Verified:** 2026-03-18T16:00:00Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | get_adapter() returns the correct adapter subclass for the current OS | VERIFIED | detect.py: sys.platform branches with lazy imports for LinuxAdapter, MacOSAdapter, WindowsAdapter |
| 2 | get_adapter() raises UnsupportedPlatformError on unsupported OS | VERIFIED | detect.py line 60-63: raises UnsupportedPlatformError with platform name |
| 3 | AbstractPlatformAdapter cannot be instantiated directly (TypeError) | VERIFIED | base.py: ABC with 12 @abstractmethod decorators; instantiation raises TypeError |
| 4 | A subclass missing any abstract method raises TypeError at instantiation | VERIFIED | ABC metaclass enforcement; all 3 adapters implement all 12 methods (confirmed by method grep) |
| 5 | Progress helper prints numbered steps in [N/TOTAL] format | VERIFIED | progress.py line 49: `f"[{self.current}/{self.total}] {description}..."` with `end=" ", flush=True` |
| 6 | validate_firewall_rules raises on rules not matching deny-by-default template | PARTIAL | Function and exception implemented correctly; BUT all three adapters pass identical strings for generated and template — validation is tautological and cannot catch real rule drift |
| 7 | LinuxAdapter implements all 12 abstract methods with systemd, nftables, sysctl.d, cron | VERIFIED | linux.py: 506 lines, all 12 methods present, policy drop + rate limit, masquerade, wg-quick@wg0 systemd, adduser wg-automate, /etc/cron.d/wg-automate |
| 8 | MacOSAdapter implements all 12 abstract methods with pfctl, launchd, SUDO_USER handling | VERIFIED | macos.py: 577 lines, all 12 methods, com.apple/wireguard anchor, plistlib, sysctl -w + launchd persistence, dscl user, UserName key |
| 9 | WindowsAdapter implements all 12 abstract methods with netsh, winreg, /installtunnelservice | VERIFIED | windows.py: 587 lines, all 12 methods, IsUserAnAdmin, IPEnableRouter via winreg, wireguard.exe /installtunnelservice, schtasks, icacls (no os.chmod) |
| 10 | NAT masquerade targets only detected outbound interface, not globally | VERIFIED | Linux: iifname+oifname masquerade; macOS: nat on {outbound} from {subnet}; Windows: New-NetNat on VPN subnet |

**Score:** 9/10 truths verified (1 partial)

### Required Artifacts

| Artifact | Provides | Lines | Status | Details |
|----------|----------|-------|--------|---------|
| `src/wg_automate/platform/__init__.py` | Package init with public API | 36 | VERIFIED | Exports get_adapter, get_platform_info, AbstractPlatformAdapter, Progress, all 6 exception classes |
| `src/wg_automate/platform/base.py` | AbstractPlatformAdapter ABC with 12 abstract methods | 257 | VERIFIED | All 12 @abstractmethod present; concrete validate_firewall_rules delegates to module-level function |
| `src/wg_automate/platform/detect.py` | get_adapter() factory + get_platform_info() | 64 | VERIFIED | Lazy imports per platform branch; UnsupportedPlatformError on unknown OS |
| `src/wg_automate/platform/exceptions.py` | Exception hierarchy (5 subclasses) | 58 | VERIFIED | PlatformError, PrivilegeError, UnsupportedPlatformError, PrerequisiteError, FirewallValidationError, SetupError |
| `src/wg_automate/platform/progress.py` | Progress step reporter | 75 | VERIFIED | [N/TOTAL] Description... done/FAILED format with recovery hint |
| `src/wg_automate/platform/linux.py` | LinuxAdapter (min 200 lines) | 506 | VERIFIED | All 12 methods; nftables deny-by-default; sysctl.d; systemd; cron |
| `src/wg_automate/platform/macos.py` | MacOSAdapter (min 200 lines) | 577 | VERIFIED | All 12 methods; pfctl anchor; launchd; runtime sysctl; dscl user |
| `src/wg_automate/platform/windows.py` | WindowsAdapter (min 250 lines) | 587 | VERIFIED | All 12 methods; netsh; winreg; /installtunnelservice; schtasks; icacls |

All artifacts exist, are substantive (well above minimum line counts), and are wired.

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `platform/__init__.py` | `platform/detect.py` | `from .detect import get_adapter, get_platform_info` | WIRED | Line 12 |
| `platform/__init__.py` | `platform/base.py` | `from .base import AbstractPlatformAdapter` | WIRED | Line 13 |
| `platform/detect.py` | `platform/base.py` | `from .base import AbstractPlatformAdapter` | WIRED | Line 16 |
| `platform/linux.py` | `platform/base.py` | `class LinuxAdapter(AbstractPlatformAdapter)` | WIRED | Line 85 |
| `platform/linux.py` | `security/atomic.py` | `from ..security.atomic import atomic_write` | WIRED | Line 28 |
| `platform/linux.py` | `security/permissions.py` | NOT WIRED — decision documented | INFO | deploy_config intentionally skips set_file_permissions; atomic_write sets mode=0o600 atomically |
| `platform/macos.py` | `platform/base.py` | `class MacOSAdapter(AbstractPlatformAdapter)` | WIRED | Line 34 |
| `platform/macos.py` | `security/atomic.py` | `from ..security.atomic import atomic_write` | WIRED | Line 31 |
| `platform/windows.py` | `platform/base.py` | `class WindowsAdapter(AbstractPlatformAdapter)` | WIRED | Line 50 |
| `platform/windows.py` | `security/permissions.py` | `from ..security.permissions import set_file_permissions` | WIRED | Line 33 |
| `platform/windows.py` | `security/atomic.py` | `from ..security.atomic import atomic_write` | WIRED | Line 32 |

**Note on linux.py + security/permissions.py:** The plan specified this as a key link, but the SUMMARY documents a deliberate decision: `atomic_write` sets `mode=0o600` before the rename, making the file never world-readable at any instant. A second `set_file_permissions` call was deemed redundant. This is a documented architectural decision, not an oversight.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| PLAT-01 | 02-01 | OS detected at startup; refuses to run if not root, unsupported OS, or missing tools | SATISFIED | get_adapter() raises UnsupportedPlatformError; check_privileges() raises PrivilegeError; check_prerequisites() raises PrerequisiteError |
| PLAT-02 | 02-01 | AbstractPlatformAdapter ABC; missing method implementations cause instantiation failure | SATISFIED | base.py: 12 @abstractmethod; all three adapters implement all 12 methods; TypeError raised if any missing |
| PLAT-03 | 02-02 | Linux: WireGuard install, atomic write + 600 perms, sysctl.d, nftables, systemd, DuckDNS cron as wg-automate | SATISFIED | linux.py 506 lines; all items implemented; cron user wg-automate confirmed |
| PLAT-04 | 02-03 | macOS: WireGuard via Homebrew, 600 perms, sysctl, pfctl, launchd, DuckDNS launchd | SATISFIED | macos.py 577 lines; pfctl anchor; launchd plist; runtime sysctl + boot plist; dscl user |
| PLAT-05 | 02-04 | Windows: WireGuard via winget, %ProgramData% config with SYSTEM+Admins ACL, IPEnableRouter, netsh, /installtunnelservice, Task Scheduler | SATISFIED | windows.py 587 lines; all items implemented; icacls via set_file_permissions; winreg; schtasks |
| PLAT-06 | 02-01 | File permissions: os.chmod(600) on Unix; icacls on Windows (never os.chmod on Windows) | SATISFIED | linux/macos: atomic_write mode=0o600; windows: set_file_permissions (icacls); confirmed os.chmod absent from windows.py executable code |
| FW-01 | 02-02 | Deny-by-default on WG interface; rate-limited new UDP connections only | SATISFIED | Linux: policy drop + limit rate 5/second burst 10; macOS: block drop in + max-pkt-rate 5/1 overload; Windows: netsh block rule on WG interface |
| FW-02 | 02-02 | NAT masquerade only on detected outbound interface | SATISFIED | Linux: iifname+oifname masquerade; macOS: nat on {outbound}; Windows: New-NetNat on VPN subnet |
| FW-03 | 02-01 | Generated rules validated against deny-by-default template before application | PARTIAL | validate_firewall_rules function implemented and called in all 3 adapters. However, generated == template in all cases (tautological). The guard exists and runs, but cannot catch real drift. |
| HARD-04 | 02-01 | Privilege dropped after setup; DuckDNS runs as non-root/non-SYSTEM user | SATISFIED | Linux: adduser --system wg-automate + cron.d; macOS: dscl wg-automate user + launchd UserName key; Windows: net user wg-automate-dns + schtasks /ru |

**Requirement coverage: 9 SATISFIED, 1 PARTIAL (FW-03), 0 MISSING, 0 ORPHANED**

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `linux.py` line 235 | `template_rules = _build_nftables_ruleset(pub_iface, wg_interface, wg_port)` — same call as generated | WARNING | FW-03 validation is tautological; will always pass regardless of rule content |
| `macos.py` lines 255-262 | `rules` and `template` are identical f-string literals | WARNING | FW-03 validation is tautological |
| `windows.py` lines 253-260 | `generated` and `template` are identical string literals | WARNING | FW-03 validation is tautological |
| `linux.py` line 152 | `return []` at end of check_prerequisites | INFO | Correct — returns empty list when all tools present; not a stub |
| `macos.py` line 326 | `pass` in except OSError block | INFO | Correct — suppresses error on token file cleanup; not a stub |
| `windows.py` line 548 | `pass` in except Exception block | INFO | Correct — best-effort password memory wipe; not a stub |

**Blocker anti-patterns: 0**
**Warning anti-patterns: 3 (all related to FW-03 tautology)**

### Human Verification Required

#### 1. Linux end-to-end platform setup

**Test:** On a fresh Ubuntu 22.04+ VM with root, run `sudo wg-automate init --port 51820 --subnet 10.0.0.0/24`.
**Expected:** Progress prints 6 steps all completing with "done". `nft list ruleset` shows `wg_filter` with `policy drop` on input and forward, rate limit `5/second burst 10`, and `masquerade` on the outbound interface. `systemctl is-enabled wg-quick@wg0` returns `enabled`. `/etc/cron.d/wg-automate` exists and is owned root, runs as user `wg-automate`.
**Why human:** Requires real Linux kernel with nftables module, WireGuard kernel module, and systemd.

#### 2. macOS end-to-end platform setup

**Test:** On macOS 14+ (Sonoma or Sequoia) with Homebrew and wireguard-tools installed, run `sudo wg-automate init`.
**Expected:** `pfctl -a com.apple/wireguard -sr` shows `block drop` and `pass in quick ... max-pkt-rate 5/1`. `/Library/LaunchDaemons/com.wg-automate.wg0.plist` loads successfully. `sysctl net.inet.ip.forwarding` returns 1. `launchctl list | grep wg-automate.dns` shows the DNS task.
**Why human:** Requires real macOS hardware; pfctl anchor behavior and launchd loading require the actual OS.

#### 3. Windows end-to-end platform setup

**Test:** On Windows 10/11 with Administrator shell, with WireGuard installed, run `wg-automate init`.
**Expected:** `netsh advfirewall firewall show rule name=wg-automate-wg0-in` shows the UDP allow rule. `sc query WireGuardTunnel$wg0` shows SERVICE_RUNNING. `reg query HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v IPEnableRouter` shows `0x1`. `schtasks /query /tn WgAutomateDNS` shows the scheduled task.
**Why human:** Requires real Windows system with kernel-level WireGuard service and registry write permissions.

### Gaps Summary

One gap was identified: **FW-03 firewall rule validation is tautological across all three platform adapters.**

The `validate_firewall_rules` function in `base.py` is correctly implemented — it normalizes both input strings and raises `FirewallValidationError` on mismatch. However, the gap is in how the three adapters invoke it:

- **Linux** (`linux.py:234-235`): `generated_rules = _build_nftables_ruleset(pub_iface, wg_interface, wg_port)` then `template_rules = _build_nftables_ruleset(pub_iface, wg_interface, wg_port)` — two calls to the same function with the same args always produce the same string.
- **macOS** (`macos.py:244-262`): `rules` and `template` are f-strings constructed identically from the same local variables in the same scope.
- **Windows** (`windows.py:245-260`): `template` and `generated` are string literals with identical content.

The SUMMARY for linux.py explicitly notes: "generated and template strings are built from the same `_build_nftables_ruleset()` function, making the comparison symmetric and always meaningful." However, "always meaningful" is not the same as "can catch drift" — the comparison will always succeed regardless of what `_build_nftables_ruleset` returns.

**Impact on the phase goal:** The platform hardening is functionally complete. The firewall rules applied are substantively correct (deny-by-default, rate-limited, outbound-only NAT). The FW-03 gap means a future code change that accidentally removes `policy drop` from the template string would not be caught by `validate_firewall_rules`. This is a correctness-in-future-maintenance concern, not a runtime security hole.

**All other phase 2 goals are fully achieved.** All three platform adapters implement the complete 12-method ABC, privilege checks work correctly, file permissions use platform-appropriate mechanisms, and DuckDNS runs as non-privileged users on all platforms.

---

## Commit Verification

All documented commits verified in git log:

| Commit | Content |
|--------|---------|
| `3a1136a` | feat(02-01): platform exceptions, progress reporter, and package init |
| `6900733` | feat(02-01): AbstractPlatformAdapter ABC and platform detection factory |
| `4ac6bbd` | feat(02-02): LinuxAdapter privilege checks, prerequisites, and WireGuard install |
| `32d5666` | feat(02-03): MacOSAdapter privilege checks, prerequisites, Homebrew detection, and config paths |
| `7b21492` | feat(02-04): WindowsAdapter privilege, prereqs, install, config, and outbound interface |

---

_Verified: 2026-03-18T16:00:00Z_
_Verifier: Claude (gsd-verifier)_
