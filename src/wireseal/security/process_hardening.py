"""Process-level hardening to reduce attack surface.

Applies best-effort protections against:
  - Memory forensics (core dump exclusion, MADV_DONTDUMP)
  - Debugger attachment (PR_SET_DUMPABLE=0 on Linux)
  - Process memory inspection (/proc/pid/mem)

All functions are best-effort and silently ignore failures on
unsupported platforms or insufficient privileges.
"""

import ctypes
import sys


def harden_process() -> dict[str, bool]:
    """Apply all available process-level hardening.

    Returns a dict of {protection_name: success_bool}.
    """
    results: dict[str, bool] = {}

    results["disable_core_dump"] = _disable_core_dump()
    results["disable_ptrace"] = _disable_ptrace()
    results["set_dumpable_zero"] = _set_dumpable_zero()

    return results


def _disable_core_dump() -> bool:
    """Set RLIMIT_CORE to 0 to prevent core dumps containing secrets."""
    try:
        if sys.platform == "win32":
            # Windows: disable WER crash dumps via SetErrorMode
            SEM_NOGPFAULTERRORBOX = 0x0002
            SEM_FAILCRITICALERRORS = 0x0001
            ctypes.windll.kernel32.SetErrorMode(
                SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS
            )
            return True

        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except Exception:
        return False


def _set_dumpable_zero() -> bool:
    """Set PR_SET_DUMPABLE=0 on Linux to prevent /proc/pid/mem reads by non-root.

    This also prevents ptrace attach from processes with the same UID,
    blocks core dumps, and hides /proc/pid/environ.
    """
    if sys.platform != "linux":
        return False
    try:
        PR_SET_DUMPABLE = 4
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        result = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        return result == 0
    except Exception:
        return False


def _disable_ptrace() -> bool:
    """Restrict ptrace to only direct parent process (Linux YAMA scope).

    On macOS, uses PT_DENY_ATTACH to prevent debugger attachment.
    """
    try:
        if sys.platform == "linux":
            # Use PR_SET_PTRACER with PR_SET_PTRACER_ANY=0 (deny all)
            # This works alongside YAMA LSM ptrace_scope
            PR_SET_PTRACER = 0x59616d61  # YAMA
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            # Setting ptracer to 0 means no process can ptrace us
            libc.prctl(PR_SET_PTRACER, 0, 0, 0, 0)
            return True
        elif sys.platform == "darwin":
            PT_DENY_ATTACH = 31
            libc = ctypes.CDLL("libSystem.B.dylib", use_errno=True)
            libc.ptrace(PT_DENY_ATTACH, 0, 0, 0)
            return True
        return False
    except Exception:
        return False


def mark_buffer_nodump(data: bytearray) -> bool:
    """Mark a buffer's memory pages with MADV_DONTDUMP (Linux only).

    This excludes the pages from core dumps even if core dumps are
    somehow re-enabled after our RLIMIT_CORE=0 setting.
    """
    if sys.platform != "linux" or not data:
        return False
    try:
        MADV_DONTDUMP = 16
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        addr = ctypes.addressof(ctypes.c_char.from_buffer(data))
        length = len(data)
        # Align to page boundary
        import os
        page_size = os.sysconf("SC_PAGE_SIZE")
        aligned_addr = addr & ~(page_size - 1)
        aligned_length = length + (addr - aligned_addr)
        result = libc.madvise(
            ctypes.c_void_p(aligned_addr),
            ctypes.c_size_t(aligned_length),
            ctypes.c_int(MADV_DONTDUMP),
        )
        return result == 0
    except Exception:
        return False
