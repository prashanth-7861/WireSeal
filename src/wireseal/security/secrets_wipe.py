"""Memory wiping functions for sensitive data.

Provides zero-random-zero overwrite for bytearrays and best-effort
CPython internal buffer zeroing for strings.
"""

import ctypes
import os
import sys


def wipe_bytes(data: bytearray) -> None:
    """Zero a bytearray using the zero-random-zero pattern.

    Performs three overwrite passes:
      1. All zeros
      2. Random bytes
      3. All zeros again

    This is a no-op if data has length 0.
    """
    length = len(data)
    if length == 0:
        return

    # Pass 1: zero
    for i in range(length):
        data[i] = 0

    # Pass 2: random
    random_bytes = os.urandom(length)
    for i in range(length):
        data[i] = random_bytes[i]

    # Pass 3: zero again
    for i in range(length):
        data[i] = 0


# SEC-011: strings that CPython has interned (all small ints, identifier-like
# short strings, and anything in the interpreter's intern table) are shared
# across the whole process. Zeroing their buffer corrupts unrelated parts of
# the runtime and can crash the interpreter. We also refuse to wipe any
# non-pure-ASCII string because CPython's "compact ASCII" layout — the only
# layout whose character buffer offset we can compute from (sys.getsizeof -
# len) — only applies to 1-byte-per-char ASCII. Non-ASCII strings use a
# different, multi-byte layout and memset'ing there would write past the
# header or short of the data, corrupting the heap.


def _is_pure_ascii(s: str) -> bool:
    """Return True iff every character in *s* is in the 0..127 range."""
    try:
        s.encode("ascii")
    except UnicodeEncodeError:
        return False
    return True


def _looks_interned(s: str) -> bool:
    """Heuristic: is *s* likely to be interned by CPython?

    CPython auto-interns identifier-shaped ASCII strings and most short
    literals. We treat short identifier-like strings as interned; real
    secrets are long and random, so callers passing such values indicate
    a bug and we refuse to wipe them rather than risk corrupting the
    interpreter (the memset would hit a shared buffer).

    We deliberately do NOT call ``sys.intern`` here — it always returns
    ``s`` itself for not-yet-interned strings, which would incorrectly
    flag them as interned and also pollute the intern dict. The length +
    shape heuristic is conservative but safe.
    """
    if len(s) == 0:
        return True
    # Short identifier-like strings: overwhelmingly likely to be interned.
    if len(s) <= 20 and all(c.isalnum() or c == "_" for c in s):
        return True
    # Refuse very short strings in general — below this length even random
    # content may collide with an interned literal somewhere in the runtime.
    if len(s) < 8:
        return True
    return False


def wipe_string(s: str) -> bool:
    """Best-effort wipe of a Python string's internal buffer via ctypes.

    SEC-011: returns ``True`` on success, ``False`` when the wipe was refused
    as unsafe (non-ASCII, interned, or empty). Previously this function
    silently succeeded in all cases — including on interned or multi-byte
    strings where the memset could corrupt the interpreter. The new behaviour
    lets callers log or assert on refusal in debug builds.

    Strings are immutable; this attempts to zero the underlying
    CPython compact-ASCII buffer. Refuses to touch:
      - empty strings
      - non-pure-ASCII strings (different internal layout)
      - interned strings (shared across the interpreter)
    """
    try:
        length = len(s)
        if length == 0:
            return False

        # Non-ASCII uses a different CPython layout — memset here would corrupt
        # the heap, not wipe the string. Refuse.
        if not _is_pure_ascii(s):
            return False

        # Refuse interned strings: writing to a shared buffer would take down
        # the interpreter or at least other subsystems holding the same str.
        if _looks_interned(s):
            return False

        # The header size is sys.getsizeof(s) - len(s) for compact ASCII strings.
        # For a pure-ASCII string of length n, CPython stores the characters
        # immediately after the PyUnicodeObject header.
        header_size = sys.getsizeof(s) - length
        if header_size <= 0:
            return False
        ctypes.memset(id(s) + header_size, 0, length)
        return True
    except Exception:
        # Best-effort: silently ignore failures
        return False
