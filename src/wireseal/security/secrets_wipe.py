"""Memory wiping functions for sensitive data.

Provides zero-random-zero overwrite for bytearrays and best-effort
CPython internal buffer zeroing for strings.
"""

import ctypes
import os


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


def wipe_string(s: str) -> None:
    """Best-effort wipe of a Python string's internal buffer via ctypes.

    # Best-effort: CPython implementation detail, not guaranteed.
    Strings are immutable; this attempts to zero the underlying
    CPython compact-ASCII buffer. Silently fails on non-CPython
    interpreters or future Python versions that change the internal layout.
    """
    try:
        import sys
        # The header size is sys.getsizeof(s) - len(s) for compact ASCII strings.
        # For a pure-ASCII string of length n, CPython stores the characters
        # immediately after the PyUnicodeObject header.
        length = len(s)
        if length == 0:
            return
        header_size = sys.getsizeof(s) - length
        ctypes.memset(id(s) + header_size, 0, length)
    except Exception:
        # Best-effort: silently ignore failures
        pass
