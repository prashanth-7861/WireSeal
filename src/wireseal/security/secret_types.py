"""Secure secret container types.

SEC-05 Pattern: Always wipe in finally blocks:

    secret = SecretBytes(some_data)
    try:
        use(secret)
    finally:
        secret.wipe()

Or use the context manager (preferred):

    with SecretBytes(data) as secret:
        use(secret)

Exception suppression: raise NewError("msg") from None
"""

import ctypes
import hmac
import sys

from .secrets_wipe import wipe_bytes
from .process_hardening import mark_buffer_nodump


class SecretBytes:
    """Mutable secret container that prevents accidental exposure and wipes memory on release.

    Enforces the following security invariants:
      SEC-01: Never expose content via repr, str, eq timing, hash, or pickle.
      SEC-02: Attempts to lock memory pages via mlock/VirtualLock (best-effort).
      SEC-03: Wipes via zero-random-zero overwrite on release.
      SEC-04: Stores content in bytearray (mutable), never in immutable bytes/str.
      SEC-05: Supports context manager for automatic cleanup.
    """

    def __init__(self, data: bytearray | bytes) -> None:
        # SEC-04: never hold key material in an immutable type
        if isinstance(data, bytes):
            self._data: bytearray = bytearray(data)
        else:
            self._data = data
        self._wiped = False
        self._mlock()
        # SEC-06: Exclude secret buffer from core dumps (Linux MADV_DONTDUMP)
        mark_buffer_nodump(self._data)

    # ------------------------------------------------------------------
    # Memory locking (best-effort, SEC-02)
    # ------------------------------------------------------------------

    def _mlock(self) -> None:
        """Pin memory pages containing the secret buffer (best-effort)."""
        if not self._data:
            return
        try:
            addr = ctypes.addressof(ctypes.c_char.from_buffer(self._data))
            length = len(self._data)
            if sys.platform == "win32":
                ctypes.windll.kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
            elif sys.platform.startswith("darwin"):
                libc = ctypes.CDLL("libSystem.B.dylib", use_errno=True)
                libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
            else:
                # Linux and other POSIX
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
        except Exception:
            # Best-effort: never crash because mlock failed
            pass

    def _munlock(self) -> None:
        """Unpin memory pages after wiping (best-effort)."""
        if not self._data:
            return
        try:
            addr = ctypes.addressof(ctypes.c_char.from_buffer(self._data))
            length = len(self._data)
            if sys.platform == "win32":
                ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
            elif sys.platform.startswith("darwin"):
                libc = ctypes.CDLL("libSystem.B.dylib", use_errno=True)
                libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
            else:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Wipe (SEC-03)
    # ------------------------------------------------------------------

    def wipe(self) -> None:
        """Zero the secret buffer using zero-random-zero overwrite, then unlock pages."""
        if self._wiped:
            return
        wipe_bytes(self._data)
        self._munlock()
        self._wiped = True

    def __del__(self) -> None:
        """Safety net: wipe if not already done when object is garbage collected."""
        if not self._wiped:
            self.wipe()

    # ------------------------------------------------------------------
    # SEC-01: Never expose content
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return "SecretBytes(***)"

    def __str__(self) -> str:
        return "SecretBytes(***)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretBytes):
            return NotImplemented
        # Constant-time comparison to prevent timing side-channels (SEC-01)
        return hmac.compare_digest(self._data, other._data)

    def __hash__(self) -> int:
        raise TypeError("SecretBytes is not hashable")

    def __getstate__(self) -> None:
        raise TypeError("SecretBytes cannot be pickled")

    def __reduce__(self) -> None:
        raise TypeError("SecretBytes cannot be pickled")

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError("SecretBytes cannot be pickled")

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._data)

    def __bytes__(self) -> bytes:
        """Disallow implicit coercion to immutable ``bytes``.

        SEC-012: ``bytes(secret)`` used to copy the plaintext into an
        immutable ``bytes`` object that Python could then intern, cache, or
        leave on the heap indefinitely — defeating the whole point of the
        SecretBytes container. Callers that truly need the raw buffer (e.g.
        for a ``ctypes`` call) must request it explicitly via
        ``expose_secret()`` and take responsibility for the lifetime of the
        returned view.
        """
        raise TypeError(
            "SecretBytes cannot be coerced to bytes — use expose_secret() for "
            "a zero-copy view, or to_bytearray() for a wipe-capable copy."
        )

    # ------------------------------------------------------------------
    # Context manager (SEC-05)
    # ------------------------------------------------------------------

    def __enter__(self) -> "SecretBytes":
        return self

    def __exit__(self, *args: object) -> None:
        self.wipe()

    # ------------------------------------------------------------------
    # Raw access
    # ------------------------------------------------------------------

    def to_bytearray(self) -> bytearray:
        """Return a COPY of the internal buffer as a bytearray. Caller must wipe the copy."""
        return bytearray(self._data)

    def expose_secret(self) -> bytearray:
        """Return a direct reference to the internal bytearray.

        WARNING: This bypasses all protection. Use only when raw buffer access is
        truly required (e.g., passing to a ctypes call). The caller must NOT store
        or copy this reference.
        """
        return self._data

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_wiped(self) -> bool:
        """True once wipe() has been called."""
        return self._wiped
