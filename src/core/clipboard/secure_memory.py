from __future__ import annotations

import ctypes
import os
import sys
from typing import Self


class SecureBuffer:
    """Keeps data XOR-obfuscated and clears the backing arrays explicitly."""

    def __init__(self, value: str | bytes) -> None:
        raw = bytearray(value.encode("utf-8") if isinstance(value, str) else value)
        if not raw:
            raise ValueError("Secure buffer value must not be empty.")

        self._mask = bytearray(os.urandom(len(raw)))
        self._data = bytearray(left ^ right for left, right in zip(raw, self._mask))
        self._data_locked = self._lock_memory(self._data)
        self._mask_locked = self._lock_memory(self._mask)
        self._zero(raw)

    @property
    def size(self) -> int:
        return len(self._data)

    @property
    def cleared(self) -> bool:
        return not self._data

    def reveal_bytes(self) -> bytearray:
        if self.cleared:
            raise RuntimeError("Secure buffer has already been cleared.")
        return bytearray(left ^ right for left, right in zip(self._data, self._mask))

    def reveal_text(self) -> str:
        raw = self.reveal_bytes()
        try:
            return raw.decode("utf-8")
        finally:
            self._zero(raw)

    def contains_plaintext(self, value: str | bytes) -> bool:
        needle = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        return needle in bytes(self._data) or needle in bytes(self._mask)

    def clear(self) -> None:
        if self.cleared:
            return
        self._zero(self._data)
        self._zero(self._mask)
        self._unlock_memory(self._data, self._data_locked)
        self._unlock_memory(self._mask, self._mask_locked)
        self._data.clear()
        self._mask.clear()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args) -> None:
        self.clear()

    def __del__(self) -> None:
        try:
            self.clear()
        except Exception:  # noqa: BLE001 - destructors must not raise during shutdown
            return

    @staticmethod
    def _zero(buffer: bytearray) -> None:
        if buffer:
            ctypes.memset(
                (ctypes.c_char * len(buffer)).from_buffer(buffer), 0, len(buffer)
            )

    @staticmethod
    def _lock_memory(buffer: bytearray) -> bool:
        if not buffer:
            return False
        try:
            address = ctypes.addressof(
                (ctypes.c_char * len(buffer)).from_buffer(buffer)
            )
            if sys.platform == "win32":
                return bool(
                    ctypes.windll.kernel32.VirtualLock(
                        ctypes.c_void_p(address), ctypes.c_size_t(len(buffer))
                    )
                )
            libc = ctypes.CDLL(None, use_errno=True)
            return (
                libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(len(buffer))) == 0
            )
        except (AttributeError, OSError, TypeError):
            return False

    @staticmethod
    def _unlock_memory(buffer: bytearray, locked: bool) -> None:
        if not locked or not buffer:
            return
        try:
            address = ctypes.addressof(
                (ctypes.c_char * len(buffer)).from_buffer(buffer)
            )
            if sys.platform == "win32":
                ctypes.windll.kernel32.VirtualUnlock(
                    ctypes.c_void_p(address), ctypes.c_size_t(len(buffer))
                )
            else:
                libc = ctypes.CDLL(None, use_errno=True)
                libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(len(buffer)))
        except (AttributeError, OSError, TypeError):
            pass
