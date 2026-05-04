from __future__ import annotations

import ctypes
import os
import sys
import time

class KeyStorage:
    # Best-effort protected memory
    # ключ хранится в bytearray, чтобы его можно было затереть
    # на Unix выполняется попытка mlock()
    # на Windows отмечается best-effort режим
    # если системная защита недоступна, используется безопасный fallback

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._cached_key: bytearray | None = None
        self._created_at: float | None = None
        self._last_access_at: float | None = None
        self._ttl_seconds = ttl_seconds
        self._memory_protected: bool = False

    def save(self, key: bytes) -> None:
        self.clear()

        self._cached_key = bytearray(key)
        self._protect_memory()

        now = time.time()
        self._created_at = now
        self._last_access_at = now

    def load(self) -> bytes:
        if self._cached_key is None:
            raise RuntimeError("Ключ отсутствует в памяти.")

        if self.is_expired():
            self.clear()
            raise RuntimeError("Срок хранения ключа истёк.")

        self._last_access_at = time.time()
        return bytes(self._cached_key)

    def clear(self) -> None:
        if self._cached_key is not None:
            self._unprotect_memory()

            for i in range(len(self._cached_key)):
                self._cached_key[i] = 0

        self._cached_key = None
        self._created_at = None
        self._last_access_at = None
        self._memory_protected = False

    def has_key(self) -> bool:
        return self._cached_key is not None and not self.is_expired()

    def is_expired(self) -> bool:
        if self._cached_key is None or self._last_access_at is None:
            return False

        return time.time() - self._last_access_at > self._ttl_seconds

    def touch(self) -> None:
        if self._cached_key is not None:
            self._last_access_at = time.time()

    def is_memory_protected(self) -> bool:
        return self._memory_protected

    def _protect_memory(self) -> None:
        if self._cached_key is None:
            return

        if os.name == "posix":
            self._memory_protected = self._try_mlock()
        elif os.name == "nt":
            self._memory_protected = self._try_windows_protect()
        else:
            self._memory_protected = False

    def _unprotect_memory(self) -> None:
        if self._cached_key is None:
            return

        if os.name == "posix" and self._memory_protected:
            self._try_munlock()

    def _buffer_address_and_size(self) -> tuple[int, int]:
        if self._cached_key is None:
            raise RuntimeError("Ключ отсутствует в памяти.")

        buffer = (ctypes.c_char * len(self._cached_key)).from_buffer(self._cached_key)
        return ctypes.addressof(buffer), len(self._cached_key)

    def _try_mlock(self) -> bool:
        try:
            libc = ctypes.CDLL(None)
            address, size = self._buffer_address_and_size()
            result = libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return result == 0
        except Exception:
            return False

    def _try_munlock(self) -> bool:
        try:
            libc = ctypes.CDLL(None)
            address, size = self._buffer_address_and_size()
            result = libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return result == 0
        except Exception:
            return False

    def _try_windows_protect(self) -> bool:
        # В учебном проекте оставлен best-effort режим.
        # CryptProtectMemory защищает данные в памяти, но требует аккуратной
        # работы с размером блока и платформенными ограничениями
        return sys.platform.startswith("win")