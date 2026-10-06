from __future__ import annotations

import ctypes
import time

from src.core.security.memory_guard import ProtectedSecret


class KeyStorage:
    """Keeps the active key in locked, guarded memory for a limited time."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        if ttl_seconds <= 0:
            raise ValueError("Key cache TTL must be positive.")
        self._cached_key: ProtectedSecret | None = None
        self._created_at: float | None = None
        self._last_access_at: float | None = None
        self._ttl_seconds = ttl_seconds

    def save(self, key: bytes) -> None:
        self.clear()
        self._cached_key = ProtectedSecret(
            key,
            lock_memory=True,
            guard_pages=True,
            wipe_passes=2,
        )
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
        raw = self._cached_key.read()
        try:
            return bytes(raw)
        finally:
            if raw:
                ctypes.memset((ctypes.c_char * len(raw)).from_buffer(raw), 0, len(raw))

    def clear(self) -> None:
        if self._cached_key is not None:
            self._cached_key.close()
        self._cached_key = None
        self._created_at = None
        self._last_access_at = None

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
        return bool(
            self._cached_key is not None and self._cached_key.status.memory_locked
        )

    @property
    def protection_status(self):
        return self._cached_key.status if self._cached_key is not None else None
