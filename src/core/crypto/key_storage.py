from __future__ import annotations

import time


class KeyStorage:
    # безопасное временное хранение ключа в памяти
    # ключ хранится только как bytearray, чтобы его можно было затереть

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._cached_key: bytearray | None = None
        self._created_at: float | None = None
        self._last_access_at: float | None = None
        self._ttl_seconds = ttl_seconds

    def save(self, key: bytes) -> None:
        self.clear()

        self._cached_key = bytearray(key)
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
            for i in range(len(self._cached_key)):
                self._cached_key[i] = 0

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