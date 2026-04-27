from __future__ import annotations

class KeyStorage:
    # временное хранение ключа в памяти
    # не записывается на диск

    def __init__(self) -> None:
        self._cached_key: bytes | None = None

    def save(self, key: bytes) -> None:
        self._cached_key = key

    def load(self) -> bytes:
        if self._cached_key is None:
            raise RuntimeError("Ключ отсутствует в памяти.")
        return self._cached_key

    def clear(self) -> None:
        self._cached_key = None

    def has_key(self) -> bool:
        return self._cached_key is not None