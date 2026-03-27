from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class DerivedKey:
    key: bytes
    salt: bytes


class KeyManager:

    def derive_key(self, password: str, salt: bytes) -> bytes:
        if not isinstance(password, str) or password == "":
            raise ValueError("Password must be a non-empty string")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
            raise ValueError("Salt must be at least 8 bytes")

        data = password.encode("utf-8") + bytes(salt)
        return hashlib.sha256(data).digest()

    def store_key(self) -> None:
        raise NotImplementedError("store_key is implemented in Sprint 2")

    def load_key(self) -> None:
        raise NotImplementedError("load_key is implemented in Sprint 2")
