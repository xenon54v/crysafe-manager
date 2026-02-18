from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class DerivedKey:
    key: bytes
    salt: bytes


class KeyManager:
    """
    Sprint 1 stub.
    - derive_key: placeholder derivation
    - store_key/load_key: placeholders for Sprint 2 integration
    """

    def derive_key(self, password: str, salt: bytes) -> bytes:
        if not isinstance(password, str) or password == "":
            raise ValueError("Password must be a non-empty string")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
            raise ValueError("Salt must be at least 8 bytes")

        # Placeholder KDF: SHA-256(password || salt)
        # Sprint 2 will replace with PBKDF2/scrypt/argon2 params.
        data = password.encode("utf-8") + bytes(salt)
        return hashlib.sha256(data).digest()

    def store_key(self) -> None:
        # Placeholder: Sprint 2 will implement writing key metadata into key_store table
        raise NotImplementedError("store_key is implemented in Sprint 2")

    def load_key(self) -> None:
        # Placeholder: Sprint 2 will implement loading key metadata from key_store table
        raise NotImplementedError("load_key is implemented in Sprint 2")
