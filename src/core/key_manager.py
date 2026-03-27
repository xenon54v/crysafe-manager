from __future__ import annotations

from dataclasses import dataclass

from src.core.crypto.key_derivation import (
    AuthHashResult,
    KeyDerivationService,
)


@dataclass(frozen=True)
class DerivedKey:
    key: bytes
    salt: bytes


class KeyManager:
    def __init__(self) -> None:
        self._kdf = KeyDerivationService()

    # -------- Password hashing / verification --------

    def create_auth_hash(self, password: str) -> AuthHashResult:
        return self._kdf.create_auth_hash(password)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        return self._kdf.verify_password(password, stored_hash)

    # -------- Encryption key derivation --------

    def generate_salt(self, length: int | None = None) -> bytes:
        return self._kdf.generate_salt(length)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        return self._kdf.derive_encryption_key(password, salt)

    def derive_key_bundle(self, password: str) -> DerivedKey:
        salt = self.generate_salt()
        key = self.derive_key(password, salt)
        return DerivedKey(key=key, salt=salt)

    # -------- Storage hooks (Sprint 2 implementation point) --------

    def store_key(self) -> None:
        raise NotImplementedError("store_key will be implemented as part of Sprint 2 key storage flow")

    def load_key(self) -> None:
        raise NotImplementedError("load_key will be implemented as part of Sprint 2 key storage flow")