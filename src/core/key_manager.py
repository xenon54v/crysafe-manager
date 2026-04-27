from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

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
        self._active_key: Optional[bytes] = None
        self._active_salt: Optional[bytes] = None

    # -------- Password hashing / verification --------

    def create_auth_hash(self, password: str) -> AuthHashResult:
        return self._kdf.create_auth_hash(password)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        return self._kdf.verify_password(password, stored_hash)

    # -------- Encryption key derivation --------

    def generate_salt(self, length: int | None = None) -> bytes:
        if length is None:
            length = 16
        return self._kdf.generate_salt(length)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        return self._kdf.derive_encryption_key(password, salt)

    def derive_key_bundle(self, password: str) -> DerivedKey:
        salt = self.generate_salt()
        key = self.derive_key(password, salt)
        return DerivedKey(key=key, salt=salt)

    # -------- Active key flow for current app logic --------

    def unlock_with_password(self, db, password: str) -> bytes:
        row = db.execute(
            """
            SELECT salt
            FROM key_store
            WHERE key_type = ?
            LIMIT 1;
            """,
            ("master",)
        ).fetchone()

        if row is None:
            salt = self.generate_salt()
            auth_hash = self.create_auth_hash(password).hash

            db.execute(
                """
                INSERT INTO key_store (key_type, salt, hash, params)
                VALUES (?, ?, ?, ?);
                """,
                ("master", salt, auth_hash, "argon2+pbkdf2")
            )
        else:
            salt = row[0]

        self._active_salt = salt
        self._active_key = self.derive_key(password, salt)
        return self._active_key

    def get_active_key(self) -> bytes:
        if self._active_key is None:
            raise RuntimeError("Encryption key is not unlocked.")
        return self._active_key

    @property
    def active_key(self) -> bytes:
        return self.get_active_key()

    @property
    def active_salt(self) -> bytes:
        if self._active_salt is None:
            raise RuntimeError("Encryption salt is not initialized.")
        return self._active_salt

    def clear_active_key(self) -> None:
        self._active_key = None
        self._active_salt = None

    # -------- Storage hooks (Sprint 2 implementation point) --------

    def store_key(self) -> None:
        raise NotImplementedError(
            "store_key will be implemented as part of Sprint 2 key storage flow"
        )

    def load_key(self) -> None:
        raise NotImplementedError(
            "load_key will be implemented as part of Sprint 2 key storage flow"
        )