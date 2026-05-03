from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Optional

from src.core.crypto.key_derivation import (
    Argon2Settings,
    AuthHashResult,
    KeyDerivationService,
    PBKDF2Settings,
)

from src.core.crypto.key_storage import KeyStorage

@dataclass(frozen=True)
class DerivedKey:
    key: bytes
    salt: bytes

class KeyManager:
    def __init__(
            self,
            argon2_settings: Argon2Settings | None = None,
            pbkdf2_settings: PBKDF2Settings | None = None,
            key_cache_ttl_seconds: int = 3600,
    ) -> None:
        self._kdf = KeyDerivationService(argon2_settings, pbkdf2_settings)
        self._storage = KeyStorage(ttl_seconds=key_cache_ttl_seconds)
        self._active_key: Optional[bytes] = None
        self._active_salt: Optional[bytes] = None

    def _build_key_params(self) -> str:
        return json.dumps(
            {
                "version": 1,
                "auth": {
                    "algorithm": "argon2id",
                    "time_cost": self._kdf.argon2_settings.time_cost,
                    "memory_cost": self._kdf.argon2_settings.memory_cost,
                    "parallelism": self._kdf.argon2_settings.parallelism,
                    "hash_len": self._kdf.argon2_settings.hash_len,
                },
                "encryption": {
                    "algorithm": "pbkdf2_hmac_sha256",
                    "iterations": self._kdf.pbkdf2_settings.iterations,
                    "salt_len": self._kdf.pbkdf2_settings.salt_len,
                    "key_len": self._kdf.pbkdf2_settings.key_len,
                },
            },
            ensure_ascii=False,
        )

    # Password hashing / verification

    def create_auth_hash(self, password: str) -> AuthHashResult:
        return self._kdf.create_auth_hash(password)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        return self._kdf.verify_password(password, stored_hash)

    # Encryption key derivation

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

    # Active key flow for current app logic

    def unlock_with_password(self, db, password: str) -> bytes:
        row = db.execute(
            """
            SELECT salt, hash, params
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
                ("master", salt, auth_hash, self._build_key_params())
            )
        else:
            salt = row[0]
            stored_hash = row[1]
            params = row[2]

            if not params:
                params = self._build_key_params()

                db.execute(
                    """
                    UPDATE key_store
                    SET params = ?
                    WHERE key_type = ?;
                    """,
                    (params, "master")
                )
            try:
                parsed = json.loads(params)
            except Exception:
                raise ValueError("Повреждены параметры ключа")

            if not self.verify_password(password, stored_hash):
                raise ValueError("Неверный мастер-пароль")

        self._active_salt = salt
        self._active_key = self.derive_key(password, salt)
        self._storage.save(self._active_key)
        return self._active_key

    def get_active_key(self) -> bytes:
        return self._storage.load()

    @property
    def active_key(self) -> bytes:
        return self.get_active_key()

    @property
    def active_salt(self) -> bytes:
        if self._active_salt is None:
            raise RuntimeError("Encryption salt is not initialized.")
        return self._active_salt

    def clear_active_key(self) -> None:
        self._storage.clear()
        self._active_key = None
        self._active_salt = None

    def store_key(self) -> None:
        if self._active_key is None:
            raise RuntimeError("Нет активного ключа для сохранения в памяти.")

        self._storage.save(self._active_key)

    def load_key(self) -> bytes:
        return self._storage.load()