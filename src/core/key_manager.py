from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.core.crypto.key_derivation import (
    Argon2Settings,
    AuthHashResult,
    KeyDerivationService,
    PBKDF2Settings,
)
from src.core.crypto.key_storage import KeyStorage
from src.core.os_keychain import OSKeychain


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
        self._os_keychain = OSKeychain()
        self._active_key: bytes | None = None
        self._active_salt: bytes | None = None

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

    def is_master_password_set(self, db) -> bool:
        row = db.execute(
            "SELECT 1 FROM key_store WHERE key_type = ? LIMIT 1;",
            ("master",),
        ).fetchone()
        return row is not None

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

    def derive_named_key(
        self,
        password: str,
        salt: bytes,
        purpose: str,
    ) -> bytes:
        if not purpose:
            raise ValueError("Key purpose must not be empty.")

        purpose_password = f"{purpose}:{password}"
        return self.derive_key(purpose_password, salt)

    def derive_subkey(self, purpose: str, length: int = 32) -> bytes:
        """Derive a domain-separated session key from the active master key."""
        if not purpose or not purpose.strip():
            raise ValueError("Key purpose must not be empty.")
        if not 16 <= length <= 64:
            raise ValueError("Derived key length must be between 16 and 64 bytes.")

        active_key = self.get_active_key()
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=self.active_salt,
            info=f"CryptoSafe Manager:{purpose}:v1".encode(),
        ).derive(active_key)

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
            ("master",),
        ).fetchone()

        if row is None:
            salt = self.generate_salt()
            auth_hash = self.create_auth_hash(password).hash

            db.execute(
                """
                INSERT INTO key_store (key_type, salt, hash, params)
                VALUES (?, ?, ?, ?);
                """,
                ("master", salt, auth_hash, self._build_key_params()),
            )
        else:
            salt = row[0]
            stored_hash = row[1]
            if isinstance(stored_hash, bytes):
                stored_hash = stored_hash.decode("utf-8")
            params = row[2]

            if not params:
                params = self._build_key_params()

                db.execute(
                    """
                    UPDATE key_store
                    SET params = ?
                    WHERE key_type = ?;
                    """,
                    (params, "master"),
                )
            try:
                json.loads(params)
            except (json.JSONDecodeError, TypeError) as exc:
                raise ValueError("Повреждены параметры ключа") from exc

            if not self.verify_password(password, stored_hash):
                raise ValueError("Неверный мастер-пароль")

        self.activate_key(self.derive_key(password, salt), salt)
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

    def activate_key(self, key: bytes, salt: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("Encryption key must contain 32 bytes.")
        if not isinstance(salt, bytes) or not salt:
            raise ValueError("Encryption salt must not be empty.")

        self._active_key = key
        self._active_salt = salt
        self._storage.save(key)

    def load_key(self) -> bytes:
        return self._storage.load()

    def save_keychain_secret(self, name: str, value: str) -> bool:
        return self._os_keychain.save_secret(name, value)

    def load_keychain_secret(self, name: str) -> str | None:
        return self._os_keychain.load_secret(name)

    def delete_keychain_secret(self, name: str) -> bool:
        return self._os_keychain.delete_secret(name)

    def is_keychain_available(self) -> bool:
        return self._os_keychain.is_available()

    def lock(self) -> None:
        self.clear_active_key()
