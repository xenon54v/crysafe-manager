from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.abstract import EncryptionService

class KeyManagerProtocol(Protocol):
    def get_active_key(self) -> bytes:
        ...

class VaultEncryptionError(Exception):
    """Ошибка шифрования или расшифровки данных хранилища."""

class AESGCMEncryptionService(EncryptionService):
    # Формат хранения: nonce + ciphertext
    # nonce: 12 байт, уникальный для каждой операции шифрования.
    # ciphertext:
        # зашифрованные данные вместе с authentication tag.
        # в AES-GCM тег аутентификации автоматически добавляется
        # к результату метода encrypt().

    NONCE_SIZE = 12
    KEY_SIZE = 32
    PAYLOAD_VERSION = 1

    def encrypt(
            self,
            data: bytes,
            key_manager: KeyManagerProtocol,
            associated_data: bytes | None = None,
    ) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError("Data for encryption must be bytes.")

        key = self._get_valid_key(key_manager)

        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(key)

        ciphertext = aesgcm.encrypt(
            nonce,
            data,
            associated_data,
        )

        return nonce + ciphertext

    def decrypt(
            self,
            encrypted_data: bytes,
            key_manager: KeyManagerProtocol,
            associated_data: bytes | None = None,
    ) -> bytes:
        if not isinstance(encrypted_data, bytes):
            raise TypeError("Encrypted data must be bytes.")

        if len(encrypted_data) <= self.NONCE_SIZE:
            raise VaultEncryptionError("Encrypted data is too short.")

        key = self._get_valid_key(key_manager)

        nonce = encrypted_data[:self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE:]

        aesgcm = AESGCM(key)

        try:
            return aesgcm.decrypt(
                nonce,
                ciphertext,
                associated_data,
            )
        except InvalidTag as exc:
            raise VaultEncryptionError(
                "Encrypted data authentication failed."
            ) from exc

    def encrypt_entry(
            self,
            entry_data: dict[str, Any],
            key_manager: KeyManagerProtocol,
            associated_data: bytes | None = None,
    ) -> bytes:
        payload = self._build_payload(entry_data)

        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        payload_bytes = payload_json.encode("utf-8")

        return self.encrypt(
            payload_bytes,
            key_manager,
            associated_data=associated_data,
        )

    def decrypt_entry(
            self,
            encrypted_data: bytes,
            key_manager: KeyManagerProtocol,
            associated_data: bytes | None = None,
    ) -> dict[str, Any]:
        payload_bytes = self.decrypt(
            encrypted_data,
            key_manager,
            associated_data=associated_data,
        )

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultEncryptionError(
                "Encrypted payload has invalid JSON format."
            ) from exc

        self._validate_payload(payload)

        return payload

    def _build_payload(self, entry_data: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()

        return {
            "version": self.PAYLOAD_VERSION,
            "created_at": entry_data.get("created_at", now),
            "title": entry_data.get("title", ""),
            "username": entry_data.get("username", ""),
            "password": entry_data.get("password", ""),
            "url": entry_data.get("url", ""),
            "notes": entry_data.get("notes", ""),
            "category": entry_data.get("category", ""),
            "tags": entry_data.get("tags", []),
        }

    def _validate_payload(self, payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise VaultEncryptionError("Encrypted payload must be a dictionary.")

        required_fields = {
            "version",
            "created_at",
            "title",
            "username",
            "password",
            "url",
            "notes",
        }

        missing_fields = required_fields - set(payload.keys())

        if missing_fields:
            raise VaultEncryptionError(
                "Encrypted payload has missing required fields."
            )

    def _get_valid_key(self, key_manager: KeyManagerProtocol) -> bytes:
        key = key_manager.get_active_key()
        self._validate_key(key)
        return key

    def _validate_key(self, key: bytes) -> None:
        if not isinstance(key, bytes):
            raise VaultEncryptionError("Encryption key must be bytes.")

        if len(key) != self.KEY_SIZE:
            raise VaultEncryptionError(
                "AES-256-GCM requires a 32-byte encryption key."
            )