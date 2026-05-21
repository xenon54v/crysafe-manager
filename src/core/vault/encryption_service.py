from __future__ import annotations

import os
from typing import Protocol

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