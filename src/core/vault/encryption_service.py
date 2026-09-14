from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.abstract import EncryptionService


class KeyManagerProtocol(Protocol):
    def get_active_key(self) -> bytes: ...


class VaultEncryptionError(Exception):
    """Raised when vault data cannot be encrypted or authenticated."""


class AESGCMEncryptionService(EncryptionService):
    """Encrypts independent vault payloads with AES-256-GCM.

    The returned binary format is a 12-byte nonce followed by the ciphertext
    and the 16-byte GCM authentication tag produced by ``AESGCM.encrypt``.
    """

    NONCE_SIZE = 12
    TAG_SIZE = 16
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
        ciphertext_and_tag = AESGCM(key).encrypt(nonce, data, associated_data)
        return nonce + ciphertext_and_tag

    def decrypt(
        self,
        encrypted_data: bytes,
        key_manager: KeyManagerProtocol,
        associated_data: bytes | None = None,
    ) -> bytes:
        if not isinstance(encrypted_data, bytes):
            raise TypeError("Encrypted data must be bytes.")

        minimum_size = self.NONCE_SIZE + self.TAG_SIZE
        if len(encrypted_data) < minimum_size:
            raise VaultEncryptionError("Encrypted data is invalid.")

        key = self._get_valid_key(key_manager)
        nonce = encrypted_data[: self.NONCE_SIZE]
        ciphertext_and_tag = encrypted_data[self.NONCE_SIZE :]

        try:
            return AESGCM(key).decrypt(nonce, ciphertext_and_tag, associated_data)
        except (InvalidTag, ValueError) as exc:
            raise VaultEncryptionError("Encrypted data authentication failed.") from exc

    def encrypt_entry(
        self,
        entry_data: dict[str, Any],
        key_manager: KeyManagerProtocol,
        associated_data: bytes | None = None,
    ) -> bytes:
        payload = self._build_payload(entry_data)

        try:
            payload_bytes = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise VaultEncryptionError("Entry data cannot be serialized.") from exc

        return self.encrypt(payload_bytes, key_manager, associated_data)

    def decrypt_entry(
        self,
        encrypted_data: bytes,
        key_manager: KeyManagerProtocol,
        associated_data: bytes | None = None,
    ) -> dict[str, Any]:
        payload_bytes = self.decrypt(encrypted_data, key_manager, associated_data)

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultEncryptionError("Encrypted payload is invalid.") from exc

        self._validate_payload(payload)
        return payload

    def _build_payload(self, entry_data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(entry_data, dict):
            raise TypeError("Entry data must be a dictionary.")

        now = datetime.now(timezone.utc).isoformat()
        tags = entry_data.get("tags", [])
        if isinstance(tags, str):
            tags = [part.strip() for part in tags.split(",") if part.strip()]

        sharing_metadata = entry_data.get("sharing_metadata", {})
        if sharing_metadata is None:
            sharing_metadata = {}

        return {
            "version": int(entry_data.get("version", self.PAYLOAD_VERSION)),
            "created_at": str(entry_data.get("created_at", now)),
            "title": str(entry_data.get("title", "")),
            "username": str(entry_data.get("username", "")),
            "password": str(entry_data.get("password", "")),
            "url": str(entry_data.get("url", "")),
            "notes": str(entry_data.get("notes", "")),
            "category": str(entry_data.get("category", "")),
            "tags": tags if isinstance(tags, list) else [],
            "totp_secret": str(entry_data.get("totp_secret", "")),
            "sharing_metadata": sharing_metadata,
        }

    def _validate_payload(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise VaultEncryptionError("Encrypted payload is invalid.")

        required_fields = {
            "version",
            "created_at",
            "title",
            "username",
            "password",
            "url",
            "notes",
            "category",
            "tags",
            "totp_secret",
            "sharing_metadata",
        }
        if required_fields.difference(payload):
            raise VaultEncryptionError("Encrypted payload is invalid.")
        if not isinstance(payload["version"], int) or payload["version"] < 1:
            raise VaultEncryptionError("Encrypted payload version is invalid.")
        if not isinstance(payload["tags"], list):
            raise VaultEncryptionError("Encrypted payload tags are invalid.")
        if not isinstance(payload["sharing_metadata"], dict):
            raise VaultEncryptionError("Encrypted payload sharing metadata is invalid.")

    def _get_valid_key(self, key_manager: KeyManagerProtocol) -> bytes:
        key = key_manager.get_active_key()
        if not isinstance(key, bytes) or len(key) != self.KEY_SIZE:
            raise VaultEncryptionError("A valid 32-byte encryption key is required.")
        return key
