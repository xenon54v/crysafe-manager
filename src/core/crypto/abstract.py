from __future__ import annotations

from abc import ABC, abstractmethod


class EncryptionService(ABC):
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt plaintext bytes with key."""
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt ciphertext bytes with key."""
        raise NotImplementedError
