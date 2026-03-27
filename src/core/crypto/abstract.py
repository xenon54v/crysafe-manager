from __future__ import annotations

from abc import ABC, abstractmethod


class EncryptionService(ABC):
    @abstractmethod
    def encrypt(self, data: bytes, key_manager) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key_manager) -> bytes:
        raise NotImplementedError
