from __future__ import annotations

import secrets
from typing import Optional

from .abstract import EncryptionService


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Key must not be empty")
    # repeat key over data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def zero_bytes(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


class AES256Placeholder(EncryptionService):
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        # In a real scheme we'd use nonce+AEAD. Here we add a random nonce as a stub.
        nonce = secrets.token_bytes(16)
        body = _xor_bytes(data, key)
        return nonce + body

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext too short")
        # nonce is ignored for XOR placeholder, but kept for future compatibility
        _nonce = ciphertext[:16]
        body = ciphertext[16:]
        return _xor_bytes(body, key)
