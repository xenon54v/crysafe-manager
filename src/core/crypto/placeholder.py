from __future__ import annotations

import secrets

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
    def encrypt(self, data: bytes, key_manager) -> bytes:
        key = key_manager.get_active_key()
        nonce = secrets.token_bytes(16)
        body = _xor_bytes(data, key)
        return nonce + body

    def decrypt(self, ciphertext: bytes, key_manager) -> bytes:
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext too short")

        key = key_manager.get_active_key()
        body = ciphertext[16:]
        return _xor_bytes(body, key)