from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager


def test_encrypt_decrypt_roundtrip():
    service = AES256Placeholder()
    key_manager = KeyManager()

    key_manager._active_key = b"k" * 32

    data = b"secret_data"

    ciphertext = service.encrypt(data, key_manager)
    plaintext = service.decrypt(ciphertext, key_manager)

    assert plaintext == data