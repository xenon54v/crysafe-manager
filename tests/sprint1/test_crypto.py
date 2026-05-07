from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager

def test_encrypt_decrypt_roundtrip():
    service = AES256Placeholder()
    key_manager = KeyManager()

    key_manager._active_key = b"k" * 32
    key_manager._active_salt = b"s" * 16
    key_manager.store_key()

    data = b"secret_data"

    ciphertext = service.encrypt(data, key_manager)
    plaintext = service.decrypt(ciphertext, key_manager)

    assert plaintext == data

def test_encrypt_produces_different_ciphertexts_for_same_data():
    service = AES256Placeholder()
    key_manager = KeyManager()

    key_manager._active_key = b"k" * 32
    key_manager._active_salt = b"s" * 16
    key_manager.store_key()

    data = b"secret_data"

    ciphertext1 = service.encrypt(data, key_manager)
    ciphertext2 = service.encrypt(data, key_manager)

    assert ciphertext1 != ciphertext2

def test_ciphertext_does_not_contain_plaintext():
    service = AES256Placeholder()
    key_manager = KeyManager()

    key_manager._active_key = b"k" * 32
    key_manager._active_salt = b"s" * 16
    key_manager.store_key()

    data = b"secret_data"

    ciphertext = service.encrypt(data, key_manager)

    assert data not in ciphertext

