from src.core.crypto.placeholder import AES256Placeholder


def test_encrypt_decrypt_roundtrip():
    service = AES256Placeholder()
    key = b"k" * 32
    data = b"secret_data"

    ciphertext = service.encrypt(data, key)
    plaintext = service.decrypt(ciphertext, key)

    assert plaintext == data
