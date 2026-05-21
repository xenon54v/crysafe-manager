import pytest

from src.core.vault.encryption_service import (
    AESGCMEncryptionService,
    VaultEncryptionError,
)

class FakeKeyManager:
    def __init__(self, key: bytes | None = None):
        self.key = key or (b"A" * 32)

    def get_active_key(self) -> bytes:
        return self.key

def test_encrypt_decrypt_entry_success():
    service = AESGCMEncryptionService()
    key_manager = FakeKeyManager()

    entry_data = {
        "title": "GitHub",
        "username": "user@example.com",
        "password": "StrongPassword123!",
        "url": "https://github.com",
        "notes": "main account",
        "category": "Work",
        "tags": ["git", "main"],
    }

    encrypted = service.encrypt_entry(entry_data, key_manager)
    decrypted = service.decrypt_entry(encrypted, key_manager)

    assert isinstance(encrypted, bytes)
    assert decrypted["version"] == 1
    assert decrypted["title"] == entry_data["title"]
    assert decrypted["username"] == entry_data["username"]
    assert decrypted["password"] == entry_data["password"]
    assert decrypted["url"] == entry_data["url"]
    assert decrypted["notes"] == entry_data["notes"]
    assert decrypted["category"] == entry_data["category"]
    assert decrypted["tags"] == entry_data["tags"]
    assert "created_at" in decrypted

def test_encrypted_data_does_not_contain_plaintext():
    service = AESGCMEncryptionService()
    key_manager = FakeKeyManager()

    entry_data = {
        "title": "SecretService",
        "username": "secret_user",
        "password": "VerySecretPassword123!",
        "url": "https://secret.example.com",
        "notes": "very private notes",
    }

    encrypted = service.encrypt_entry(entry_data, key_manager)

    assert b"SecretService" not in encrypted
    assert b"secret_user" not in encrypted
    assert b"VerySecretPassword123!" not in encrypted
    assert b"secret.example.com" not in encrypted
    assert b"very private notes" not in encrypted

def test_each_encryption_uses_unique_nonce():
    service = AESGCMEncryptionService()
    key_manager = FakeKeyManager()

    entry_data = {
        "title": "GitHub",
        "username": "user@example.com",
        "password": "StrongPassword123!",
        "url": "https://github.com",
        "notes": "main account",
    }

    encrypted_1 = service.encrypt_entry(entry_data, key_manager)
    encrypted_2 = service.encrypt_entry(entry_data, key_manager)

    nonce_1 = encrypted_1[:service.NONCE_SIZE]
    nonce_2 = encrypted_2[:service.NONCE_SIZE]

    assert nonce_1 != nonce_2
    assert encrypted_1 != encrypted_2

def test_decrypt_detects_tampering():
    service = AESGCMEncryptionService()
    key_manager = FakeKeyManager()

    entry_data = {
        "title": "GitHub",
        "username": "user@example.com",
        "password": "StrongPassword123!",
        "url": "https://github.com",
        "notes": "main account",
    }

    encrypted = service.encrypt_entry(entry_data, key_manager)

    tampered = bytearray(encrypted)
    tampered[-1] ^= 1

    with pytest.raises(VaultEncryptionError):
        service.decrypt_entry(bytes(tampered), key_manager)

def test_decrypt_fails_with_wrong_key():
    service = AESGCMEncryptionService()

    key_manager_1 = FakeKeyManager(b"A" * 32)
    key_manager_2 = FakeKeyManager(b"B" * 32)

    entry_data = {
        "title": "GitHub",
        "username": "user@example.com",
        "password": "StrongPassword123!",
        "url": "https://github.com",
        "notes": "main account",
    }

    encrypted = service.encrypt_entry(entry_data, key_manager_1)

    with pytest.raises(VaultEncryptionError):
        service.decrypt_entry(encrypted, key_manager_2)

def test_associated_data_protects_context():
    service = AESGCMEncryptionService()
    key_manager = FakeKeyManager()

    entry_data = {
        "title": "GitHub",
        "username": "user@example.com",
        "password": "StrongPassword123!",
        "url": "https://github.com",
        "notes": "main account",
    }

    encrypted = service.encrypt_entry(
        entry_data,
        key_manager,
        associated_data=b"entry-id-1",
    )

    decrypted = service.decrypt_entry(
        encrypted,
        key_manager,
        associated_data=b"entry-id-1",
    )

    assert decrypted["title"] == "GitHub"

    with pytest.raises(VaultEncryptionError):
        service.decrypt_entry(
            encrypted,
            key_manager,
            associated_data=b"entry-id-2",
        )

def test_invalid_key_length_raises_error():
    service = AESGCMEncryptionService()
    key_manager = FakeKeyManager(b"short-key")

    with pytest.raises(VaultEncryptionError):
        service.encrypt(b"data", key_manager)

def test_too_short_encrypted_data_raises_error():
    service = AESGCMEncryptionService()
    key_manager = FakeKeyManager()

    with pytest.raises(VaultEncryptionError):
        service.decrypt(b"short", key_manager)