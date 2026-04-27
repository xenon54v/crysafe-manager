import pytest
from src.core.crypto.key_storage import KeyStorage

def test_key_storage_save_and_load():
    storage = KeyStorage()

    key = b"a" * 32
    storage.save(key)

    assert storage.load() == key

def test_key_storage_clear():
    storage = KeyStorage()

    storage.save(b"a" * 32)
    storage.clear()

    assert storage.has_key() is False

def test_key_storage_load_without_key():
    storage = KeyStorage()

    with pytest.raises(RuntimeError):
        storage.load()