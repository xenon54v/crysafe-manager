import time
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

def test_key_storage_expires_after_ttl():
    storage = KeyStorage(ttl_seconds=1)

    storage.save(b"a" * 32)

    assert storage.has_key() is True

    time.sleep(1.1)

    assert storage.has_key() is False

    with pytest.raises(RuntimeError):
        storage.load()

def test_key_storage_clear_removes_key_before_ttl():
    storage = KeyStorage(ttl_seconds=60)

    storage.save(b"a" * 32)
    storage.clear()

    assert storage.has_key() is False

    with pytest.raises(RuntimeError):
        storage.load()