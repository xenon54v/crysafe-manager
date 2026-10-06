from __future__ import annotations

import pytest

from src.core.key_manager import KeyManager
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database

MASTER_PASSWORD = "Correct Horse Battery Staple 42!"


@pytest.fixture
def vault(tmp_path):
    db = Database(tmp_path / "sprint6.db")
    db.connect()
    key_manager = KeyManager()
    key_manager.unlock_with_password(db, MASTER_PASSWORD)
    entry_manager = EntryManager(db, key_manager)
    yield db, key_manager, entry_manager
    key_manager.lock()
    db.close()


@pytest.fixture
def populated_vault(vault):
    db, key_manager, entries = vault
    created = entries.create_entry(
        {
            "title": "Primary Account",
            "username": "user@example.com",
            "password": "EntryPassword!42",
            "url": "https://example.com/login",
            "notes": "Recovery codes are stored offline.",
            "category": "Personal",
            "tags": ["mail", "important"],
            "totp_secret": "JBSWY3DPEHPK3PXP",
        }
    )
    return db, key_manager, entries, created
