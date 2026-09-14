from __future__ import annotations

import pytest

from src.core.vault.entry_manager import EntryManager, EntryManagerError
from src.database.db import Database


class FakeKeyManager:
    def get_active_key(self) -> bytes:
        return b"E" * 32


def test_entry_can_forbid_all_clipboard_operations(tmp_path):
    db = Database(tmp_path / "entry-policy.db")
    db.connect()
    manager = EntryManager(db, FakeKeyManager())
    entry = manager.create_entry(
        {
            "title": "Restricted",
            "username": "user",
            "password": "StrongPassword9!",
            "sharing_metadata": {"never_copy_to_clipboard": True},
        }
    )

    with pytest.raises(EntryManagerError, match="disabled"):
        manager.get_clipboard_value(entry["id"], "password")
    db.close()


def test_copy_all_contains_supported_fields(tmp_path):
    db = Database(tmp_path / "entry-copy-all.db")
    db.connect()
    manager = EntryManager(db, FakeKeyManager())
    entry = manager.create_entry(
        {
            "title": "Portal",
            "username": "student",
            "password": "StrongPassword9!",
            "url": "https://example.com",
            "notes": "Study",
        }
    )

    value = manager.get_clipboard_value(entry["id"], "all")

    assert value.splitlines() == [
        "Username: student",
        "Password: StrongPassword9!",
        "URL: https://example.com",
        "Notes: Study",
    ]
    db.close()
