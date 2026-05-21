import sqlite3

import pytest

from src.core.events import EventBus
from src.core.vault.entry_manager import EntryManager, EntryManagerError
from src.database.models import CREATE_TABLES_SQL


class FakeDatabase:
    def __init__(self):
        self._connection = sqlite3.connect(":memory:")
        self._connection.row_factory = sqlite3.Row

        for sql in CREATE_TABLES_SQL:
            self._connection.execute(sql)

        self._connection.commit()

    def execute(self, query, params=()):
        return self._connection.execute(query, params)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


class FakeKeyManager:
    def __init__(self):
        self.key = b"A" * 32

    def get_active_key(self) -> bytes:
        return self.key


def create_manager():
    db = FakeDatabase()
    key_manager = FakeKeyManager()
    event_bus = EventBus()
    manager = EntryManager(
        db=db,
        key_manager=key_manager,
        event_bus=event_bus,
    )
    return manager, db


def test_create_entry_success():
    manager, db = create_manager()

    entry = manager.create_entry(
        {
            "title": "GitHub",
            "username": "user@example.com",
            "password": "StrongPassword123!",
            "url": "https://github.com",
            "notes": "main account",
            "category": "Work",
            "tags": ["git", "main"],
        }
    )

    assert entry["id"] is not None
    assert entry["title"] == "GitHub"
    assert entry["username"] == "user@example.com"
    assert entry["password"] == "StrongPassword123!"
    assert entry["url"] == "https://github.com"
    assert entry["notes"] == "main account"
    assert entry["category"] == "Work"
    assert entry["tags"] == ["git", "main"]
    assert entry["version"] == 1
    assert "created_at" in entry
    assert "updated_at" in entry

    db.close()


def test_create_entry_stores_only_encrypted_data():
    manager, db = create_manager()

    entry = manager.create_entry(
        {
            "title": "SecretService",
            "username": "secret_user",
            "password": "VerySecretPassword123!",
            "url": "https://secret.example.com",
            "notes": "private notes",
            "tags": ["secret"],
        }
    )

    cursor = db.execute(
        """
        SELECT encrypted_data
        FROM vault_entries
        WHERE id = ?;
        """,
        (entry["id"],),
    )

    row = cursor.fetchone()
    encrypted_data = row["encrypted_data"]

    assert isinstance(encrypted_data, bytes)
    assert b"SecretService" not in encrypted_data
    assert b"secret_user" not in encrypted_data
    assert b"VerySecretPassword123!" not in encrypted_data
    assert b"secret.example.com" not in encrypted_data
    assert b"private notes" not in encrypted_data

    db.close()


def test_get_entry_success():
    manager, db = create_manager()

    created = manager.create_entry(
        {
            "title": "Email",
            "username": "mail@example.com",
            "password": "MailPassword123!",
            "url": "https://mail.example.com",
            "notes": "email account",
            "tags": ["mail"],
        }
    )

    loaded = manager.get_entry(created["id"])

    assert loaded is not None
    assert loaded["id"] == created["id"]
    assert loaded["title"] == "Email"
    assert loaded["username"] == "mail@example.com"
    assert loaded["password"] == "MailPassword123!"

    db.close()


def test_get_entry_returns_none_for_missing_entry():
    manager, db = create_manager()

    loaded = manager.get_entry("missing-id")

    assert loaded is None

    db.close()


def test_get_all_entries_success():
    manager, db = create_manager()

    manager.create_entry(
        {
            "title": "First",
            "username": "first_user",
            "password": "FirstPassword123!",
        }
    )

    manager.create_entry(
        {
            "title": "Second",
            "username": "second_user",
            "password": "SecondPassword123!",
        }
    )

    entries = manager.get_all_entries()

    titles = {entry["title"] for entry in entries}

    assert len(entries) == 2
    assert "First" in titles
    assert "Second" in titles

    db.close()


def test_update_entry_success():
    manager, db = create_manager()

    created = manager.create_entry(
        {
            "title": "Old title",
            "username": "old_user",
            "password": "OldPassword123!",
            "url": "https://old.example.com",
            "notes": "old notes",
            "tags": ["old"],
        }
    )

    updated = manager.update_entry(
        created["id"],
        {
            "title": "New title",
            "username": "new_user",
            "password": "NewPassword123!",
            "url": "https://new.example.com",
            "notes": "new notes",
            "tags": ["new"],
        },
    )

    assert updated["id"] == created["id"]
    assert updated["title"] == "New title"
    assert updated["username"] == "new_user"
    assert updated["password"] == "NewPassword123!"
    assert updated["url"] == "https://new.example.com"
    assert updated["notes"] == "new notes"
    assert updated["tags"] == ["new"]
    assert updated["created_at"] == created["created_at"]
    assert updated["updated_at"] != created["updated_at"]

    db.close()


def test_update_missing_entry_raises_error():
    manager, db = create_manager()

    with pytest.raises(EntryManagerError):
        manager.update_entry(
            "missing-id",
            {
                "title": "New title",
                "password": "NewPassword123!",
            },
        )

    db.close()


def test_delete_entry_success():
    manager, db = create_manager()

    created = manager.create_entry(
        {
            "title": "Delete me",
            "username": "delete_user",
            "password": "DeletePassword123!",
        }
    )

    deleted = manager.delete_entry(
        created["id"],
        soft_delete=False,
    )

    loaded = manager.get_entry(created["id"])

    assert deleted is True
    assert loaded is None

    db.close()


def test_delete_missing_entry_returns_false():
    manager, db = create_manager()

    deleted = manager.delete_entry(
        "missing-id",
        soft_delete=False,
    )

    assert deleted is False

    db.close()


def test_create_entry_requires_title():
    manager, db = create_manager()

    with pytest.raises(EntryManagerError):
        manager.create_entry(
            {
                "title": "",
                "username": "user",
                "password": "Password123!",
            }
        )

    db.close()


def test_create_entry_requires_password():
    manager, db = create_manager()

    with pytest.raises(EntryManagerError):
        manager.create_entry(
            {
                "title": "No password",
                "username": "user",
                "password": "",
            }
        )

    db.close()


def test_database_table_does_not_have_plaintext_columns():
    manager, db = create_manager()

    cursor = db.execute("PRAGMA table_info(vault_entries);")
    columns = cursor.fetchall()

    column_names = {column["name"] for column in columns}

    assert "id" in column_names
    assert "encrypted_data" in column_names
    assert "created_at" in column_names
    assert "updated_at" in column_names
    assert "tags" in column_names

    assert "title" not in column_names
    assert "username" not in column_names
    assert "password" not in column_names
    assert "encrypted_password" not in column_names
    assert "url" not in column_names
    assert "notes" not in column_names

    db.close()

def test_soft_delete_moves_entry_to_deleted_entries():
    manager, db = create_manager()

    created = manager.create_entry(
        {
            "title": "Soft delete me",
            "username": "soft_user",
            "password": "SoftDeletePassword123!",
            "url": "https://soft.example.com",
            "notes": "temporary deleted entry",
            "tags": ["deleted"],
        }
    )

    deleted = manager.delete_entry(
        created["id"],
        soft_delete=True,
    )

    loaded = manager.get_entry(created["id"])

    cursor = db.execute(
        """
        SELECT id, encrypted_data, created_at, updated_at, deleted_at, expires_at, tags
        FROM deleted_entries
        WHERE id = ?;
        """,
        (created["id"],),
    )

    deleted_row = cursor.fetchone()

    assert deleted is True
    assert loaded is None
    assert deleted_row is not None
    assert deleted_row["id"] == created["id"]
    assert deleted_row["encrypted_data"] is not None
    assert deleted_row["deleted_at"] is not None
    assert deleted_row["expires_at"] is not None

    db.close()