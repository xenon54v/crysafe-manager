from concurrent.futures import ThreadPoolExecutor

import pytest

from src.core.vault.entry_manager import EntryManager, EntryManagerError
from src.database.db import Database


class FakeKeyManager:
    def get_active_key(self) -> bytes:
        return b"K" * 32


def test_database_uses_connection_pool_and_required_indexes(tmp_path):
    db = Database(tmp_path / "pool.db", pool_size=4)
    db.connect()

    indexes = {
        row["name"]
        for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index';"
        ).fetchall()
    }

    assert db.connection_pool_size == 4
    assert "idx_vault_entries_created_at" in indexes
    assert "idx_vault_entries_updated_at" in indexes
    assert "idx_vault_entries_tags" in indexes
    db.close()


def test_soft_delete_rolls_back_if_archive_insert_fails(tmp_path):
    db = Database(tmp_path / "rollback.db")
    db.connect()
    manager = EntryManager(db, FakeKeyManager())
    entry = manager.create_entry({"title": "Keep", "password": "StrongPassword7!"})
    db.execute(
        """
        CREATE TRIGGER reject_archive
        BEFORE INSERT ON deleted_entries
        BEGIN
            SELECT RAISE(ABORT, 'archive unavailable');
        END;
        """
    )

    with pytest.raises(EntryManagerError):
        manager.delete_entry(entry["id"], soft_delete=True)

    assert manager.get_entry(entry["id"]) is not None
    assert db.execute("SELECT COUNT(*) FROM deleted_entries;").fetchone()[0] == 0
    db.close()


def test_concurrent_creates_do_not_corrupt_database(tmp_path):
    db = Database(tmp_path / "concurrency.db", pool_size=4)
    db.connect()
    manager = EntryManager(db, FakeKeyManager())

    def create(number: int) -> str:
        return manager.create_entry(
            {
                "title": f"Service {number}",
                "username": f"user{number}",
                "password": f"StrongPassword{number}!",
            }
        )["id"]

    with ThreadPoolExecutor(max_workers=8) as executor:
        ids = list(executor.map(create, range(100)))

    assert len(set(ids)) == 100
    assert len(manager.get_all_entries()) == 100
    db.close()
