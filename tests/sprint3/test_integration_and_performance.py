import time
import tracemalloc

from src.core.events import (
    ClipboardCopied,
    EntryCreated,
    EntryDeleted,
    EntryUpdated,
    EventBus,
)
from src.core.vault.entry_manager import EntryManager, EntryManagerError
from src.core.vault.search_service import VaultSearchIndex
from src.database.db import Database


class FakeKeyManager:
    def get_active_key(self) -> bytes:
        return b"P" * 32


def test_crud_events_and_future_fields(tmp_path):
    db = Database(tmp_path / "integration.db")
    db.connect()
    bus = EventBus()
    events = []
    for event_type in (EntryCreated, EntryUpdated, EntryDeleted, ClipboardCopied):
        bus.subscribe(event_type, events.append)
    manager = EntryManager(db, FakeKeyManager(), bus)

    created = manager.create_entry(
        {
            "title": "Portal",
            "username": "student",
            "password": "StrongPassword9!",
            "totp_secret": "BASE32SECRET",
            "sharing_metadata": {"owner": "local_user"},
        }
    )
    updated = manager.update_entry(created["id"], {"notes": "Updated"})
    copied = manager.get_clipboard_value(created["id"], "password")
    deleted = manager.delete_entry(created["id"])

    assert updated["totp_secret"] == "BASE32SECRET"
    assert updated["sharing_metadata"] == {"owner": "local_user"}
    assert copied == "StrongPassword9!"
    assert deleted is True
    assert [type(event) for event in events] == [
        EntryCreated,
        EntryUpdated,
        ClipboardCopied,
        EntryDeleted,
    ]
    db.close()


def test_missing_id_error_does_not_echo_identifier(tmp_path):
    db = Database(tmp_path / "errors.db")
    db.connect()
    manager = EntryManager(db, FakeKeyManager())
    missing_id = "sensitive-missing-id"

    try:
        manager.update_entry(missing_id, {"title": "A", "password": "StrongPassword9!"})
    except EntryManagerError as exc:
        assert missing_id not in str(exc)
    else:
        raise AssertionError("Missing entry must not be updated")
    db.close()


def test_load_search_and_memory_requirements_for_one_thousand_entries(tmp_path):
    db = Database(tmp_path / "performance.db")
    db.connect()
    manager = EntryManager(db, FakeKeyManager())
    for number in range(1000):
        manager.create_entry(
            {
                "title": f"Service {number}",
                "username": f"user{number}@example.com",
                "password": f"GeneratedPassword{number}!A",
                "url": f"https://service{number}.example.com",
                "notes": "performance fixture",
                "category": "Test",
                "tags": ["load", str(number % 10)],
            }
        )

    tracemalloc.start()
    load_started = time.perf_counter()
    entries = manager.get_all_entries()
    load_elapsed = time.perf_counter() - load_started
    index = VaultSearchIndex()
    index.rebuild(entries)
    search_started = time.perf_counter()
    results = index.search('title:"service 999"')
    search_elapsed = time.perf_counter() - search_started
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(entries) == 1000
    assert [entry["title"] for entry in results] == ["Service 999"]
    assert load_elapsed < 2.0
    assert search_elapsed < 0.2
    assert peak_memory < 50 * 1024 * 1024
    db.close()
