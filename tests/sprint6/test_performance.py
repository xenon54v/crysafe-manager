from __future__ import annotations

import time

from src.core.import_export import (
    ExportOptions,
    ImportOptions,
    VaultExporter,
    VaultImporter,
)
from src.core.key_manager import KeyManager
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database

from .conftest import MASTER_PASSWORD


def test_export_and_import_one_thousand_entries_meet_targets(tmp_path):
    source_db = Database(tmp_path / "source.db")
    source_db.connect()
    source_keys = KeyManager()
    source_keys.unlock_with_password(source_db, MASTER_PASSWORD)
    source_entries = EntryManager(source_db, source_keys)
    for index in range(1000):
        source_entries.create_entry(
            {
                "title": f"Account {index:04d}",
                "username": f"user{index}@example.com",
                "password": f"Unique-Password-{index}!",
                "url": f"https://service{index}.example.com",
                "notes": "migration record",
                "tags": ["bulk"],
            }
        )

    started = time.perf_counter()
    artifact = VaultExporter(source_entries, source_keys).export(
        ExportOptions(compress=True),
        master_password=MASTER_PASSWORD,
        export_password="Performance Export Password!8",
    )
    export_seconds = time.perf_counter() - started
    assert export_seconds < 5.0

    target_db = Database(tmp_path / "target.db")
    target_db.connect()
    target_keys = KeyManager()
    target_keys.unlock_with_password(target_db, "Independent Target Master!6")
    target_entries = EntryManager(target_db, target_keys)
    started = time.perf_counter()
    result = VaultImporter(target_entries).import_data(
        artifact.data,
        ImportOptions(),
        password="Performance Export Password!8",
    )
    import_seconds = time.perf_counter() - started
    assert import_seconds < 10.0
    assert result.created == 1000
    assert len(target_entries.get_all_entries()) == 1000

    target_keys.lock()
    target_db.close()
    source_keys.lock()
    source_db.close()
