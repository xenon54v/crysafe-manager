from __future__ import annotations

import hashlib
import json

import pytest

from src.core.import_export import (
    ExportOptions,
    ImportOptions,
    VaultExporter,
    VaultImporter,
)
from src.core.import_export.errors import ExportError, ImportValidationError

from .conftest import MASTER_PASSWORD


def test_schema_contains_exchange_tables(vault):
    db, _key_manager, _entries = vault
    names = {
        row[0]
        for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table';"
        ).fetchall()
    }
    assert {
        "shared_entries",
        "import_export_history",
        "contacts",
        "contact_keys",
        "import_checkpoints",
        "exchange_nonces",
    } <= names
    assert db.execute("PRAGMA user_version;").fetchone()[0] == 7


def test_password_encrypted_round_trip_and_history(populated_vault):
    db, key_manager, entries, created = populated_vault
    exporter = VaultExporter(entries, key_manager)
    artifact = exporter.export(
        ExportOptions(compress=True),
        master_password=MASTER_PASSWORD,
        export_password="Portable Backup Password!9",
    )
    assert artifact.encrypted
    assert b"EntryPassword!42" not in artifact.data
    assert artifact.checksum == hashlib.sha256(artifact.data).hexdigest()

    preview = VaultImporter(entries).preview(
        artifact.data,
        ImportOptions(mode="dry_run"),
        password="Portable Backup Password!9",
    )
    assert preview.encrypted
    assert preview.entries[0]["title"] == created["title"]
    assert preview.update_count == 1
    history = db.execute(
        "SELECT operation_type, entry_count FROM import_export_history;"
    ).fetchall()
    assert [tuple(row) for row in history] == [("export", 1)]


def test_new_nonce_and_salt_are_used_for_every_export(populated_vault):
    _db, key_manager, entries, _created = populated_vault
    exporter = VaultExporter(entries, key_manager)
    first = exporter.export(
        ExportOptions(),
        master_password=MASTER_PASSWORD,
        export_password="same password",
    )
    second = exporter.export(
        ExportOptions(),
        master_password=MASTER_PASSWORD,
        export_password="same password",
    )
    first_package = json.loads(first.data)
    second_package = json.loads(second.data)
    assert first_package["encryption"]["salt"] != second_package["encryption"]["salt"]
    assert first_package["encryption"]["nonce"] != second_package["encryption"]["nonce"]
    assert first.data != second.data


def test_tampered_export_is_rejected_before_payload_decryption(populated_vault):
    _db, key_manager, entries, _created = populated_vault
    artifact = VaultExporter(entries, key_manager).export(
        ExportOptions(),
        master_password=MASTER_PASSWORD,
        export_password="Export Password 123!",
    )
    package = json.loads(artifact.data)
    package["data"] = ("A" if package["data"][0] != "A" else "B") + package["data"][1:]
    with pytest.raises(ImportValidationError, match="checksum"):
        VaultImporter(entries).preview(
            json.dumps(package).encode(),
            ImportOptions(mode="dry_run"),
            password="Export Password 123!",
        )


def test_excessive_pbkdf2_work_factor_is_rejected(populated_vault):
    _db, key_manager, entries, _created = populated_vault
    artifact = VaultExporter(entries, key_manager).export(
        ExportOptions(),
        master_password=MASTER_PASSWORD,
        export_password="Export Password 123!",
    )
    package = json.loads(artifact.data)
    package["encryption"]["iterations"] = 50_000_000
    with pytest.raises(ImportValidationError, match="derivation parameters"):
        VaultImporter(entries).preview(
            json.dumps(package).encode(),
            ImportOptions(mode="dry_run"),
            password="Export Password 123!",
        )


def test_compressed_import_cannot_expand_beyond_size_limit(vault):
    _db, key_manager, entries = vault
    entries.create_entry(
        {
            "title": "Compression test",
            "password": "secret",
            "notes": "A" * 200_000,
        }
    )
    artifact = VaultExporter(entries, key_manager).export(
        ExportOptions(compress=True),
        master_password=MASTER_PASSWORD,
        export_password="Compression Password 123!",
    )
    assert len(artifact.data) < 100_000
    with pytest.raises(ImportValidationError, match="expands beyond"):
        VaultImporter(entries).preview(
            artifact.data,
            ImportOptions(mode="dry_run", max_file_size=100_000),
            password="Compression Password 123!",
        )


def test_selective_export_field_exclusion_and_128_bit_option(populated_vault):
    _db, key_manager, entries, created = populated_vault
    artifact = VaultExporter(entries, key_manager).export(
        ExportOptions(
            entry_ids=(created["id"],),
            excluded_fields=frozenset({"notes", "totp_secret"}),
            encryption_bits=128,
        ),
        master_password=MASTER_PASSWORD,
        export_password="Export Password 123!",
    )
    package = json.loads(artifact.data)
    assert package["encryption"]["algorithm"] == "AES-128-GCM"
    preview = VaultImporter(entries).preview(
        artifact.data,
        ImportOptions(mode="dry_run"),
        password="Export Password 123!",
    )
    assert preview.entries[0]["notes"] == ""
    assert preview.entries[0]["totp_secret"] == ""


def test_csv_and_password_manager_formats_round_trip(populated_vault):
    _db, key_manager, entries, _created = populated_vault
    exporter = VaultExporter(entries, key_manager)
    importer = VaultImporter(entries)
    for format_name in ("csv", "bitwarden_json", "lastpass_csv"):
        artifact = exporter.export(
            ExportOptions(format_name=format_name),
            master_password=MASTER_PASSWORD,
            export_password="Format Password 123!",
        )
        preview = importer.preview(
            artifact.data,
            ImportOptions(mode="dry_run"),
            password="Format Password 123!",
        )
        assert preview.entry_count == 1
        assert preview.entries[0]["title"] == "Primary Account"
        assert preview.entries[0]["password"] == "EntryPassword!42"


def test_plaintext_csv_requires_explicit_migration_approval(populated_vault):
    _db, key_manager, entries, _created = populated_vault
    with pytest.raises(ValueError, match="explicit"):
        ExportOptions(format_name="csv", encrypt=False)
    artifact = VaultExporter(entries, key_manager).export(
        ExportOptions(format_name="csv", encrypt=False, allow_plaintext=True),
        master_password=MASTER_PASSWORD,
    )
    assert not artifact.encrypted
    assert b"EntryPassword!42" in artifact.data
    preview = VaultImporter(entries).preview(
        artifact.data, ImportOptions(mode="dry_run")
    )
    assert preview.format_name == "csv"


def test_export_requires_correct_master_password(populated_vault):
    _db, key_manager, entries, _created = populated_vault
    exporter = VaultExporter(entries, key_manager)
    with pytest.raises(ExportError, match="confirmation"):
        exporter.export(
            ExportOptions(),
            master_password="wrong",
            export_password="Export Password 123!",
        )


def test_atomic_file_export_leaves_no_temporary_files(populated_vault, tmp_path):
    _db, key_manager, entries, _created = populated_vault
    destination = tmp_path / "backup.csm.json"
    artifact = VaultExporter(entries, key_manager).export_to_file(
        destination,
        ExportOptions(),
        master_password=MASTER_PASSWORD,
        export_password="File Password 123!",
    )
    assert destination.read_bytes() == artifact.data
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


def test_import_modes_duplicate_handling_and_replace(populated_vault):
    db, key_manager, entries, _created = populated_vault
    exporter = VaultExporter(entries, key_manager)
    artifact = exporter.export(
        ExportOptions(),
        master_password=MASTER_PASSWORD,
        export_password="Mode Password 123!",
    )
    importer = VaultImporter(entries)
    skipped = importer.import_data(
        artifact.data,
        ImportOptions(conflict_action="skip"),
        password="Mode Password 123!",
    )
    assert (skipped.created, skipped.updated, skipped.skipped) == (0, 0, 1)
    duplicated = importer.import_data(
        artifact.data,
        ImportOptions(conflict_action="duplicate"),
        password="Mode Password 123!",
    )
    assert duplicated.created == 1
    assert len(entries.get_all_entries()) == 2
    replaced = importer.import_data(
        artifact.data,
        ImportOptions(mode="replace"),
        password="Mode Password 123!",
    )
    assert replaced.created == 1
    assert len(entries.get_all_entries()) == 1
    assert (
        db.execute(
            "SELECT COUNT(*) FROM import_export_history WHERE operation_type = 'import';"
        ).fetchone()[0]
        == 3
    )


def test_import_sanitizes_scripts_and_rejects_executables(vault):
    _db, _key_manager, entries = vault
    csv_data = (
        b"title,username,password,url,notes\n"
        b"Unsafe,user,secret,javascript:alert(1),<script>alert(1)</script> note\n"
    )
    preview = VaultImporter(entries).preview(csv_data, ImportOptions(mode="dry_run"))
    assert preview.warnings
    assert preview.entries[0]["url"] == ""
    assert "<script" not in preview.entries[0]["notes"].casefold()
    with pytest.raises(ImportValidationError, match="Executable"):
        VaultImporter(entries).preview(b"MZ" + b"\x00" * 100)


def test_import_size_limit_and_manual_format_fallback(vault, tmp_path):
    _db, _key_manager, entries = vault
    path = tmp_path / "large.csv"
    path.write_bytes(b"x" * 101)
    with pytest.raises(ImportValidationError, match="size limit"):
        VaultImporter(entries).preview(
            path, ImportOptions(mode="dry_run", max_file_size=100)
        )
    with pytest.raises(ImportValidationError, match="select a format manually"):
        VaultImporter(entries).preview(b"not a known format")


def test_bitwarden_plaintext_auto_detection(vault):
    _db, _key_manager, entries = vault
    data = json.dumps(
        {
            "encrypted": False,
            "items": [
                {
                    "type": 1,
                    "name": "Imported",
                    "login": {
                        "username": "alice",
                        "password": "secret",
                        "uris": [{"uri": "https://example.org"}],
                    },
                }
            ],
        }
    ).encode()
    result = VaultImporter(entries).import_data(data, ImportOptions())
    assert result.created == 1
    assert entries.get_all_entries()[0]["username"] == "alice"


def test_partial_import_resumes_from_checkpoint(vault, monkeypatch):
    db, _key_manager, entries = vault
    source = (
        b"title,username,password,url\n"
        b"First,one,secret-1,https://one.example\n"
        b"Second,two,secret-2,https://two.example\n"
    )
    checkpoint_id = "resume-test"
    original_create = entries.create_entry
    call_count = 0

    def fail_on_second(data):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise RuntimeError("simulated interruption")
        return original_create(data)

    monkeypatch.setattr(entries, "create_entry", fail_on_second)
    options = ImportOptions(
        allow_partial=True,
        checkpoint_id=checkpoint_id,
    )
    with pytest.raises(ImportValidationError, match="could not be completed"):
        VaultImporter(entries).import_data(source, options)
    checkpoint = db.execute(
        "SELECT next_index FROM import_checkpoints WHERE checkpoint_id = ?;",
        (checkpoint_id,),
    ).fetchone()
    assert checkpoint[0] == 1
    assert len(entries.get_all_entries()) == 1

    monkeypatch.setattr(entries, "create_entry", original_create)
    resumed = VaultImporter(entries).import_data(source, options)
    assert resumed.created == 1
    assert len(entries.get_all_entries()) == 2
    assert (
        db.execute(
            "SELECT 1 FROM import_checkpoints WHERE checkpoint_id = ?;",
            (checkpoint_id,),
        ).fetchone()
        is None
    )
