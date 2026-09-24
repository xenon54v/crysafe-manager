from __future__ import annotations

import sqlite3

import pytest

from src.core.audit import AuditConfig, AuditEventBridge, AuditLogger, AuditQuery
from src.core.events import (
    AuthenticationFailed,
    ClipboardCleared,
    ClipboardCopied,
    EntryCreated,
    EventBus,
    SearchPerformed,
    SecurityAlert,
    now_utc,
)
from src.database.audit_repo import AuditRepository
from src.database.db import Database
from src.database.settings_repo import SettingsRepository


def test_event_bridge_covers_security_relevant_categories(secure_audit):
    _db, _key_manager, logger = secure_audit
    bus = EventBus()
    bridge = AuditEventBridge(bus, logger)
    events = (
        EntryCreated("EntryCreated", now_utc(), "entry-1"),
        ClipboardCopied("ClipboardCopied", now_utc(), "entry-1", "password"),
        ClipboardCleared("ClipboardCleared", now_utc(), "timer"),
        SearchPerformed("SearchPerformed", now_utc(), "private words", 3),
        AuthenticationFailed("AuthenticationFailed", now_utc(), "local_user", 2),
        SecurityAlert(
            "SecurityAlert",
            now_utc(),
            "SUSPICIOUS_ACTIVITY",
            "CRITICAL",
            "unit_test",
            {"password": "must-not-persist"},
        ),
    )
    for event in events:
        bus.publish(event)
    logger.flush()
    rows = logger.query_entries(AuditQuery(page_size=50, descending=False))["entries"]
    event_types = {row["event_type"] for row in rows}
    database_bytes = logger.db.path.read_bytes()

    assert {
        "VAULT_ENTRY_CREATE",
        "CLIPBOARD_COPY",
        "CLIPBOARD_CLEAR",
        "VAULT_SEARCH",
        "AUTH_LOGIN_FAILURE",
        "SUSPICIOUS_ACTIVITY",
    }.issubset(event_types)
    assert b"private words" not in database_bytes
    assert b"must-not-persist" not in database_bytes
    bridge.close()


def test_pending_pre_auth_record_is_signed_after_unlock(tmp_path):
    db = Database(tmp_path / "pending.db")
    db.connect()
    AuditRepository(db).add_log("AUTH_LOGIN_FAILURE", details="attempt_count=1")
    pending = db.execute("SELECT signature FROM audit_log;").fetchone()
    assert pending[0] is None

    from src.core.key_manager import KeyManager

    key_manager = KeyManager()
    key_manager.unlock_with_password(db, "StrongMasterPassword9!")
    logger = AuditLogger(db, key_manager)

    signed = db.execute(
        "SELECT signature, key_id FROM audit_log WHERE event_type = 'AUTH_LOGIN_FAILURE';"
    ).fetchone()
    assert signed[0]
    assert signed[1]
    assert logger.verify_integrity().verified
    logger.close()
    db.close()


def test_audit_configuration_is_encrypted(secure_audit):
    db, key_manager, _logger = secure_audit
    repository = SettingsRepository(db, key_manager)
    expected = AuditConfig(
        max_entries=2_000,
        max_age_days=90,
        verification_interval_hours=12,
        scheduled_export="weekly",
    )
    repository.save_audit_config(expected)
    row = db.execute(
        "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?;",
        (SettingsRepository.AUDIT_KEY,),
    ).fetchone()

    assert repository.load_audit_config() == expected
    assert row["encrypted"] == 1
    assert b"weekly" not in bytes(row["setting_value"])


def test_access_control_blocks_log_reads_when_locked(tmp_path):
    db = Database(tmp_path / "access.db")
    db.connect()
    from src.core.key_manager import KeyManager

    key_manager = KeyManager()
    key_manager.unlock_with_password(db, "StrongMasterPassword9!")
    unlocked = True
    logger = AuditLogger(db, key_manager, is_authenticated=lambda: unlocked)
    logger.log_event("ACCESS_TEST", source="unit_test")
    unlocked = False

    with pytest.raises(PermissionError, match="Authentication"):
        logger.query_entries()
    with pytest.raises(PermissionError, match="Authentication"):
        logger.verify_integrity()
    unlocked = True
    logger.close()
    db.close()


def test_filter_query_resists_sql_injection(secure_audit):
    _db, _key_manager, logger = secure_audit
    for index in range(12):
        logger.log_event(
            "FILTER_EVENT",
            source="unit_test",
            details={"safe_value": f"record-{index}"},
        )

    result = logger.query_entries(AuditQuery(search_text="%' OR 1=1 --", page_size=50))

    assert result["total"] == 0
    assert logger.verify_integrity().verified


def test_key_generations_rotate_for_forward_security(tmp_path):
    db = Database(tmp_path / "rotation.db")
    db.connect()
    from src.core.key_manager import KeyManager

    key_manager = KeyManager()
    key_manager.unlock_with_password(db, "StrongMasterPassword9!")
    logger = AuditLogger(db, key_manager, AuditConfig(key_rotation_interval=3))
    for index in range(9):
        logger.log_event("ROTATION_EVENT", source="unit_test", details={"i": index})

    generations = db.execute(
        "SELECT generation FROM audit_keys ORDER BY generation;"
    ).fetchall()

    assert [row[0] for row in generations] == [0, 1, 2, 3]
    assert logger.verify_integrity().verified
    logger.close()
    db.close()


def test_rotation_creates_encrypted_immutable_archive(tmp_path):
    db = Database(tmp_path / "archive.db")
    db.connect()
    from src.core.key_manager import KeyManager

    key_manager = KeyManager()
    key_manager.unlock_with_password(db, "StrongMasterPassword9!")
    logger = AuditLogger(db, key_manager, AuditConfig(max_entries=100))
    for index in range(105):
        logger.log_event("ARCHIVE_EVENT", source="unit_test", details={"i": index})

    archive_id = logger.rotate_if_needed()
    archive = db.execute("SELECT * FROM audit_archives;").fetchone()

    assert archive_id is not None
    assert archive["entry_count"] >= 1
    assert bytes(archive["encrypted_data"]).startswith(b"{") is False
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute("UPDATE audit_archives SET entry_count = 0;")
    logger.close()
    db.close()
