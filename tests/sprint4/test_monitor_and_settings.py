from __future__ import annotations

import time

from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.clipboard.clipboard_service import (
    ClipboardConfig,
    ClipboardService,
    ClipboardState,
)
from src.core.clipboard.platform_adapter import InMemoryClipboardAdapter
from src.database.audit_repo import AuditRepository
from src.database.db import Database
from src.database.repo import VaultRepository
from src.database.settings_repo import SettingsRepository


class FakeKeyManager:
    def get_active_key(self) -> bytes:
        return b"S" * 32


def test_monitor_detects_external_change_without_erasing_new_content():
    adapter = InMemoryClipboardAdapter()
    service = ClipboardService(
        adapter,
        is_vault_unlocked=lambda: True,
        config=ClipboardConfig(timeout_seconds=None),
    )
    monitor = ClipboardMonitor(adapter, service, poll_interval=0.1)
    monitor.start()
    service.copy_text("managed-secret", entry_id="1", field="password")

    adapter.copy_text("external-content")
    deadline = time.monotonic() + 1.0
    while service.has_sensitive_value and time.monotonic() < deadline:
        time.sleep(0.02)

    monitor.stop()
    assert not service.has_sensitive_value
    assert service.snapshot.state is ClipboardState.WARNING
    assert adapter.read_text() == "external-content"


def test_idle_monitor_uses_less_than_one_percent_cpu():
    adapter = InMemoryClipboardAdapter()
    service = ClipboardService(adapter, is_vault_unlocked=lambda: True)
    monitor = ClipboardMonitor(adapter, service, poll_interval=0.1)
    started_cpu = time.process_time()
    monitor.start()
    time.sleep(1.1)
    monitor.stop()
    used_cpu = time.process_time() - started_cpu

    assert used_cpu < 0.011


def test_clipboard_settings_are_encrypted_and_persisted(tmp_path):
    db = Database(tmp_path / "settings.db")
    db.connect()
    repo = SettingsRepository(db, FakeKeyManager())
    config = ClipboardConfig(
        timeout_seconds=15,
        notifications_enabled=False,
        security_level="advanced",
        application_whitelist=("trusted-browser",),
        block_after_suspicious_access=True,
    )

    repo.save_clipboard_config(config)
    loaded = repo.load_clipboard_config()
    row = db.execute(
        "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?;",
        (SettingsRepository.CLIPBOARD_KEY,),
    ).fetchone()

    assert loaded == config
    assert row["encrypted"] == 1
    assert b"trusted-browser" not in bytes(row["setting_value"])
    assert b"advanced" not in bytes(row["setting_value"])
    db.close()


def test_clipboard_audit_contains_metadata_but_not_secret(tmp_path):
    db = Database(tmp_path / "audit.db")
    db.connect()
    audit = AuditRepository(db)
    adapter = InMemoryClipboardAdapter()
    service = ClipboardService(
        adapter,
        is_vault_unlocked=lambda: True,
        audit_callback=audit.add_clipboard_log,
    )
    secret = "NeverWriteThisSecretToDisk"

    service.copy_text(secret, entry_id="entry-7", field="password")
    service.clear("manual")
    rows = db.execute(
        "SELECT action, entry_id, details FROM audit_log ORDER BY id;"
    ).fetchall()

    assert [row["action"] for row in rows] == ["clipboard_copy", "clipboard_clear"]
    assert all(secret not in str(tuple(row)) for row in rows)
    assert rows[0]["entry_id"] == "entry-7"
    db.close()


def test_encrypted_clipboard_settings_survive_master_password_change(tmp_path):
    db = Database(tmp_path / "password-change.db")
    db.connect()
    vault = VaultRepository(db)
    vault.key_manager.unlock_with_password(db, "OldStrongPassword9!")
    settings = SettingsRepository(db, vault.key_manager)
    expected = ClipboardConfig.profile("secure")
    settings.save_clipboard_config(expected)

    vault.change_master_password("OldStrongPassword9!", "NewStrongPassword8!")

    assert SettingsRepository(db, vault.key_manager).load_clipboard_config() == expected
    db.close()
