from __future__ import annotations

import os
import statistics
import time
from contextlib import nullcontext

from src.core.import_export import (
    ExportOptions,
    ImportOptions,
    VaultExporter,
    VaultImporter,
)
from src.core.key_manager import KeyManager
from src.core.security import (
    ActivityMonitor,
    MemoryGuard,
    PanicMode,
    SecurityHardeningConfig,
    SideChannelProtection,
)
from src.core.vault.encryption_service import AESGCMEncryptionService
from src.core.vault.entry_manager import EntryManager
from src.core.vault.search_service import VaultSearchIndex
from src.database.db import Database
from src.gui.tray_service import SecurityTrayService, TrayCallbacks


class FakeDetector:
    def idle_seconds(self):
        return None

    def screen_locked(self):
        return False


class FakeKeyManager:
    def get_active_key(self) -> bytes:
        return b"K" * 32


class NoOpProtection:
    def harden_operation(self):
        return nullcontext()


def _bench_encrypt(service, payload: bytes, repetitions: int = 2_000) -> int:
    keys = FakeKeyManager()
    started = time.perf_counter_ns()
    for _ in range(repetitions):
        service.encrypt(payload, keys)
    return time.perf_counter_ns() - started


def test_default_constant_time_layer_adds_less_than_ten_percent_overhead():
    payload = os.urandom(1024)
    protected = AESGCMEncryptionService(SideChannelProtection())
    baseline = AESGCMEncryptionService(NoOpProtection())
    protected_samples = []
    baseline_samples = []
    for index in range(7):
        if index % 2:
            baseline_samples.append(_bench_encrypt(baseline, payload))
            protected_samples.append(_bench_encrypt(protected, payload))
        else:
            protected_samples.append(_bench_encrypt(protected, payload))
            baseline_samples.append(_bench_encrypt(baseline, payload))

    ratio = statistics.median(protected_samples) / statistics.median(baseline_samples)
    assert ratio < 1.10


def test_idle_activity_monitor_uses_less_than_one_percent_cpu():
    monitor = ActivityMonitor(
        lambda _reason: None,
        SecurityHardeningConfig(),
        detector=FakeDetector(),
    )
    started_cpu = time.process_time()
    monitor.start()
    time.sleep(1.1)
    monitor.stop()

    assert time.process_time() - started_cpu < 0.011


def test_security_services_start_in_under_three_seconds():
    started = time.perf_counter()
    config = SecurityHardeningConfig()
    protection = SideChannelProtection()
    guard = MemoryGuard()
    monitor = ActivityMonitor(lambda _reason: None, config, detector=FakeDetector())
    panic = PanicMode(config, verify_master_password=lambda _value: True)
    callbacks = TrayCallbacks(*(lambda: None for _ in range(7)))
    tray = SecurityTrayService(callbacks)
    elapsed = time.perf_counter() - started

    assert protection is not None
    assert guard.active_allocations == 0
    assert not monitor.snapshot.monitoring
    assert not panic.activated
    assert not tray.available
    assert elapsed < 3.0


def test_search_evaluates_every_record_before_returning_results():
    class CountingProtection(SideChannelProtection):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def constant_time_contains(self, haystack: str, needle: str) -> bool:
            self.calls += 1
            return super().constant_time_contains(haystack, needle)

    protection = CountingProtection()
    index = VaultSearchIndex(side_channel_protection=protection)
    index.rebuild(
        [
            {"title": "first match", "password": "A"},
            {"title": "middle", "password": "B"},
            {"title": "last match", "password": "C"},
        ]
    )

    results = index.search("match")

    assert [entry["title"] for entry in results] == ["first match", "last match"]
    assert protection.calls == 3


def test_import_export_uses_shared_protected_memory_and_releases_it(tmp_path):
    source_db = Database(tmp_path / "source.db")
    source_db.connect()
    source_keys = KeyManager()
    source_keys.unlock_with_password(source_db, "Sprint7 Source Master!8")
    source_entries = EntryManager(source_db, source_keys)
    source_entries.create_entry(
        {
            "title": "Protected exchange",
            "username": "user@example.com",
            "password": "NeverLeaveThisInAPlainBuffer!7",
        }
    )
    guard = MemoryGuard(lock_memory=True, guard_pages=True)
    exporter = VaultExporter(
        source_entries,
        source_keys,
        confirm_master_password=lambda _value: True,
        memory_guard=guard,
    )
    artifact = exporter.export(
        ExportOptions(),
        master_password="confirmed",
        export_password="Separate Export Password!9",
    )

    target_db = Database(tmp_path / "target.db")
    target_db.connect()
    target_keys = KeyManager()
    target_keys.unlock_with_password(target_db, "Sprint7 Target Master!8")
    target_entries = EntryManager(target_db, target_keys)
    result = VaultImporter(target_entries, memory_guard=guard).import_data(
        artifact.data,
        ImportOptions(),
        password="Separate Export Password!9",
    )

    assert result.created == 1
    assert guard.active_allocations == 0
    assert b"NeverLeaveThisInAPlainBuffer" not in artifact.data
    target_keys.lock()
    source_keys.lock()
    target_db.close()
    source_db.close()
