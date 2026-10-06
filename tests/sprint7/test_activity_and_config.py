from __future__ import annotations

import pytest

from src.core.security import (
    ActivityMonitor,
    ActivitySensitivity,
    DeviceType,
    SecurityHardeningConfig,
    SecurityProfile,
)
from src.core.state_manager import StateManager
from src.database.db import Database
from src.database.settings_repo import SettingsRepository, SettingsRepositoryError


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class FakeDetector:
    def __init__(self) -> None:
        self.locked = False
        self.idle: float | None = None

    def idle_seconds(self) -> float | None:
        return self.idle

    def screen_locked(self) -> bool:
        return self.locked


class FakeKeyManager:
    def get_active_key(self) -> bytes:
        return b"S" * 32


def test_twenty_four_hour_activity_simulation_locks_once_and_recovers():
    clock = FakeClock()
    detector = FakeDetector()
    locks: list[str] = []
    config = SecurityHardeningConfig(auto_lock_timeout_seconds=300)
    monitor = ActivityMonitor(locks.append, config, detector=detector, clock=clock)
    recovered = False

    for minute in range(24 * 60):
        clock.advance(60)
        if minute < 8 * 60 and minute % 4 == 0 or recovered and minute % 4 == 0:
            monitor.record_activity("keyboard")
        if monitor.evaluate_once() and not recovered:
            monitor.resume()
            recovered = True

    assert locks == ["inactivity"]
    assert recovered
    assert not monitor.snapshot.locked


def test_activity_sensitivity_and_screen_lock_policy():
    clock = FakeClock()
    detector = FakeDetector()
    locks: list[str] = []
    config = SecurityHardeningConfig(
        activity_sensitivity=ActivitySensitivity.LOW,
        auto_lock_timeout_seconds=600,
    )
    monitor = ActivityMonitor(locks.append, config, detector=detector, clock=clock)

    assert not monitor.record_activity("mouse_move")
    assert monitor.record_activity("keyboard")
    detector.locked = True
    assert monitor.evaluate_once()
    assert locks == ["screen_lock"]


def test_security_profiles_have_device_specific_secure_defaults():
    standard_desktop = SecurityHardeningConfig.for_profile(
        SecurityProfile.STANDARD, DeviceType.DESKTOP
    )
    standard_laptop = SecurityHardeningConfig.for_profile(
        SecurityProfile.STANDARD, DeviceType.LAPTOP
    )
    paranoid = SecurityHardeningConfig.for_profile(SecurityProfile.PARANOID)

    assert (
        standard_laptop.auto_lock_timeout_seconds
        < standard_desktop.auto_lock_timeout_seconds
    )
    assert paranoid.algorithmic_noise_enabled
    assert paranoid.wipe_passes == 3
    assert paranoid.changes_from(standard_desktop)


def test_configuration_rejects_insecure_combinations():
    with pytest.raises(ValueError):
        SecurityHardeningConfig(
            profile=SecurityProfile.ENHANCED,
            clear_clipboard_on_lock=False,
        )
    with pytest.raises(ValueError):
        SecurityHardeningConfig(
            profile=SecurityProfile.PARANOID,
            guard_pages_enabled=False,
        )
    with pytest.raises(ValueError):
        SecurityHardeningConfig(auto_lock_timeout_seconds=59)
    with pytest.raises(ValueError):
        SecurityHardeningConfig(constant_time_enabled=False)


def test_security_settings_are_encrypted_and_transactionally_persisted(tmp_path):
    db = Database(tmp_path / "security-settings.db")
    db.connect()
    repository = SettingsRepository(db, FakeKeyManager())
    expected = SecurityHardeningConfig.for_profile(
        SecurityProfile.ENHANCED, DeviceType.LAPTOP
    )

    repository.save_security_config(expected)
    row = db.execute(
        "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?;",
        (SettingsRepository.SECURITY_KEY,),
    ).fetchone()

    assert repository.load_security_config() == expected
    assert row["encrypted"] == 1
    assert b"enhanced" not in bytes(row["setting_value"])
    db.close()


def test_profile_change_rolls_back_when_mirrored_setting_fails(tmp_path):
    db = Database(tmp_path / "security-rollback.db")
    db.connect()
    repository = SettingsRepository(db, FakeKeyManager())
    original = SecurityHardeningConfig.for_profile(SecurityProfile.STANDARD)
    repository.save_security_config(original)
    db.execute(
        """
        CREATE TRIGGER reject_auto_lock_update
        BEFORE UPDATE ON settings
        WHEN NEW.setting_key = 'auto_lock_timeout'
        BEGIN
            SELECT RAISE(ABORT, 'test failure');
        END;
        """
    )

    with pytest.raises(SettingsRepositoryError):
        repository.save_security_config(
            SecurityHardeningConfig.for_profile(SecurityProfile.ENHANCED)
        )

    assert repository.load_security_config() == original
    db.close()


def test_session_integrity_detects_in_memory_state_tampering():
    manager = StateManager()
    manager.login("local_user")
    token = manager.integrity_token

    manager._session.user = "modified"

    assert manager.integrity_token == token
    assert not manager.verify_integrity()
    manager.close()
