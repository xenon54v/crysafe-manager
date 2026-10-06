from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum


class SecurityProfile(StrEnum):
    """Represent security profile behavior."""

    STANDARD = "standard"
    ENHANCED = "enhanced"
    PARANOID = "paranoid"


class ActivitySensitivity(StrEnum):
    """Represent activity sensitivity behavior."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DeviceType(StrEnum):
    """Represent device type behavior."""

    DESKTOP = "desktop"
    LAPTOP = "laptop"


@dataclass(frozen=True)
class SecurityHardeningConfig:
    """Validated settings for Sprint 7 security services."""

    profile: SecurityProfile = SecurityProfile.STANDARD
    auto_lock_timeout_seconds: int = 300
    activity_sensitivity: ActivitySensitivity = ActivitySensitivity.MEDIUM
    device_type: DeviceType = DeviceType.DESKTOP
    clear_clipboard_on_lock: bool = True
    hide_sensitive_windows_on_lock: bool = True
    lock_on_screen_lock: bool = True
    minimize_to_tray: bool = True
    start_minimized_to_tray: bool = False
    tray_notifications: bool = True
    panic_hotkey: str = "<Control-Shift-Escape>"
    panic_close_application: bool = False
    panic_fake_error: bool = False
    panic_decoy_command: tuple[str, ...] = ()
    panic_decoy_url: str = ""
    constant_time_enabled: bool = True
    cache_hardening_enabled: bool = True
    algorithmic_noise_enabled: bool = False
    crypto_jitter_max_ms: float = 0.0
    lock_sensitive_memory: bool = True
    guard_pages_enabled: bool = True
    wipe_passes: int = 1
    lazy_load_page_size: int = 250

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile", SecurityProfile(self.profile))
        object.__setattr__(
            self,
            "activity_sensitivity",
            ActivitySensitivity(self.activity_sensitivity),
        )
        object.__setattr__(self, "device_type", DeviceType(self.device_type))
        if not 60 <= self.auto_lock_timeout_seconds <= 8 * 60 * 60:
            raise ValueError("Auto-lock timeout must be between 1 minute and 8 hours.")
        if not self.panic_hotkey.strip():
            raise ValueError("Panic hotkey must not be empty.")
        if not 0.0 <= self.crypto_jitter_max_ms <= 25.0:
            raise ValueError("Cryptographic jitter must be between 0 and 25 ms.")
        if self.wipe_passes not in {1, 2, 3}:
            raise ValueError("Memory wipe passes must be 1, 2, or 3.")
        if not 50 <= self.lazy_load_page_size <= 1000:
            raise ValueError("Lazy-load page size must be between 50 and 1000.")
        mandatory_controls = (
            self.constant_time_enabled,
            self.lock_sensitive_memory,
            self.hide_sensitive_windows_on_lock,
            self.lock_on_screen_lock,
        )
        if not all(mandatory_controls):
            raise ValueError(
                "Constant-time comparison, protected memory, screen locking, and "
                "sensitive-window hiding are mandatory security controls."
            )
        if (
            self.profile in {SecurityProfile.ENHANCED, SecurityProfile.PARANOID}
            and not self.clear_clipboard_on_lock
        ):
            raise ValueError(
                "Enhanced and paranoid profiles require clipboard clearing."
            )
        if self.profile is SecurityProfile.PARANOID:
            required = (
                self.hide_sensitive_windows_on_lock,
                self.lock_on_screen_lock,
                self.constant_time_enabled,
                self.cache_hardening_enabled,
                self.guard_pages_enabled,
            )
            if not all(required):
                raise ValueError(
                    "Paranoid profile cannot disable mandatory hardening controls."
                )
        if self.panic_decoy_url and not self.panic_decoy_url.startswith(
            ("https://", "http://")
        ):
            raise ValueError("Decoy URL must use HTTP or HTTPS.")

    @classmethod
    def for_profile(
        cls,
        profile: SecurityProfile | str,
        device_type: DeviceType | str = DeviceType.DESKTOP,
    ) -> SecurityHardeningConfig:
        selected = SecurityProfile(profile)
        device = DeviceType(device_type)
        if selected is SecurityProfile.STANDARD:
            return cls(
                profile=selected,
                device_type=device,
                auto_lock_timeout_seconds=180 if device is DeviceType.LAPTOP else 300,
            )
        if selected is SecurityProfile.ENHANCED:
            return cls(
                profile=selected,
                device_type=device,
                auto_lock_timeout_seconds=120 if device is DeviceType.LAPTOP else 180,
                activity_sensitivity=ActivitySensitivity.HIGH,
                wipe_passes=2,
                lazy_load_page_size=200,
            )
        return cls(
            profile=selected,
            device_type=device,
            auto_lock_timeout_seconds=60,
            activity_sensitivity=ActivitySensitivity.HIGH,
            algorithmic_noise_enabled=True,
            crypto_jitter_max_ms=2.0,
            wipe_passes=3,
            lazy_load_page_size=100,
        )

    def with_profile(self, profile: SecurityProfile | str) -> SecurityHardeningConfig:
        updated = self.for_profile(profile, self.device_type)
        return replace(
            updated,
            minimize_to_tray=self.minimize_to_tray,
            start_minimized_to_tray=self.start_minimized_to_tray,
            tray_notifications=self.tray_notifications,
            panic_hotkey=self.panic_hotkey,
            panic_close_application=self.panic_close_application,
            panic_fake_error=self.panic_fake_error,
            panic_decoy_command=self.panic_decoy_command,
            panic_decoy_url=self.panic_decoy_url,
        )

    def changes_from(self, previous: SecurityHardeningConfig) -> tuple[str, ...]:
        labels = {
            "auto_lock_timeout_seconds": "Auto-lock timeout",
            "activity_sensitivity": "Activity sensitivity",
            "clear_clipboard_on_lock": "Clipboard clearing",
            "lock_on_screen_lock": "Screen-lock response",
            "constant_time_enabled": "Constant-time comparisons",
            "algorithmic_noise_enabled": "Algorithmic noise",
            "crypto_jitter_max_ms": "Cryptographic jitter",
            "wipe_passes": "Memory wipe passes",
            "lazy_load_page_size": "Vault page size",
        }
        changed = []
        for field_name, label in labels.items():
            before = getattr(previous, field_name)
            after = getattr(self, field_name)
            if before != after:
                changed.append(f"{label}: {before} -> {after}")
        return tuple(changed)
