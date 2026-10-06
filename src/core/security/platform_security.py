from __future__ import annotations

import ctypes
import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Protocol

_SAFE_KEY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


class ActivityDetector(Protocol):
    """Define the activity detector interface."""

    def idle_seconds(self) -> float | None: ...

    def screen_locked(self) -> bool: ...


class FallbackActivityDetector:
    """Adapt fallback activity detector behavior to the current platform."""

    def idle_seconds(self) -> float | None:
        return None

    def screen_locked(self) -> bool:
        return False


class WindowsActivityDetector(FallbackActivityDetector):
    """Adapt windows activity detector behavior to the current platform."""

    class _LastInputInfo(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

    def idle_seconds(self) -> float | None:
        try:
            info = self._LastInputInfo()
            info.cbSize = ctypes.sizeof(info)
            if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
                return None
            tick = ctypes.windll.kernel32.GetTickCount64()
            return max(0.0, (tick - info.dwTime) / 1000.0)
        except (AttributeError, OSError, TypeError):
            return None

    def screen_locked(self) -> bool:
        try:
            desktop = ctypes.windll.user32.OpenInputDesktop(0, False, 0x0100)
            if not desktop:
                return True
            ctypes.windll.user32.CloseDesktop(desktop)
            return False
        except (AttributeError, OSError, TypeError):
            return False


class MacOSActivityDetector(FallbackActivityDetector):
    """Measure user inactivity with the macOS Quartz API."""

    def idle_seconds(self) -> float | None:
        try:
            import Quartz

            return float(
                Quartz.CGEventSourceSecondsSinceLastEventType(
                    Quartz.kCGEventSourceStateCombinedSessionState,
                    Quartz.kCGAnyInputEventType,
                )
            )
        except (ImportError, AttributeError, TypeError, ValueError):
            return None

    def screen_locked(self) -> bool:
        try:
            import Quartz

            session = Quartz.CGSessionCopyCurrentDictionary() or {}
            return bool(session.get("CGSSessionScreenIsLocked", False))
        except (ImportError, AttributeError, TypeError):
            return False


class LinuxActivityDetector(FallbackActivityDetector):
    """Adapt linux activity detector behavior to the current platform."""

    def __init__(self) -> None:
        self._xprintidle = (
            shutil.which("xprintidle") if os.environ.get("DISPLAY") else None
        )
        self._last_lock_check = 0.0
        self._cached_locked = False

    def idle_seconds(self) -> float | None:
        if self._xprintidle is None:
            return None
        try:
            result = subprocess.run(
                [self._xprintidle],
                check=True,
                capture_output=True,
                text=True,
                timeout=0.5,
            )
            return max(0.0, float(result.stdout.strip()) / 1000.0)
        except (OSError, subprocess.SubprocessError, ValueError):
            return None

    def screen_locked(self) -> bool:
        now = time.monotonic()
        if now - self._last_lock_check < 5.0:
            return self._cached_locked
        self._last_lock_check = now
        session_id = os.environ.get("XDG_SESSION_ID")
        loginctl = shutil.which("loginctl")
        if not session_id or loginctl is None:
            return False
        try:
            result = subprocess.run(
                [loginctl, "show-session", session_id, "-p", "LockedHint", "--value"],
                check=True,
                capture_output=True,
                text=True,
                timeout=0.75,
            )
            self._cached_locked = result.stdout.strip().casefold() == "yes"
        except (OSError, subprocess.SubprocessError):
            self._cached_locked = False
        return self._cached_locked


class LinuxKernelKeyring:
    """Small adapter for session-scoped Linux kernel keyring entries."""

    def __init__(self, keyctl_path: str | None = None) -> None:
        self.keyctl_path = keyctl_path or shutil.which("keyctl")

    @property
    def available(self) -> bool:
        return bool(self.keyctl_path and os.path.exists("/proc/keys"))

    def save_secret(self, name: str, value: bytes | bytearray) -> str | None:
        if not self.available or not _SAFE_KEY_NAME.fullmatch(name):
            return None
        try:
            result = subprocess.run(
                [self.keyctl_path, "padd", "user", f"cryptosafe:{name}", "@s"],
                input=bytes(value),
                capture_output=True,
                timeout=1.0,
                check=True,
            )
            key_id = result.stdout.decode("ascii", errors="strict").strip()
            return key_id if key_id.isdigit() else None
        except (OSError, UnicodeError, subprocess.SubprocessError):
            return None

    def read_secret(self, key_id: str) -> bytearray | None:
        if not self.available or not key_id.isdigit():
            return None
        try:
            result = subprocess.run(
                [self.keyctl_path, "pipe", key_id],
                capture_output=True,
                timeout=1.0,
                check=True,
            )
            return bytearray(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return None

    def revoke(self, key_id: str) -> bool:
        if not self.available or not key_id.isdigit():
            return False
        try:
            subprocess.run(
                [self.keyctl_path, "revoke", key_id],
                capture_output=True,
                timeout=1.0,
                check=True,
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False


def create_activity_detector(system: str | None = None) -> ActivityDetector:
    """Create the activity detector for the selected operating system."""

    selected = system or platform.system()
    if selected == "Windows":
        return WindowsActivityDetector()
    if selected == "Darwin":
        return MacOSActivityDetector()
    if selected == "Linux":
        return LinuxActivityDetector()
    return FallbackActivityDetector()


@dataclass(frozen=True)
class PlatformCapabilities:
    """Store platform capabilities values."""

    system: str
    memory_lock: bool
    secure_key_store: bool
    secure_desktop: bool
    biometric_unlock: bool
    kernel_keyring: bool
    service_manager: str | None
    mandatory_access_control: tuple[str, ...]


def detect_platform_capabilities(system: str | None = None) -> PlatformCapabilities:
    """Report the security capabilities available on the selected OS."""

    selected = system or platform.system()
    if selected == "Windows":
        return PlatformCapabilities(
            selected,
            True,
            True,
            True,
            hasattr(ctypes, "windll"),
            False,
            None,
            (),
        )
    if selected == "Darwin":
        return PlatformCapabilities(
            selected,
            True,
            True,
            False,
            True,
            False,
            "launchd",
            ("Gatekeeper",),
        )
    if selected == "Linux":
        policies = tuple(
            name
            for name, path in (
                ("SELinux", "/sys/fs/selinux"),
                ("AppArmor", "/sys/module/apparmor"),
            )
            if os.path.exists(path)
        )
        return PlatformCapabilities(
            selected,
            True,
            shutil.which("secret-tool") is not None,
            False,
            False,
            os.path.exists("/proc/keys"),
            "systemd" if shutil.which("systemctl") else None,
            policies,
        )
    return PlatformCapabilities(selected, False, False, False, False, False, None, ())
