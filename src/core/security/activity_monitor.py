from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

from .config import ActivitySensitivity, SecurityHardeningConfig
from .platform_security import ActivityDetector, create_activity_detector


@dataclass(frozen=True)
class ActivitySnapshot:
    """Store activity snapshot values."""

    idle_seconds: float
    timeout_seconds: int
    monitoring: bool
    locked: bool
    last_activity_type: str
    system_screen_locked: bool


class ActivityMonitor:
    """Tracks local and system activity without a busy polling loop."""

    _VALID_ACTIVITY: ClassVar[set[str]] = {
        "mouse_move",
        "mouse_click",
        "keyboard",
        "focus",
        "screen_unlock",
    }

    def __init__(
        self,
        lock_callback: Callable[[str], None],
        config: SecurityHardeningConfig,
        *,
        detector: ActivityDetector | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.lock_callback = lock_callback
        self.config = config
        self.detector = detector or create_activity_detector()
        self._clock = clock
        self._last_activity = clock()
        self._last_activity_type = "startup"
        self._monitoring = False
        self._locked = False
        self._screen_locked = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._lock:
            if self._monitoring:
                return
            self._monitoring = True
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="cryptosafe-activity-monitor",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._monitoring = False
            self._stop_event.set()
            thread = self._thread
            self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def update_config(self, config: SecurityHardeningConfig) -> None:
        with self._lock:
            self.config = config
            self._last_activity = self._clock()

    def record_activity(self, activity_type: str) -> bool:
        if activity_type not in self._VALID_ACTIVITY:
            raise ValueError("Unknown activity type.")
        if not self._accepts(activity_type):
            return False
        with self._lock:
            if self._locked:
                return False
            self._last_activity = self._clock()
            self._last_activity_type = activity_type
        return True

    def resume(self) -> None:
        with self._lock:
            self._locked = False
            self._screen_locked = False
            self._last_activity = self._clock()
            self._last_activity_type = "screen_unlock"

    def evaluate_once(self) -> bool:
        """Evaluate lock conditions once and return whether a lock was requested."""
        try:
            system_locked = bool(self.detector.screen_locked())
        except Exception:  # noqa: BLE001 - platform probes must degrade safely
            system_locked = False
        try:
            system_idle = self.detector.idle_seconds()
        except Exception:  # noqa: BLE001 - platform probes must degrade safely
            system_idle = None

        reason = ""
        with self._lock:
            if self._locked:
                return False
            now = self._clock()
            internal_idle = max(0.0, now - self._last_activity)
            if system_idle is not None and system_idle < internal_idle:
                self._last_activity = now - max(0.0, system_idle)
                internal_idle = max(0.0, system_idle)
            self._screen_locked = system_locked
            if system_locked and self.config.lock_on_screen_lock:
                reason = "screen_lock"
            elif internal_idle >= self.config.auto_lock_timeout_seconds:
                reason = "inactivity"
            if reason:
                self._locked = True
        if reason:
            self.lock_callback(reason)
            return True
        return False

    @property
    def snapshot(self) -> ActivitySnapshot:
        with self._lock:
            return ActivitySnapshot(
                idle_seconds=max(0.0, self._clock() - self._last_activity),
                timeout_seconds=self.config.auto_lock_timeout_seconds,
                monitoring=self._monitoring,
                locked=self._locked,
                last_activity_type=self._last_activity_type,
                system_screen_locked=self._screen_locked,
            )

    def _run(self) -> None:
        interval = {
            ActivitySensitivity.LOW: 2.0,
            ActivitySensitivity.MEDIUM: 1.0,
            ActivitySensitivity.HIGH: 0.5,
        }[self.config.activity_sensitivity]
        while not self._stop_event.wait(interval):
            try:
                self.evaluate_once()
            except Exception:  # noqa: BLE001 - monitoring must fail closed in the UI
                self.lock_callback("monitor_failure")
                with self._lock:
                    self._locked = True
                return

    def _accepts(self, activity_type: str) -> bool:
        sensitivity = self.config.activity_sensitivity
        if sensitivity is ActivitySensitivity.HIGH:
            return True
        if sensitivity is ActivitySensitivity.MEDIUM:
            return activity_type != "mouse_move"
        return activity_type in {"mouse_click", "keyboard", "screen_unlock"}

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_args) -> None:
        self.stop()
