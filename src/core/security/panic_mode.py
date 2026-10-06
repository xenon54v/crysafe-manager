from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .config import SecurityHardeningConfig


class PanicInterruptedError(RuntimeError):
    """Raised when panic mode interrupts an in-progress sensitive operation."""


@dataclass(frozen=True)
class PanicResult:
    """Store panic result values."""

    activated: bool
    method: str
    completed_handlers: tuple[str, ...]
    failed_handlers: tuple[str, ...]


class PanicMode:
    """Runs emergency handlers in a fail-secure order and supports recovery."""

    def __init__(
        self,
        config: SecurityHardeningConfig,
        *,
        verify_master_password: Callable[[str], bool],
        audit_callback: Callable[[str, str, dict[str, Any]], None] | None = None,
        capture_state: Callable[[], Any] | None = None,
        restore_state: Callable[[Any], None] | None = None,
    ) -> None:
        self.config = config
        self.verify_master_password = verify_master_password
        self.audit_callback = audit_callback
        self.capture_state = capture_state
        self.restore_state = restore_state
        self._handlers: list[tuple[int, str, Callable[[], None]]] = []
        self._interrupt = threading.Event()
        self._activated = False
        self._saved_state: Any = None
        self._lock = threading.RLock()

    @property
    def activated(self) -> bool:
        with self._lock:
            return self._activated

    @property
    def interrupted(self) -> bool:
        return self._interrupt.is_set()

    def register_handler(
        self, name: str, handler: Callable[[], None], *, priority: int = 100
    ) -> None:
        if not name.strip():
            raise ValueError("Panic handler name must not be empty.")
        with self._lock:
            self._handlers = [item for item in self._handlers if item[1] != name]
            self._handlers.append((priority, name, handler))
            self._handlers.sort(key=lambda item: item[0])

    def unregister_handler(self, name: str) -> None:
        with self._lock:
            self._handlers = [item for item in self._handlers if item[1] != name]

    def activate(self, method: str = "hotkey") -> PanicResult:
        with self._lock:
            if self._activated:
                return PanicResult(False, method, (), ())
            self._activated = True
            self._interrupt.set()
            if self.capture_state is not None:
                try:
                    self._saved_state = self.capture_state()
                except Exception:  # noqa: BLE001 - cleanup must still execute
                    self._saved_state = None
            handlers = tuple(self._handlers)

        self._audit(
            "PANIC_MODE_ACTIVATED",
            "CRITICAL",
            {"method": method, "phase": "started"},
        )

        completed: list[str] = []
        failed: list[str] = []
        for _priority, name, handler in handlers:
            try:
                handler()
                completed.append(name)
            except Exception:  # noqa: BLE001 - one failed handler cannot stop panic
                failed.append(name)
        severity = "CRITICAL" if failed else "WARN"
        self._audit(
            "PANIC_MODE_RESPONSE_COMPLETED",
            severity,
            {"method": method, "completed": completed, "failed": failed},
        )
        return PanicResult(True, method, tuple(completed), tuple(failed))

    def recover(self, master_password: str) -> bool:
        with self._lock:
            if not self._activated:
                return True
        if not self.verify_master_password(master_password):
            self._audit("PANIC_RECOVERY_REJECTED", "WARN", {"reason": "password"})
            return False
        with self._lock:
            saved_state = self._saved_state
            self._saved_state = None
            self._activated = False
            self._interrupt.clear()
        if saved_state is not None and self.restore_state is not None:
            self.restore_state(saved_state)
        self._audit("PANIC_MODE_RECOVERED", "INFO", {})
        return True

    def check_interrupted(self) -> None:
        if self.interrupted:
            raise PanicInterruptedError(
                "Sensitive operation was interrupted by panic mode."
            )

    def update_config(self, config: SecurityHardeningConfig) -> None:
        with self._lock:
            self.config = config

    def _audit(self, event: str, severity: str, details: dict[str, Any]) -> None:
        if self.audit_callback is not None:
            try:
                self.audit_callback(event, severity, details)
            except Exception:  # noqa: BLE001 - audit failure cannot block emergency cleanup
                return


class MouseShakeDetector:
    """Detects alternating horizontal movement inside a short time window."""

    def __init__(
        self,
        callback: Callable[[], None],
        *,
        threshold: int = 5,
        minimum_delta: int = 35,
        window_seconds: float = 1.2,
    ) -> None:
        self.callback = callback
        self.threshold = threshold
        self.minimum_delta = minimum_delta
        self.window_seconds = window_seconds
        self._last_x: int | None = None
        self._last_direction = 0
        self._changes: list[float] = []

    def record(self, x: int, timestamp: float) -> bool:
        if self._last_x is None:
            self._last_x = x
            return False
        delta = x - self._last_x
        self._last_x = x
        if abs(delta) < self.minimum_delta:
            return False
        direction = 1 if delta > 0 else -1
        if self._last_direction and direction != self._last_direction:
            self._changes.append(timestamp)
        self._last_direction = direction
        cutoff = timestamp - self.window_seconds
        self._changes = [value for value in self._changes if value >= cutoff]
        if len(self._changes) >= self.threshold:
            self._changes.clear()
            self.callback()
            return True
        return False
