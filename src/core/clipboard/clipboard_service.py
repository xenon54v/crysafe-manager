from __future__ import annotations

import atexit
import math
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

from src.core.events import ClipboardCleared, ClipboardCopied, EventBus, now_utc

from .platform_adapter import ClipboardAdapterError, PlatformClipboardAdapter
from .secure_memory import SecureBuffer


class ClipboardType(str, Enum):
    TEXT = "text"
    USERNAME = "username"
    PASSWORD = "password"
    TOTP = "totp"
    ENCRYPTED_BLOB = "encrypted_blob"


class SecurityLevel(str, Enum):
    BASIC = "basic"
    ADVANCED = "advanced"
    PARANOID = "paranoid"


class ClipboardState(str, Enum):
    IDLE = "idle"
    ACTIVE = "active"
    WARNING = "warning"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass(frozen=True)
class ClipboardConfig:
    timeout_seconds: int | None = 30
    notifications_enabled: bool = True
    security_level: SecurityLevel = SecurityLevel.BASIC
    application_whitelist: tuple[str, ...] = ()
    block_after_suspicious_access: bool = False
    ephemeral_mode: bool = False

    def __post_init__(self) -> None:
        if self.timeout_seconds is not None and not 5 <= self.timeout_seconds <= 300:
            raise ValueError("Clipboard timeout must be between 5 and 300 seconds.")
        if not isinstance(self.security_level, SecurityLevel):
            object.__setattr__(
                self, "security_level", SecurityLevel(self.security_level)
            )
        clean_apps = tuple(
            item.strip() for item in self.application_whitelist if item and item.strip()
        )
        object.__setattr__(self, "application_whitelist", clean_apps)

    @classmethod
    def profile(cls, name: str) -> ClipboardConfig:
        profiles = {
            "standard": cls(30, True, SecurityLevel.BASIC),
            "secure": cls(15, True, SecurityLevel.ADVANCED, (), True),
            "public computer": cls(5, True, SecurityLevel.PARANOID, (), True, True),
        }
        try:
            return profiles[name.strip().casefold()]
        except KeyError as exc:
            raise ValueError("Unknown clipboard profile.") from exc


@dataclass(frozen=True)
class ClipboardSnapshot:
    state: ClipboardState
    entry_id: str | None = None
    source: str = ""
    data_type: ClipboardType | None = None
    masked_preview: str = ""
    expires_at_monotonic: float | None = None
    message: str = ""
    adapter_name: str = ""

    def remaining_seconds(self, now: float | None = None) -> int | None:
        if self.expires_at_monotonic is None:
            return None
        current = time.monotonic() if now is None else now
        return max(0, math.ceil(self.expires_at_monotonic - current))


class ClipboardObserver(Protocol):
    def clipboard_state_changed(self, snapshot: ClipboardSnapshot) -> None: ...


TimerFactory = Callable[[float, Callable[[], None]], threading.Timer]
AuditCallback = Callable[[str, str | None, str], None]


class ClipboardService:
    MAX_VALUE_BYTES = 1024 * 1024

    def __init__(
        self,
        adapter: PlatformClipboardAdapter,
        event_bus: EventBus | None = None,
        is_vault_unlocked: Callable[[], bool] | None = None,
        config: ClipboardConfig | None = None,
        audit_callback: AuditCallback | None = None,
        clock: Callable[[], float] = time.monotonic,
        timer_factory: TimerFactory = threading.Timer,
    ) -> None:
        self.adapter = adapter
        self.event_bus = event_bus
        self.is_vault_unlocked = is_vault_unlocked or (lambda: False)
        self.config = config or ClipboardConfig()
        self.audit_callback = audit_callback
        self._clock = clock
        self._timer_factory = timer_factory
        self._lock = threading.RLock()
        self._buffer: SecureBuffer | None = None
        self._clear_timer: threading.Timer | None = None
        self._warning_timer: threading.Timer | None = None
        self._observers: list[
            ClipboardObserver | Callable[[ClipboardSnapshot], None]
        ] = []
        self._blocked = False
        self._signal_handlers: dict[int, object] = {}
        self._snapshot = ClipboardSnapshot(
            ClipboardState.IDLE, adapter_name=self.adapter.name
        )
        atexit.register(self.close)

    @property
    def snapshot(self) -> ClipboardSnapshot:
        with self._lock:
            return self._snapshot

    @property
    def has_sensitive_value(self) -> bool:
        with self._lock:
            return self._buffer is not None and not self._buffer.cleared

    def add_observer(
        self, observer: ClipboardObserver | Callable[[ClipboardSnapshot], None]
    ) -> None:
        with self._lock:
            if observer not in self._observers:
                self._observers.append(observer)

    def remove_observer(
        self, observer: ClipboardObserver | Callable[[ClipboardSnapshot], None]
    ) -> None:
        with self._lock:
            if observer in self._observers:
                self._observers.remove(observer)

    def copy_text(
        self,
        value: str,
        *,
        entry_id: str,
        field: str,
        source: str = "",
        data_type: ClipboardType | str = ClipboardType.TEXT,
    ) -> ClipboardSnapshot:
        if not self.is_vault_unlocked():
            raise PermissionError("Unlock the vault before copying data.")
        if self._blocked:
            raise PermissionError(
                "Clipboard copying is blocked after a security event."
            )

        value = self._validate_value(value)
        item_type = ClipboardType(data_type)
        entry_id = self._validate_identifier(entry_id)
        field = self._validate_identifier(field)
        source = self._sanitize_label(source)
        new_buffer = SecureBuffer(value)

        with self._lock:
            self._discard_current_locked(
                clear_platform=True, reason="replaced", publish=False
            )
            try:
                self.adapter.copy_text(value)
            except ClipboardAdapterError:
                new_buffer.clear()
                self._set_error_locked(
                    "Clipboard copy failed. The value was not retained."
                )
                self._audit("clipboard_error", entry_id, "operation=copy")
                snapshot = self._snapshot
            else:
                self._buffer = new_buffer
                deadline = (
                    None
                    if self.config.timeout_seconds is None
                    else self._clock() + self.config.timeout_seconds
                )
                self._snapshot = ClipboardSnapshot(
                    ClipboardState.ACTIVE,
                    entry_id=entry_id,
                    source=source,
                    data_type=item_type,
                    masked_preview=self._mask_preview(value),
                    expires_at_monotonic=deadline,
                    message="Copied to secure clipboard.",
                    adapter_name=self.adapter.name,
                )
                self._schedule_timers_locked()
                self._audit(
                    "clipboard_copy", entry_id, f"field={field};type={item_type.value}"
                )
                self._publish(
                    ClipboardCopied("ClipboardCopied", now_utc(), entry_id, field)
                )
                snapshot = self._snapshot

        self._notify(snapshot)
        if snapshot.state is ClipboardState.ERROR:
            raise ClipboardAdapterError(snapshot.message)
        return snapshot

    def clear(self, reason: str = "manual") -> bool:
        reason = self._sanitize_label(reason) or "manual"
        with self._lock:
            entry_id = self._snapshot.entry_id
            had_value = self._buffer is not None
            clear_ok = self._discard_current_locked(
                clear_platform=True, reason=reason, publish=had_value
            )
            snapshot = self._snapshot
        self._audit(
            "clipboard_clear", entry_id, f"reason={reason};success={int(clear_ok)}"
        )
        self._notify(snapshot)
        return clear_ok

    def external_content_changed(self) -> None:
        with self._lock:
            if self._buffer is None:
                return
            entry_id = self._snapshot.entry_id
            self._discard_current_locked(
                clear_platform=False, reason="external_change", publish=True
            )
            self._snapshot = replace(
                self._snapshot,
                state=ClipboardState.WARNING,
                message="Clipboard content was changed by another application.",
            )
            snapshot = self._snapshot
        self._audit("clipboard_security", entry_id, "event=external_change")
        self._notify(snapshot)

    def report_external_access(self, application: str = "unknown") -> None:
        application = self._sanitize_label(application) or "unknown"
        trusted = {item.casefold() for item in self.config.application_whitelist}
        if application.casefold() in trusted:
            self._audit(
                "clipboard_security",
                self.snapshot.entry_id,
                f"event=external_access;application={application};result=allowed",
            )
            return
        with self._lock:
            if self._buffer is None:
                return
            entry_id = self._snapshot.entry_id
            remaining = self._snapshot.remaining_seconds(self._clock())
            if remaining is None or remaining > 5:
                self._cancel_timer(self._clear_timer)
                self._clear_timer = self._make_timer(5.0, self._timer_clear)
                deadline = self._clock() + 5.0
            else:
                deadline = self._snapshot.expires_at_monotonic
            self._snapshot = replace(
                self._snapshot,
                state=ClipboardState.WARNING,
                expires_at_monotonic=deadline,
                message="External clipboard access detected. Clearing was accelerated.",
            )
            if (
                self.config.block_after_suspicious_access
                or self.config.security_level is SecurityLevel.PARANOID
            ):
                self._blocked = True
            snapshot = self._snapshot
        self._audit(
            "clipboard_security",
            entry_id,
            f"event=external_access;application={application}",
        )
        self._notify(snapshot)

    def reveal_current(self, authenticator: Callable[[], bool]) -> str:
        if not authenticator():
            raise PermissionError("Clipboard preview authentication failed.")
        with self._lock:
            if self._buffer is None:
                raise RuntimeError("Clipboard does not contain an active value.")
            self._audit(
                "clipboard_preview", self._snapshot.entry_id, "result=authenticated"
            )
            return self._buffer.reveal_text()

    def update_config(self, config: ClipboardConfig) -> None:
        with self._lock:
            self.config = config
            if self._buffer is not None:
                self._snapshot = replace(
                    self._snapshot,
                    expires_at_monotonic=(
                        None
                        if config.timeout_seconds is None
                        else self._clock() + config.timeout_seconds
                    ),
                )
                self._schedule_timers_locked()
            snapshot = self._snapshot
        self._notify(snapshot)

    def unblock(self) -> None:
        with self._lock:
            self._blocked = False
            if self._snapshot.state is ClipboardState.BLOCKED:
                self._snapshot = replace(self._snapshot, state=ClipboardState.IDLE)
            snapshot = self._snapshot
        self._notify(snapshot)

    def replace_adapter(self, adapter: PlatformClipboardAdapter) -> None:
        self.clear("adapter_change")
        with self._lock:
            self.adapter = adapter
            self._snapshot = replace(self._snapshot, adapter_name=adapter.name)
            snapshot = self._snapshot
        self._notify(snapshot)

    def close(self) -> None:
        try:
            self.clear("app_close")
        except Exception:  # noqa: BLE001 - shutdown cleanup must remain best-effort
            return
        finally:
            self._restore_signal_handlers()

    def install_signal_cleanup(self) -> None:
        """Clear the clipboard on cooperative SIGINT/SIGTERM process shutdown."""
        if threading.current_thread() is not threading.main_thread():
            return
        for signal_number in (signal.SIGINT, signal.SIGTERM):
            if signal_number in self._signal_handlers:
                continue
            previous = signal.getsignal(signal_number)
            self._signal_handlers[signal_number] = previous

            def handle(signum, frame, old_handler=previous):
                self.clear("process_signal")
                if callable(old_handler):
                    old_handler(signum, frame)
                if old_handler != signal.SIG_IGN:
                    raise SystemExit(128 + signum)

            signal.signal(signal_number, handle)

    def _restore_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return
        for signal_number, previous in tuple(self._signal_handlers.items()):
            signal.signal(signal_number, previous)
        self._signal_handlers.clear()

    def _schedule_timers_locked(self) -> None:
        self._cancel_timers_locked()
        timeout = self.config.timeout_seconds
        if timeout is None:
            return
        if timeout > 5:
            self._warning_timer = self._make_timer(timeout - 5.0, self._timer_warning)
        self._clear_timer = self._make_timer(float(timeout), self._timer_clear)

    def _make_timer(
        self, delay: float, callback: Callable[[], None]
    ) -> threading.Timer:
        timer = self._timer_factory(delay, callback)
        timer.daemon = True
        timer.start()
        return timer

    def _timer_warning(self) -> None:
        with self._lock:
            if self._buffer is None:
                return
            self._snapshot = replace(
                self._snapshot,
                state=ClipboardState.WARNING,
                message="Clipboard will be cleared in 5 seconds.",
            )
            snapshot = self._snapshot
        self._notify(snapshot)

    def _timer_clear(self) -> None:
        self.clear("timer")

    def _discard_current_locked(
        self, *, clear_platform: bool, reason: str, publish: bool
    ) -> bool:
        self._cancel_timers_locked()
        clear_ok = True
        if clear_platform:
            try:
                self.adapter.clear()
            except ClipboardAdapterError:
                clear_ok = False
        if self._buffer is not None:
            self._buffer.clear()
            self._buffer = None
        state = ClipboardState.BLOCKED if self._blocked else ClipboardState.IDLE
        message = (
            "Clipboard cleared."
            if clear_ok
            else "Sensitive memory was cleared, but the system clipboard could not be cleared."
        )
        self._snapshot = ClipboardSnapshot(
            ClipboardState.ERROR if not clear_ok else state,
            message=message,
            adapter_name=self.adapter.name,
        )
        if publish:
            self._publish(ClipboardCleared("ClipboardCleared", now_utc(), reason))
        return clear_ok

    def _set_error_locked(self, message: str) -> None:
        self._snapshot = ClipboardSnapshot(
            ClipboardState.ERROR, message=message, adapter_name=self.adapter.name
        )

    def _cancel_timers_locked(self) -> None:
        self._cancel_timer(self._clear_timer)
        self._cancel_timer(self._warning_timer)
        self._clear_timer = None
        self._warning_timer = None

    @staticmethod
    def _cancel_timer(timer: threading.Timer | None) -> None:
        if timer is not None:
            timer.cancel()

    def _publish(self, event) -> None:
        if self.event_bus is not None:
            try:
                self.event_bus.publish(event)
            except RuntimeError:
                self._audit(
                    "clipboard_error",
                    getattr(event, "entry_id", None),
                    "operation=event",
                )

    def _audit(self, action: str, entry_id: str | None, details: str) -> None:
        if self.audit_callback is not None:
            self.audit_callback(action, entry_id, details)

    def _notify(self, snapshot: ClipboardSnapshot) -> None:
        with self._lock:
            observers = tuple(self._observers)
        for observer in observers:
            try:
                callback = getattr(observer, "clipboard_state_changed", observer)
                callback(snapshot)
            except Exception:  # noqa: BLE001 - one faulty observer must not stop cleanup
                self._audit("clipboard_error", snapshot.entry_id, "operation=observer")

    @classmethod
    def _validate_value(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("Clipboard value must be text.")
        if not value:
            raise ValueError("Clipboard value must not be empty.")
        encoded = value.encode("utf-8")
        if len(encoded) > cls.MAX_VALUE_BYTES:
            raise ValueError("Clipboard value is too large.")
        if "\x00" in value:
            raise ValueError("Clipboard value contains an unsupported null character.")
        return value

    @staticmethod
    def _validate_identifier(value: str) -> str:
        value = str(value).strip()
        if not value or len(value) > 128 or any(char in value for char in "\r\n\x00"):
            raise ValueError("Clipboard metadata is invalid.")
        return value

    @staticmethod
    def _sanitize_label(value: str) -> str:
        return " ".join(str(value).replace("\x00", "").split())[:160]

    @staticmethod
    def _mask_preview(value: str) -> str:
        prefix = value[:3] if len(value) > 3 else value[:1]
        return f"{prefix}••••"
