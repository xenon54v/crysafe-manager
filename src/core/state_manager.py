from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Optional

@dataclass
class SessionState:
    user: Optional[str] = None
    locked: bool = True

class StateManager:

    def __init__(self, on_auto_lock: Optional[Callable[[], None]] = None) -> None:
        self._session = SessionState()
        self._clipboard_content: Optional[str] = None
        self._clipboard_timer: Optional[threading.Timer] = None
        self._inactivity_timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()
        self._on_auto_lock = on_auto_lock

    def login(self, user: str) -> None:
        with self._lock:
            self._session.user = user
            self._session.locked = False

    def logout(self) -> None:
        with self._lock:
            self._session.user = None
            self._session.locked = True

    def is_locked(self) -> bool:
        with self._lock:
            return self._session.locked

    def set_clipboard(self, value: str, timeout_seconds: int = 10) -> None:
        with self._lock:
            self._clipboard_content = value

            if self._clipboard_timer:
                self._clipboard_timer.cancel()

            self._clipboard_timer = threading.Timer(timeout_seconds, self.clear_clipboard)
            self._clipboard_timer.daemon = True
            self._clipboard_timer.start()

    def get_clipboard(self) -> Optional[str]:
        with self._lock:
            return self._clipboard_content

    def clear_clipboard(self) -> None:
        with self._lock:
            self._clipboard_content = None

    def start_inactivity_timer(self, timeout_seconds: int) -> None:
        with self._lock:
            if self._inactivity_timer:
                self._inactivity_timer.cancel()

            self._inactivity_timer = threading.Timer(timeout_seconds, self._auto_lock)
            self._inactivity_timer.daemon = True
            self._inactivity_timer.start()

    def reset_inactivity_timer(self, timeout_seconds: int) -> None:
        self.start_inactivity_timer(timeout_seconds)

    def stop_timers(self) -> None:
        with self._lock:
            if self._clipboard_timer:
                self._clipboard_timer.cancel()
                self._clipboard_timer = None

            if self._inactivity_timer:
                self._inactivity_timer.cancel()
                self._inactivity_timer = None

    def _auto_lock(self) -> None:
        callback = None

        with self._lock:
            self._session.locked = True
            callback = self._on_auto_lock

        if callback:
            callback()