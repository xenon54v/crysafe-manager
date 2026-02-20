from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class SessionState:
    user: Optional[str] = None
    locked: bool = True


class StateManager:
    """
    Centralized application state (CFG-1).
    Tracks:
      - user session (locked/unlocked)
      - clipboard placeholder
      - inactivity timer (future auto-lock)
    """

    def __init__(self) -> None:
        self._session = SessionState()
        self._clipboard_content: Optional[str] = None
        self._clipboard_timer: Optional[threading.Timer] = None
        self._inactivity_timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

    # -------- Session management --------

    def login(self, user: str) -> None:
        with self._lock:
            self._session.user = user
            self._session.locked = False

    def logout(self) -> None:
        with self._lock:
            self._session.user = None
            self._session.locked = True

    def is_locked(self) -> bool:
        return self._session.locked

    # -------- Clipboard placeholder --------

    def set_clipboard(self, value: str, timeout_seconds: int = 10) -> None:
        with self._lock:
            self._clipboard_content = value

            if self._clipboard_timer:
                self._clipboard_timer.cancel()

            self._clipboard_timer = threading.Timer(timeout_seconds, self.clear_clipboard)
            self._clipboard_timer.start()

    def get_clipboard(self) -> Optional[str]:
        return self._clipboard_content

    def clear_clipboard(self) -> None:
        with self._lock:
            self._clipboard_content = None

    # -------- Inactivity placeholder --------

    def start_inactivity_timer(self, timeout_seconds: int) -> None:
        with self._lock:
            if self._inactivity_timer:
                self._inactivity_timer.cancel()

            self._inactivity_timer = threading.Timer(timeout_seconds, self._auto_lock)
            self._inactivity_timer.start()

    def _auto_lock(self) -> None:
        with self._lock:
            self._session.locked = True
