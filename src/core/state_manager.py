from __future__ import annotations

import hashlib
import hmac
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class SessionState:
    """Store session state values."""

    user: str | None = None
    locked: bool = True


class StateManager:
    """Provide state manager operations."""

    def __init__(self, on_auto_lock: Callable[[], None] | None = None) -> None:
        self._session = SessionState()
        self._inactivity_timer: threading.Timer | None = None
        self._lock = threading.Lock()
        self._on_auto_lock = on_auto_lock
        self._integrity_key = bytearray(os.urandom(32))
        self._session_sequence = 0
        self._integrity_tag = self._calculate_integrity_tag()

    def login(self, user: str) -> None:
        with self._lock:
            self._session.user = user
            self._session.locked = False
            self._session_sequence += 1
            self._integrity_tag = self._calculate_integrity_tag()

    def logout(self) -> None:
        with self._lock:
            self._session.user = None
            self._session.locked = True
            self._session_sequence += 1
            self._integrity_tag = self._calculate_integrity_tag()

    def is_locked(self) -> bool:
        with self._lock:
            return self._session.locked

    def verify_integrity(self) -> bool:
        with self._lock:
            expected = self._calculate_integrity_tag()
            return hmac.compare_digest(expected, self._integrity_tag)

    @property
    def integrity_token(self) -> str:
        with self._lock:
            return self._integrity_tag.hex()

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
            if self._inactivity_timer:
                self._inactivity_timer.cancel()
                self._inactivity_timer = None

    def _auto_lock(self) -> None:
        callback = None

        with self._lock:
            self._session.locked = True
            self._session_sequence += 1
            self._integrity_tag = self._calculate_integrity_tag()
            callback = self._on_auto_lock

        if callback:
            callback()

    def _calculate_integrity_tag(self) -> bytes:
        payload = (
            f"{self._session.user or ''}|{int(self._session.locked)}|"
            f"{self._session_sequence}"
        ).encode()
        return hmac.new(bytes(self._integrity_key), payload, hashlib.sha256).digest()

    def close(self) -> None:
        self.stop_timers()
        with self._lock:
            for index in range(len(self._integrity_key)):
                self._integrity_key[index] = 0
            self._integrity_key.clear()
            self._integrity_tag = b""
