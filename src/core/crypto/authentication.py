from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class AuthSession:
    username: str = 'local_user'
    is_authenticated: bool = False
    login_time: Optional[datetime] = None
    last_activity_time: Optional[datetime] = None
    failed_attempt_count: int = 0

class AuthenticationService:
    def __init__(self) -> None:
        self._session = AuthSession()

    def login(self, username: str = 'local_user') -> AuthSession:
        now = datetime.now()

        self._session = AuthSession(
            username=username,
            is_authenticated=True,
            login_time=now,
            last_activity_time=now,
            failed_attempt_count=0,
        )

        return self._session

    def logout(self) -> None:
        self._session = AuthSession()

    def register_failed_attempt(self) -> int:
        self._session.failed_attempt_count += 1
        self._session.last_activity_time = datetime.now()
        return self._session.failed_attempt_count

    def reset_failed_attempts(self) -> None:
        self._session.failed_attempt_count = 0

    def get_backoff_delay(self) -> int:
        attempts = self._session.failed_attempt_count

        if attempts <= 2:
            return 1

        if attempts <= 4:
            return 5

        return 30

    def apply_backoff_delay(self) -> None:
        delay = self.get_backoff_delay()
        time.sleep(delay)

    def touch_activity(self) -> None:
        self._session.last_activity_time = datetime.now()

    @property
    def session(self) -> AuthSession:
        return self._session

    def is_authenticated(self) -> bool:
        return self._session.is_authenticated