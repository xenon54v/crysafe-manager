from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

@dataclass
class AuthSession:
    username: str = 'local_user'
    is_authenticated: bool = False
    login_time: datetime | None = None

class AuthenticationService:
    def __init__(self) -> None:
        self._session = AuthSession()

    def login(self, username: str = 'local_user') -> AuthSession:
        self._session = AuthSession(
            username=username,
            is_authenticated=True,
            login_time=datetime.now()
        )
        return self._session

    def logout(self) -> None:
        self._session = AuthSession()

    @property
    def session(self) -> AuthSession:
        return self._session
    def is_authenticated(self) -> bool:
        return self._session.is_authenticated