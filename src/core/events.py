from __future__ import annotations

import asyncio
import inspect
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Event:
    """Represent event behavior."""

    name: str
    timestamp: datetime


def now_utc() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class EntryAdded(Event):
    """Legacy Sprint 1 event retained for compatibility."""

    entry_id: int | str
    title: str


@dataclass(frozen=True)
class EntryCreated(Event):
    """Describe the entry created event."""

    entry_id: str


@dataclass(frozen=True)
class EntryUpdated(Event):
    """Describe the entry updated event."""

    entry_id: str


@dataclass(frozen=True)
class EntryDeleted(Event):
    """Describe the entry deleted event."""

    entry_id: str


@dataclass(frozen=True)
class UserLoggedIn(Event):
    """Describe the user logged in event."""

    user: str


@dataclass(frozen=True)
class UserLoggedOut(Event):
    """Describe the user logged out event."""

    user: str


@dataclass(frozen=True)
class ClipboardCopied(Event):
    """Describe the clipboard copied event."""

    entry_id: str
    field: str


@dataclass(frozen=True)
class ClipboardCleared(Event):
    """Describe the clipboard cleared event."""

    reason: str = "timer"


@dataclass(frozen=True)
class SearchPerformed(Event):
    """Describe the search performed event."""

    query: str
    result_count: int


@dataclass(frozen=True)
class AuthenticationFailed(Event):
    """Describe the authentication failed event."""

    user: str
    attempt_count: int
    source_address: str = "local"


@dataclass(frozen=True)
class MasterPasswordChanged(Event):
    """Describe the master password changed event."""

    user: str


@dataclass(frozen=True)
class VaultAccessed(Event):
    """Describe the vault accessed event."""

    operation: str
    entry_id: str | None = None


@dataclass(frozen=True)
class SystemActivity(Event):
    """Describe the system activity event."""

    event_type: str
    severity: str = "INFO"
    details: dict[str, Any] | None = None


@dataclass(frozen=True)
class ConfigurationChanged(Event):
    """Describe the configuration changed event."""

    setting_name: str


@dataclass(frozen=True)
class SecurityAlert(Event):
    """Describe the security alert event."""

    event_type: str
    severity: str
    source: str
    details: dict[str, Any] | None = None


Handler = Callable[[Event], Any]


class EventBus:
    """Represent event bus behavior."""

    def __init__(self) -> None:
        self._subscribers: defaultdict[type[Event], list[Handler]] = defaultdict(list)

    def subscribe(self, event_type: type[Event], handler: Handler) -> None:
        if handler not in self._subscribers[event_type]:
            self._subscribers[event_type].append(handler)

    def unsubscribe(self, event_type: type[Event], handler: Handler) -> None:
        if handler in self._subscribers[event_type]:
            self._subscribers[event_type].remove(handler)

    def publish(self, event: Event) -> None:
        for handler in tuple(self._subscribers[type(event)]):
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    raise RuntimeError("Async handler used in sync publish().")
            except Exception as exc:
                raise RuntimeError("Event handler failed.") from exc

    async def publish_async(self, event: Event) -> None:
        tasks = []
        for handler in tuple(self._subscribers[type(event)]):
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    tasks.append(result)
            except Exception as exc:
                raise RuntimeError("Event handler failed.") from exc

        if tasks:
            await asyncio.gather(*tasks)
