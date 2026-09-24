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
    name: str
    timestamp: datetime


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class EntryAdded(Event):
    """Legacy Sprint 1 event retained for compatibility."""

    entry_id: int | str
    title: str


@dataclass(frozen=True)
class EntryCreated(Event):
    entry_id: str


@dataclass(frozen=True)
class EntryUpdated(Event):
    entry_id: str


@dataclass(frozen=True)
class EntryDeleted(Event):
    entry_id: str


@dataclass(frozen=True)
class UserLoggedIn(Event):
    user: str


@dataclass(frozen=True)
class UserLoggedOut(Event):
    user: str


@dataclass(frozen=True)
class ClipboardCopied(Event):
    entry_id: str
    field: str


@dataclass(frozen=True)
class ClipboardCleared(Event):
    reason: str = "timer"


@dataclass(frozen=True)
class SearchPerformed(Event):
    query: str
    result_count: int


@dataclass(frozen=True)
class AuthenticationFailed(Event):
    user: str
    attempt_count: int
    source_address: str = "local"


@dataclass(frozen=True)
class MasterPasswordChanged(Event):
    user: str


@dataclass(frozen=True)
class VaultAccessed(Event):
    operation: str
    entry_id: str | None = None


@dataclass(frozen=True)
class SystemActivity(Event):
    event_type: str
    severity: str = "INFO"
    details: dict[str, Any] | None = None


@dataclass(frozen=True)
class ConfigurationChanged(Event):
    setting_name: str


@dataclass(frozen=True)
class SecurityAlert(Event):
    event_type: str
    severity: str
    source: str
    details: dict[str, Any] | None = None


Handler = Callable[[Event], Any]


class EventBus:
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
