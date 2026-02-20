from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, DefaultDict, Type
from collections import defaultdict
import asyncio
import inspect


# ---------------- Base Event ----------------

@dataclass(frozen=True)
class Event:
    name: str
    timestamp: datetime


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------- Concrete Events ----------------

@dataclass(frozen=True)
class EntryAdded(Event):
    entry_id: int
    title: str


@dataclass(frozen=True)
class EntryUpdated(Event):
    entry_id: int
    title: str


@dataclass(frozen=True)
class EntryDeleted(Event):
    entry_id: int


@dataclass(frozen=True)
class UserLoggedIn(Event):
    user: str


@dataclass(frozen=True)
class UserLoggedOut(Event):
    user: str


@dataclass(frozen=True)
class ClipboardCopied(Event):
    entry_id: int


@dataclass(frozen=True)
class ClipboardCleared(Event):
    reason: str = "timer"


Handler = Callable[[Event], Any]


# ---------------- Event Bus ----------------

class EventBus:
    def __init__(self) -> None:
        self._subscribers: DefaultDict[Type[Event], list[Handler]] = defaultdict(list)

    def subscribe(self, event_type: Type[Event], handler: Handler) -> None:
        if handler not in self._subscribers[event_type]:
            self._subscribers[event_type].append(handler)

    def unsubscribe(self, event_type: Type[Event], handler: Handler) -> None:
        if handler in self._subscribers[event_type]:
            self._subscribers[event_type].remove(handler)

    def publish(self, event: Event) -> None:
        for handler in list(self._subscribers[type(event)]):
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    raise RuntimeError("Async handler used in sync publish()")
            except Exception:
                raise RuntimeError("Event handler failed")

    async def publish_async(self, event: Event) -> None:
        tasks = []
        for handler in list(self._subscribers[type(event)]):
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    tasks.append(result)
            except Exception:
                raise RuntimeError("Event handler failed")

        if tasks:
            await asyncio.gather(*tasks)
