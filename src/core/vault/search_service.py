from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from difflib import SequenceMatcher
from typing import Any

from src.core.events import EventBus, SearchPerformed, now_utc
from src.core.vault.password_generator import PasswordStrengthAnalyzer


@dataclass(frozen=True)
class SearchFilters:
    category: str = ""
    tag: str = ""
    updated_from: datetime | None = None
    updated_to: datetime | None = None
    minimum_strength: int | None = None


@dataclass(frozen=True)
class _SearchRecord:
    entry: dict[str, Any]
    fields: dict[str, str]
    all_text: str


class VaultSearchIndex:
    """Session-only application index for the entries currently shown in the GUI."""

    FIELD_PATTERN = re.compile(
        r'\b(title|username|url|notes|category|tag|tags):(?:"([^"]*)"|(\S+))',
        re.IGNORECASE,
    )

    def __init__(
        self,
        event_bus: EventBus | None = None,
        strength_analyzer: PasswordStrengthAnalyzer | None = None,
    ) -> None:
        self._records: list[_SearchRecord] = []
        self._history: deque[str] = deque(maxlen=10)
        self._event_bus = event_bus
        self._strength_analyzer = strength_analyzer or PasswordStrengthAnalyzer()

    def rebuild(self, entries: Iterable[dict[str, Any]]) -> None:
        self.clear()
        for entry in entries:
            tags = entry.get("tags", [])
            if isinstance(tags, str):
                tags = [part.strip() for part in tags.split(",") if part.strip()]
            fields = {
                "title": self._normalize(entry.get("title", "")),
                "username": self._normalize(entry.get("username", "")),
                "url": self._normalize(entry.get("url", "")),
                "notes": self._normalize(entry.get("notes", "")),
                "category": self._normalize(entry.get("category", "")),
                "tags": self._normalize(" ".join(str(tag) for tag in tags)),
            }
            self._records.append(
                _SearchRecord(entry, fields, " ".join(fields.values()))
            )

    def clear(self) -> None:
        self._records.clear()

    def clear_history(self) -> None:
        self._history.clear()

    @property
    def history(self) -> tuple[str, ...]:
        return tuple(self._history)

    def search(
        self,
        query: str = "",
        filters: SearchFilters | None = None,
    ) -> list[dict[str, Any]]:
        filters = filters or SearchFilters()
        field_terms, general_terms = self._parse_query(query)
        results = [
            record.entry
            for record in self._records
            if self._matches_terms(record, field_terms, general_terms)
            and self._matches_filters(record.entry, filters)
        ]

        normalized_query = query.strip()
        if normalized_query:
            if normalized_query in self._history:
                self._history.remove(normalized_query)
            self._history.append(normalized_query)

        if self._event_bus is not None:
            self._event_bus.publish(
                SearchPerformed(
                    "SearchPerformed", now_utc(), normalized_query, len(results)
                )
            )
        return results

    def _matches_terms(
        self,
        record: _SearchRecord,
        field_terms: list[tuple[str, str]],
        general_terms: list[str],
    ) -> bool:
        for field, term in field_terms:
            mapped_field = "tags" if field in {"tag", "tags"} else field
            if not self._matches_text(record.fields[mapped_field], term):
                return False
        return all(self._matches_text(record.all_text, term) for term in general_terms)

    def _matches_filters(self, entry: dict[str, Any], filters: SearchFilters) -> bool:
        if filters.category and self._normalize(
            entry.get("category", "")
        ) != self._normalize(filters.category):
            return False

        if filters.tag:
            tags = entry.get("tags", [])
            if isinstance(tags, str):
                tags = tags.split(",")
            normalized_tags = {self._normalize(tag) for tag in tags}
            if self._normalize(filters.tag) not in normalized_tags:
                return False

        updated_at = self._parse_datetime(entry.get("updated_at"))
        if filters.updated_from and (
            updated_at is None or updated_at < filters.updated_from
        ):
            return False
        if filters.updated_to and (
            updated_at is None or updated_at > filters.updated_to
        ):
            return False

        if filters.minimum_strength is not None:
            score = self._strength_analyzer.analyze(
                str(entry.get("password", ""))
            ).score
            if score < filters.minimum_strength:
                return False
        return True

    def _parse_query(self, query: str) -> tuple[list[tuple[str, str]], list[str]]:
        field_terms: list[tuple[str, str]] = []

        def collect(match: re.Match[str]) -> str:
            value = match.group(2) if match.group(2) is not None else match.group(3)
            field_terms.append((match.group(1).casefold(), self._normalize(value)))
            return " "

        remaining = self.FIELD_PATTERN.sub(collect, query)
        general_terms = [
            self._normalize(quoted or plain)
            for quoted, plain in re.findall(r'"([^"]+)"|(\S+)', remaining)
            if quoted or plain
        ]
        return field_terms, general_terms

    @staticmethod
    def _matches_text(text: str, term: str) -> bool:
        if not term:
            return True
        if term in text:
            return True
        if len(term) < 3:
            return False

        words = re.findall(r"[\w@.-]+", text)
        return any(
            abs(len(word) - len(term)) <= 2
            and SequenceMatcher(None, word, term, autojunk=False).ratio() >= 0.78
            for word in words
        )

    @staticmethod
    def _normalize(value: Any) -> str:
        return " ".join(str(value).casefold().split())

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
