from datetime import datetime, timedelta, timezone

from src.core.events import EventBus, SearchPerformed
from src.core.vault.search_service import SearchFilters, VaultSearchIndex


def sample_entries():
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "1",
            "title": "GitHub Work",
            "username": "developer@example.com",
            "password": "R7!mK9@qL2#vN8$z",
            "url": "https://github.com",
            "notes": "Primary source repository",
            "category": "Work",
            "tags": ["git", "code"],
            "updated_at": now.isoformat(),
        },
        {
            "id": "2",
            "title": "Personal Mail",
            "username": "student@example.com",
            "password": "weak",
            "url": "https://mail.example.com",
            "notes": "Private inbox",
            "category": "Personal",
            "tags": ["mail"],
            "updated_at": (now - timedelta(days=90)).isoformat(),
        },
    ]


def test_full_text_fuzzy_and_field_specific_search():
    index = VaultSearchIndex()
    index.rebuild(sample_entries())

    assert [entry["id"] for entry in index.search("primry")] == ["1"]
    assert [entry["id"] for entry in index.search('title:"github" tag:code')] == ["1"]
    assert [entry["id"] for entry in index.search("username:student")] == ["2"]


def test_category_date_tag_and_strength_filters():
    index = VaultSearchIndex()
    index.rebuild(sample_entries())
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    results = index.search(
        filters=SearchFilters(
            category="Work",
            tag="git",
            updated_from=cutoff,
            minimum_strength=3,
        )
    )

    assert [entry["id"] for entry in results] == ["1"]


def test_search_history_keeps_last_ten_queries():
    index = VaultSearchIndex()
    index.rebuild(sample_entries())

    for number in range(12):
        index.search(f"query-{number}")

    assert len(index.history) == 10
    assert index.history[0] == "query-2"
    assert index.history[-1] == "query-11"


def test_search_publishes_event_for_future_audit_integration():
    bus = EventBus()
    events = []
    bus.subscribe(SearchPerformed, events.append)
    index = VaultSearchIndex(bus)
    index.rebuild(sample_entries())

    index.search("github")

    assert len(events) == 1
    assert events[0].query == "github"
    assert events[0].result_count == 1
