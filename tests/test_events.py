from src.core.events import EventBus, EntryAdded, now_utc


def test_event_publish():
    bus = EventBus()
    called = []

    def handler(event):
        called.append(event.title)

    bus.subscribe(EntryAdded, handler)

    event = EntryAdded(
        name="EntryAdded",
        timestamp=now_utc(),
        entry_id=1,
        title="Test"
    )

    bus.publish(event)

    assert called == ["Test"]
