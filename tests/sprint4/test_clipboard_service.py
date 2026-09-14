from __future__ import annotations

import threading
import time
import tracemalloc

import pytest

from src.core.clipboard.clipboard_service import (
    ClipboardConfig,
    ClipboardService,
    ClipboardState,
    ClipboardType,
)
from src.core.clipboard.platform_adapter import (
    ClipboardAdapterError,
    InMemoryClipboardAdapter,
)
from src.core.clipboard.secure_memory import SecureBuffer
from src.core.events import ClipboardCleared, ClipboardCopied, EventBus


class ManualTimer:
    def __init__(self, delay, callback):
        self.delay = delay
        self.callback = callback
        self.daemon = False
        self.started = False
        self.cancelled = False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True


class ManualTimers:
    def __init__(self):
        self.items = []

    def __call__(self, delay, callback):
        timer = ManualTimer(delay, callback)
        self.items.append(timer)
        return timer


class FailingClearAdapter(InMemoryClipboardAdapter):
    def clear(self):
        raise ClipboardAdapterError("clear failed")


def make_service(**kwargs):
    adapter = kwargs.pop("adapter", InMemoryClipboardAdapter())
    return adapter, ClipboardService(
        adapter,
        is_vault_unlocked=lambda: True,
        config=kwargs.pop("config", ClipboardConfig()),
        **kwargs,
    )


def test_secure_buffer_masks_plaintext_and_zeroes_storage():
    secret = "Correct-Horse-Battery-Staple"
    buffer = SecureBuffer(secret)

    assert buffer.reveal_text() == secret
    assert not buffer.contains_plaintext(secret)
    assert secret not in repr(buffer.__dict__)

    buffer.clear()
    assert buffer.cleared
    assert buffer.size == 0


def test_copy_notifies_observers_and_publishes_events():
    bus = EventBus()
    events = []
    snapshots = []
    bus.subscribe(ClipboardCopied, events.append)
    bus.subscribe(ClipboardCleared, events.append)
    adapter, service = make_service(event_bus=bus)
    service.add_observer(snapshots.append)

    copied = service.copy_text(
        "secret-value",
        entry_id="entry-1",
        field="password",
        source="Portal",
        data_type=ClipboardType.PASSWORD,
    )
    service.clear("manual")

    assert copied.state is ClipboardState.ACTIVE
    assert copied.masked_preview == "sec••••"
    assert adapter.read_text() == ""
    assert [type(event) for event in events] == [ClipboardCopied, ClipboardCleared]
    assert snapshots[-1].state is ClipboardState.IDLE


def test_timeout_schedule_and_warning_are_exact_to_100_ms():
    clock_value = [100.0]
    timers = ManualTimers()
    adapter, service = make_service(
        config=ClipboardConfig(timeout_seconds=30),
        clock=lambda: clock_value[0],
        timer_factory=timers,
    )

    service.copy_text("timed-secret", entry_id="1", field="password")

    assert [timer.delay for timer in timers.items] == [25.0, 30.0]
    assert abs(service.snapshot.expires_at_monotonic - 130.0) <= 0.1
    clock_value[0] = 125.0
    timers.items[0].callback()
    assert service.snapshot.state is ClipboardState.WARNING
    clock_value[0] = 130.0
    timers.items[1].callback()
    assert not service.has_sensitive_value
    assert adapter.read_text() == ""


def test_real_five_second_clear_is_within_100_ms():
    bus = EventBus()
    cleared = threading.Event()
    bus.subscribe(ClipboardCleared, lambda _event: cleared.set())
    adapter, service = make_service(
        config=ClipboardConfig(timeout_seconds=5), event_bus=bus
    )
    started = time.monotonic()

    service.copy_text("real-timer", entry_id="1", field="password")

    assert cleared.wait(5.5)
    elapsed = time.monotonic() - started
    assert abs(elapsed - 5.0) <= 0.1
    assert adapter.read_text() == ""


def test_vault_must_be_unlocked_and_input_is_sanitized():
    service = ClipboardService(
        InMemoryClipboardAdapter(), is_vault_unlocked=lambda: False
    )
    with pytest.raises(PermissionError):
        service.copy_text("secret", entry_id="1", field="password")

    _, unlocked = make_service()
    with pytest.raises(ValueError):
        unlocked.copy_text("bad\x00value", entry_id="1", field="password")
    with pytest.raises(ValueError):
        unlocked.copy_text("secret", entry_id="bad\nidentifier", field="password")


def test_external_access_accelerates_clear_and_blocks_future_copy():
    timers = ManualTimers()
    adapter, service = make_service(
        config=ClipboardConfig.profile("secure"), timer_factory=timers
    )
    service.copy_text("secret", entry_id="1", field="password")

    service.report_external_access("untrusted-app")

    assert service.snapshot.state is ClipboardState.WARNING
    assert any(timer.delay == 5.0 and timer.started for timer in timers.items)
    with pytest.raises(PermissionError):
        service.copy_text("second", entry_id="2", field="password")
    service.unblock()
    service.copy_text("second", entry_id="2", field="password")
    assert adapter.read_text() == "second"


def test_whitelisted_application_does_not_trigger_blocking():
    adapter, service = make_service(
        config=ClipboardConfig(
            timeout_seconds=15,
            application_whitelist=("trusted-app",),
            block_after_suspicious_access=True,
        )
    )
    service.copy_text("secret", entry_id="1", field="password")

    service.report_external_access("trusted-app")
    service.copy_text("second", entry_id="2", field="password")

    assert service.snapshot.state is ClipboardState.ACTIVE
    assert adapter.read_text() == "second"


def test_clear_failure_erases_process_memory_and_reports_error():
    adapter = FailingClearAdapter()
    adapter._value = "secret"
    service = ClipboardService(adapter, is_vault_unlocked=lambda: True)
    service._buffer = SecureBuffer("secret")

    success = service.clear("test")

    assert success is False
    assert not service.has_sensitive_value
    assert service.snapshot.state is ClipboardState.ERROR


def test_rapid_copy_does_not_retain_previous_values_and_meets_limits():
    adapter, service = make_service(config=ClipboardConfig(timeout_seconds=None))
    started = time.perf_counter()
    tracemalloc.start()
    for number in range(100):
        value = f"unique-secret-{number:03d}"
        service.copy_text(value, entry_id=str(number), field="password")
        if number:
            assert not service._buffer.contains_plaintext(
                f"unique-secret-{number - 1:03d}"
            )
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    elapsed_per_copy = (time.perf_counter() - started) / 100

    assert adapter.read_text() == "unique-secret-099"
    assert elapsed_per_copy < 0.1
    assert peak < 10 * 1024 * 1024


def test_close_simulates_cooperative_crash_cleanup():
    adapter, service = make_service()
    service.copy_text("crash-secret", entry_id="1", field="password")

    service.close()

    assert adapter.read_text() == ""
    assert not service.has_sensitive_value
