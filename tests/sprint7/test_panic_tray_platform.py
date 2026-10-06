from __future__ import annotations

import sys
import threading
import time
from types import SimpleNamespace

import pytest

from src.core.import_export import ExportOptions, VaultExporter
from src.core.security import PanicInterruptedError, PanicMode, SecurityHardeningConfig
from src.core.security.panic_mode import MouseShakeDetector
from src.core.security.platform_security import (
    LinuxKernelKeyring,
    detect_platform_capabilities,
)
from src.gui.tray_service import SecurityTrayService, TrayCallbacks, TraySecurityState


def _callbacks(events: list[str]) -> TrayCallbacks:
    return TrayCallbacks(
        lock_or_unlock=lambda: events.append("lock"),
        show_window=lambda: events.append("show"),
        quick_search=lambda: events.append("search"),
        clear_clipboard=lambda: events.append("clear"),
        panic=lambda: events.append("panic"),
        settings=lambda: events.append("settings"),
        exit_application=lambda: events.append("exit"),
    )


def test_panic_runs_all_handlers_in_priority_order_and_recovers_state():
    calls: list[str] = []
    audit: list[tuple[str, str, dict]] = []
    restored: list[dict] = []
    panic = PanicMode(
        SecurityHardeningConfig(),
        verify_master_password=lambda value: value == "Correct Password!7",
        audit_callback=lambda event, severity, details: audit.append(
            (event, severity, details)
        ),
        capture_state=lambda: {"query": "mail", "offset": 250},
        restore_state=restored.append,
    )
    panic.register_handler("memory", lambda: calls.append("memory"), priority=10)
    panic.register_handler(
        "failing",
        lambda: (_ for _ in ()).throw(RuntimeError("simulated")),
        priority=20,
    )
    panic.register_handler("lock", lambda: calls.append("lock"), priority=30)

    result = panic.activate("hotkey")

    assert calls == ["memory", "lock"]
    assert result.completed_handlers == ("memory", "lock")
    assert result.failed_handlers == ("failing",)
    assert panic.interrupted
    assert not panic.recover("wrong")
    assert panic.recover("Correct Password!7")
    assert restored == [{"query": "mail", "offset": 250}]
    assert [item[0] for item in audit] == [
        "PANIC_MODE_ACTIVATED",
        "PANIC_MODE_RESPONSE_COMPLETED",
        "PANIC_RECOVERY_REJECTED",
        "PANIC_MODE_RECOVERED",
    ]


def test_panic_stress_is_idempotent_across_concurrent_triggers():
    calls = 0
    call_lock = threading.Lock()

    def handler() -> None:
        nonlocal calls
        with call_lock:
            calls += 1

    panic = PanicMode(
        SecurityHardeningConfig(), verify_master_password=lambda _value: True
    )
    panic.register_handler("wipe", handler)
    threads = [threading.Thread(target=panic.activate) for _ in range(40)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert calls == 1
    assert panic.recover("password")


def test_panic_cleanup_continues_when_audit_sink_is_unavailable():
    calls: list[str] = []
    panic = PanicMode(
        SecurityHardeningConfig(),
        verify_master_password=lambda _value: True,
        audit_callback=lambda *_args: (_ for _ in ()).throw(
            RuntimeError("audit unavailable")
        ),
    )
    panic.register_handler("wipe", lambda: calls.append("wipe"))

    result = panic.activate("hardware_token")

    assert result.completed_handlers == ("wipe",)
    assert calls == ["wipe"]


def test_panic_interrupts_import_export_before_sensitive_work():
    panic = PanicMode(
        SecurityHardeningConfig(), verify_master_password=lambda _value: True
    )
    panic.activate("tray")
    manager = SimpleNamespace(db=object())
    exporter = VaultExporter(
        manager,
        SimpleNamespace(),
        interrupt_check=panic.check_interrupted,
    )

    with pytest.raises(PanicInterruptedError):
        exporter.export(
            ExportOptions(),
            master_password="unused",
            export_password="unused",
        )


def test_mouse_shake_gesture_activates_panic_callback():
    activations: list[str] = []
    detector = MouseShakeDetector(
        lambda: activations.append("panic"), threshold=3, minimum_delta=20
    )

    assert not detector.record(0, 0.0)
    assert not detector.record(40, 0.1)
    assert not detector.record(-10, 0.2)
    assert not detector.record(50, 0.3)
    assert detector.record(-20, 0.4)
    assert activations == ["panic"]


def test_tray_menu_state_animation_and_notifications(monkeypatch):
    created: list[object] = []

    class FakeMenuItem:
        def __init__(self, text, action, **options) -> None:
            self.text = text
            self.action = action
            self.options = options

    class FakeMenu:
        SEPARATOR = object()

        def __init__(self, *items) -> None:
            self.items = items

    class FakeIcon:
        def __init__(self, name, icon, title, menu) -> None:
            self.name = name
            self.icon = icon
            self.title = title
            self.menu = menu
            self.notifications: list[tuple[str, str]] = []
            self.stopped = False
            created.append(self)

        def run_detached(self) -> None:
            return None

        def update_menu(self) -> None:
            return None

        def notify(self, message: str, title: str) -> None:
            self.notifications.append((title, message))

        def stop(self) -> None:
            self.stopped = True

    monkeypatch.setitem(
        sys.modules,
        "pystray",
        SimpleNamespace(Menu=FakeMenu, MenuItem=FakeMenuItem, Icon=FakeIcon),
    )
    service = SecurityTrayService(_callbacks([]))

    assert service.start()
    service.set_state(TraySecurityState.UNLOCKED)
    service.set_clipboard_status("protected for 10 seconds")
    service.notify("Security", "Vault unlocked")
    service.begin_crypto_operation()
    time.sleep(0.02)
    service.end_crypto_operation(locked=False)

    icon = created[0]
    assert service.state is TraySecurityState.UNLOCKED
    assert len(icon.menu.items) == 10
    assert icon.notifications == [("Security", "Vault unlocked")]
    service.stop()
    assert icon.stopped


@pytest.mark.parametrize(
    ("system", "expected"),
    [
        ("Windows", "secure_desktop"),
        ("Darwin", "secure_key_store"),
        ("Linux", "kernel_keyring"),
    ],
)
def test_platform_capabilities_report_security_integration(system, expected):
    capabilities = detect_platform_capabilities(system)

    assert capabilities.system == system
    assert hasattr(capabilities, expected)
    assert capabilities.memory_lock


def test_linux_kernel_keyring_uses_stdin_and_rejects_unsafe_identifiers(monkeypatch):
    calls: list[tuple[list[str], bytes | None]] = []

    def fake_run(command, **options):
        calls.append((command, options.get("input")))
        stdout = b"731\n" if command[1] == "padd" else b"stored-secret"
        return SimpleNamespace(stdout=stdout)

    monkeypatch.setattr(
        "src.core.security.platform_security.os.path.exists", lambda _path: True
    )
    monkeypatch.setattr("src.core.security.platform_security.subprocess.run", fake_run)
    keyring = LinuxKernelKeyring("/usr/bin/keyctl")

    key_id = keyring.save_secret("session-key", b"stored-secret")

    assert key_id == "731"
    assert keyring.read_secret(key_id) == b"stored-secret"
    assert keyring.revoke(key_id)
    assert keyring.save_secret("../unsafe", b"secret") is None
    assert calls[0][0] == [
        "/usr/bin/keyctl",
        "padd",
        "user",
        "cryptosafe:session-key",
        "@s",
    ]
    assert calls[0][1] == b"stored-secret"
    assert b"stored-secret" not in " ".join(calls[0][0]).encode()
