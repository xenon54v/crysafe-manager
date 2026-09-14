from __future__ import annotations

import threading
from collections.abc import Callable

from .clipboard_service import ClipboardService, ClipboardSnapshot, ClipboardState
from .platform_adapter import ClipboardAdapterError, PlatformClipboardAdapter


class ClipboardMonitor:
    """Detects clipboard ownership changes without storing clipboard history."""

    def __init__(
        self,
        adapter: PlatformClipboardAdapter,
        service: ClipboardService,
        poll_interval: float = 1.0,
        on_degraded: Callable[[str], None] | None = None,
    ) -> None:
        if poll_interval < 0.1:
            raise ValueError("Clipboard monitor interval is too small.")
        self.adapter = adapter
        self.service = service
        self.poll_interval = poll_interval
        self.on_degraded = on_degraded
        self._expected_token: object | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.service.add_observer(self)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="clipboard-monitor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(1.0, self.poll_interval * 2))
        self._thread = None
        self.service.remove_observer(self)

    def clipboard_state_changed(self, snapshot: ClipboardSnapshot) -> None:
        if snapshot.state is ClipboardState.ACTIVE:
            try:
                self._expected_token = self.adapter.change_token()
            except ClipboardAdapterError:
                self._degraded("Clipboard monitoring is unavailable.")
        elif snapshot.state in {
            ClipboardState.IDLE,
            ClipboardState.ERROR,
            ClipboardState.BLOCKED,
        }:
            self._expected_token = None

    def report_external_access(self, application: str = "unknown") -> None:
        self.service.report_external_access(application)

    def _run(self) -> None:
        while not self._stop_event.wait(self.poll_interval):
            expected = self._expected_token
            if expected is None or not self.service.has_sensitive_value:
                continue
            try:
                current = self.adapter.change_token()
            except ClipboardAdapterError:
                self._expected_token = None
                self._degraded("Clipboard monitoring stopped after a platform error.")
                continue
            if current != expected:
                self._expected_token = None
                self.service.external_content_changed()

    def _degraded(self, message: str) -> None:
        if self.on_degraded is not None:
            self.on_degraded(message)
