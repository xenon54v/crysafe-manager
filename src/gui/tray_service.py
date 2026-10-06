from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar


class TraySecurityState(StrEnum):
    """Store tray security state values."""

    LOCKED = "locked"
    UNLOCKED = "unlocked"
    BUSY = "busy"
    PANIC = "panic"


@dataclass(frozen=True)
class TrayCallbacks:
    """Represent tray callbacks behavior."""

    lock_or_unlock: Callable[[], None]
    show_window: Callable[[], None]
    quick_search: Callable[[], None]
    clear_clipboard: Callable[[], None]
    panic: Callable[[], None]
    settings: Callable[[], None]
    exit_application: Callable[[], None]


class SecurityTrayService:
    """Native tray menu with a safe no-tray fallback."""

    COLORS: ClassVar[dict[TraySecurityState, str]] = {
        TraySecurityState.LOCKED: "#b91c1c",
        TraySecurityState.UNLOCKED: "#15803d",
        TraySecurityState.BUSY: "#d97706",
        TraySecurityState.PANIC: "#7f1d1d",
    }

    def __init__(self, callbacks: TrayCallbacks) -> None:
        self.callbacks = callbacks
        self.state = TraySecurityState.LOCKED
        self.clipboard_status = "empty"
        self._icon = None
        self._lock = threading.RLock()
        self._animation_stop = threading.Event()
        self._animation_thread: threading.Thread | None = None
        self._animation_frame = False

    def start(self) -> bool:
        try:
            import pystray
        except Exception:  # noqa: BLE001 - optional native backends vary by OS
            return False
        with self._lock:
            if self._icon is not None:
                return True
            menu = pystray.Menu(
                pystray.MenuItem(
                    lambda _item: (
                        "Unlock vault"
                        if self.state is TraySecurityState.LOCKED
                        else "Lock vault"
                    ),
                    lambda *_: self.callbacks.lock_or_unlock(),
                ),
                pystray.MenuItem(
                    "Show main window", lambda *_: self.callbacks.show_window()
                ),
                pystray.MenuItem(
                    "Quick search", lambda *_: self.callbacks.quick_search()
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(
                    lambda _item: f"Clipboard: {self.clipboard_status}",
                    None,
                    enabled=False,
                ),
                pystray.MenuItem(
                    "Clear clipboard", lambda *_: self.callbacks.clear_clipboard()
                ),
                pystray.MenuItem("Panic mode", lambda *_: self.callbacks.panic()),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Settings", lambda *_: self.callbacks.settings()),
                pystray.MenuItem("Exit", lambda *_: self.callbacks.exit_application()),
            )
            self._icon = pystray.Icon(
                "cryptosafe",
                self._make_image(self.state),
                "CryptoSafe Manager: locked",
                menu,
            )
            try:
                self._icon.run_detached()
            except Exception:  # noqa: BLE001 - fallback remains the main window
                self._icon = None
                return False
        return True

    @property
    def available(self) -> bool:
        with self._lock:
            return self._icon is not None

    def set_state(self, state: TraySecurityState | str) -> None:
        selected = TraySecurityState(state)
        with self._lock:
            self.state = selected
            if self._icon is not None:
                self._icon.icon = self._make_image(selected)
                self._icon.title = f"CryptoSafe Manager: {selected.value}"[:120]
                self._icon.update_menu()

    def set_clipboard_status(self, status: str) -> None:
        with self._lock:
            self.clipboard_status = status[:80]
            if self._icon is not None:
                self._icon.update_menu()

    def begin_crypto_operation(self) -> None:
        self.set_state(TraySecurityState.BUSY)
        with self._lock:
            if self._animation_thread is not None:
                return
            self._animation_stop.clear()
            self._animation_thread = threading.Thread(
                target=self._animate,
                name="cryptosafe-tray-animation",
                daemon=True,
            )
            self._animation_thread.start()

    def end_crypto_operation(self, *, locked: bool = False) -> None:
        self._stop_animation()
        self.set_state(
            TraySecurityState.LOCKED if locked else TraySecurityState.UNLOCKED
        )

    def notify(self, title: str, message: str) -> None:
        with self._lock:
            if self._icon is None:
                return
            try:
                self._icon.notify(message[:250], title[:64])
            except Exception:  # noqa: BLE001 - notifications are non-critical
                return

    def stop(self) -> None:
        self._stop_animation()
        with self._lock:
            if self._icon is not None:
                try:
                    self._icon.stop()
                finally:
                    self._icon = None

    def _animate(self) -> None:
        while not self._animation_stop.wait(0.35):
            with self._lock:
                if self._icon is None:
                    break
                self._animation_frame = not self._animation_frame
                state = (
                    TraySecurityState.BUSY
                    if self._animation_frame
                    else TraySecurityState.UNLOCKED
                )
                self._icon.icon = self._make_image(state)

    def _stop_animation(self) -> None:
        with self._lock:
            self._animation_stop.set()
            thread = self._animation_thread
            self._animation_thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    @classmethod
    def _make_image(cls, state: TraySecurityState):
        from PIL import Image, ImageDraw

        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        color = cls.COLORS[state]
        draw.rounded_rectangle((9, 23, 55, 58), radius=9, fill=color)
        draw.arc((18, 6, 46, 38), 180, 360, fill=color, width=8)
        draw.ellipse((29, 35, 35, 41), fill="white")
        draw.rectangle((31, 40, 33, 49), fill="white")
        return image
