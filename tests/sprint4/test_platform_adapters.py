from __future__ import annotations

import sys
import types

from src.core.clipboard.platform_adapter import (
    LinuxClipboardAdapter,
    MacOSClipboardAdapter,
    WindowsClipboardAdapter,
)


def test_windows_adapter_uses_unicode_clipboard(monkeypatch):
    state = {"value": "", "opened": False}
    clipboard = types.SimpleNamespace(
        OpenClipboard=lambda: state.update(opened=True),
        CloseClipboard=lambda: state.update(opened=False),
        EmptyClipboard=lambda: state.update(value=""),
        SetClipboardData=lambda _kind, value: state.update(value=value),
        IsClipboardFormatAvailable=lambda _kind: bool(state["value"]),
        GetClipboardData=lambda _kind: state["value"],
    )
    monkeypatch.setitem(sys.modules, "win32clipboard", clipboard)
    monkeypatch.setitem(
        sys.modules, "win32con", types.SimpleNamespace(CF_UNICODETEXT=13)
    )
    adapter = WindowsClipboardAdapter()

    adapter.copy_text("пароль")
    assert adapter.read_text() == "пароль"
    adapter.clear()
    assert state["value"] == ""
    assert state["opened"] is False


def test_macos_adapter_uses_nspasteboard(monkeypatch):
    class Pasteboard:
        def __init__(self):
            self.value = ""
            self.count = 0

        def declareTypes_owner_(self, _types, _owner):
            self.count += 1

        def setString_forType_(self, value, _kind):
            self.value = value
            return True

        def stringForType_(self, _kind):
            return self.value

        def clearContents(self):
            self.value = ""
            self.count += 1

        def changeCount(self):
            return self.count

    pasteboard = Pasteboard()
    cocoa = types.SimpleNamespace(
        NSPasteboard=types.SimpleNamespace(
            generalPasteboard=lambda: pasteboard,
            pasteboardWithUniqueName=lambda: Pasteboard(),
        ),
        NSPasteboardTypeString="public.utf8-plain-text",
    )
    monkeypatch.setitem(sys.modules, "AppKit", cocoa)
    adapter = MacOSClipboardAdapter()

    adapter.copy_text("secret")
    assert adapter.read_text() == "secret"
    assert adapter.change_token() == 1
    adapter.clear()
    assert adapter.read_text() == ""


def test_linux_wayland_backend(monkeypatch):
    calls = []
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setattr(
        "src.core.clipboard.platform_adapter.shutil.which",
        lambda command: (
            f"/usr/bin/{command}" if command in {"wl-copy", "wl-paste"} else None
        ),
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs.get("input")))
        return types.SimpleNamespace(stdout="wayland-value")

    monkeypatch.setattr("src.core.clipboard.platform_adapter.subprocess.run", fake_run)
    adapter = LinuxClipboardAdapter()
    adapter.copy_text("secret")

    assert adapter.backend == "wayland"
    assert adapter.read_text() == "wayland-value"
    adapter.clear()
    assert calls[0][0][0] == "wl-copy"
    assert calls[-1][0] == ["wl-copy", "--clear"]


def test_linux_x11_backend_supports_primary_selection(monkeypatch):
    calls = []
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        "src.core.clipboard.platform_adapter.shutil.which",
        lambda command: "/usr/bin/xclip" if command == "xclip" else None,
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs.get("input")))
        return types.SimpleNamespace(stdout="x11-value")

    monkeypatch.setattr("src.core.clipboard.platform_adapter.subprocess.run", fake_run)
    adapter = LinuxClipboardAdapter(selection="primary")
    adapter.copy_text("secret")

    assert adapter.backend == "xclip"
    assert adapter.read_text() == "x11-value"
    assert calls[0][0] == ["xclip", "-selection", "primary", "-in"]
