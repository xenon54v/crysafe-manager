from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
from abc import ABC, abstractmethod


class ClipboardAdapterError(RuntimeError):
    """Raised when a platform clipboard operation fails."""


class PlatformClipboardAdapter(ABC):
    name = "unknown"
    supports_access_detection = False

    @abstractmethod
    def copy_text(self, value: str) -> None: ...

    @abstractmethod
    def read_text(self) -> str: ...

    @abstractmethod
    def clear(self) -> None: ...

    def change_token(self) -> object:
        try:
            return hashlib.sha256(self.read_text().encode("utf-8")).digest()
        except ClipboardAdapterError:
            return object()


class WindowsClipboardAdapter(PlatformClipboardAdapter):
    name = "windows"

    def __init__(self) -> None:
        try:
            import win32clipboard
            import win32con
        except ImportError as exc:
            raise ClipboardAdapterError(
                "Windows clipboard support is unavailable."
            ) from exc
        self._clipboard = win32clipboard
        self._constants = win32con

    def copy_text(self, value: str) -> None:
        try:
            self._clipboard.OpenClipboard()
            self._clipboard.EmptyClipboard()
            self._clipboard.SetClipboardData(self._constants.CF_UNICODETEXT, value)
        except Exception as exc:
            raise ClipboardAdapterError("Windows clipboard write failed.") from exc
        finally:
            self._close()

    def read_text(self) -> str:
        try:
            self._clipboard.OpenClipboard()
            if not self._clipboard.IsClipboardFormatAvailable(
                self._constants.CF_UNICODETEXT
            ):
                return ""
            return str(self._clipboard.GetClipboardData(self._constants.CF_UNICODETEXT))
        except Exception as exc:
            raise ClipboardAdapterError("Windows clipboard read failed.") from exc
        finally:
            self._close()

    def clear(self) -> None:
        try:
            self._clipboard.OpenClipboard()
            self._clipboard.EmptyClipboard()
        except Exception as exc:
            raise ClipboardAdapterError("Windows clipboard clear failed.") from exc
        finally:
            self._close()

    def _close(self) -> None:
        try:
            self._clipboard.CloseClipboard()
        except Exception:  # noqa: BLE001 - pywin32 exposes backend-specific errors
            return

    def change_token(self) -> object:
        try:
            import ctypes

            return int(ctypes.windll.user32.GetClipboardSequenceNumber())
        except (AttributeError, OSError):
            return super().change_token()


class MacOSClipboardAdapter(PlatformClipboardAdapter):
    name = "macos"

    def __init__(self, private: bool = False) -> None:
        try:
            from AppKit import NSPasteboard, NSPasteboardTypeString
        except ImportError as exc:
            raise ClipboardAdapterError(
                "macOS clipboard support is unavailable."
            ) from exc
        self._string_type = NSPasteboardTypeString
        if private:
            self._pasteboard = NSPasteboard.pasteboardWithUniqueName()
        else:
            self._pasteboard = NSPasteboard.generalPasteboard()

    def copy_text(self, value: str) -> None:
        try:
            self._pasteboard.declareTypes_owner_([self._string_type], None)
            if not self._pasteboard.setString_forType_(value, self._string_type):
                raise ClipboardAdapterError("macOS clipboard rejected the value.")
        except ClipboardAdapterError:
            raise
        except Exception as exc:
            raise ClipboardAdapterError("macOS clipboard write failed.") from exc

    def read_text(self) -> str:
        try:
            return str(self._pasteboard.stringForType_(self._string_type) or "")
        except Exception as exc:
            raise ClipboardAdapterError("macOS clipboard read failed.") from exc

    def clear(self) -> None:
        try:
            self._pasteboard.clearContents()
        except Exception as exc:
            raise ClipboardAdapterError("macOS clipboard clear failed.") from exc

    def change_token(self) -> object:
        return int(self._pasteboard.changeCount())


class LinuxClipboardAdapter(PlatformClipboardAdapter):
    name = "linux"

    def __init__(self, selection: str = "clipboard") -> None:
        if selection not in {"clipboard", "primary"}:
            raise ValueError("Linux selection must be clipboard or primary.")
        self.selection = selection
        self.backend = self._select_backend()

    def _select_backend(self) -> str:
        if (
            os.environ.get("WAYLAND_DISPLAY")
            and shutil.which("wl-copy")
            and shutil.which("wl-paste")
        ):
            return "wayland"
        if shutil.which("xclip"):
            return "xclip"
        if shutil.which("xsel"):
            return "xsel"
        try:
            import pyperclip  # noqa: F401
        except ImportError as exc:
            raise ClipboardAdapterError(
                "No Linux clipboard backend is available."
            ) from exc
        return "pyperclip"

    def copy_text(self, value: str) -> None:
        if self.backend == "pyperclip":
            return PyperclipAdapter().copy_text(value)
        command = self._write_command()
        self._run(command, input_value=value)

    def read_text(self) -> str:
        if self.backend == "pyperclip":
            return PyperclipAdapter().read_text()
        result = self._run(self._read_command())
        return result.stdout

    def clear(self) -> None:
        if self.backend == "wayland":
            self._run(["wl-copy", "--clear"])
        else:
            self.copy_text("")

    def _write_command(self) -> list[str]:
        if self.backend == "wayland":
            return ["wl-copy", "--type", "text/plain;charset=utf-8"]
        if self.backend == "xclip":
            return ["xclip", "-selection", self.selection, "-in"]
        return ["xsel", f"--{self.selection}", "--input"]

    def _read_command(self) -> list[str]:
        if self.backend == "wayland":
            return ["wl-paste", "--no-newline", "--type", "text"]
        if self.backend == "xclip":
            return ["xclip", "-selection", self.selection, "-out"]
        return ["xsel", f"--{self.selection}", "--output"]

    @staticmethod
    def _run(
        command: list[str], input_value: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                input=input_value,
                text=True,
                capture_output=True,
                timeout=2.0,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ClipboardAdapterError("Linux clipboard operation failed.") from exc


class PyperclipAdapter(PlatformClipboardAdapter):
    name = "pyperclip"

    def __init__(self) -> None:
        try:
            import pyperclip
        except ImportError as exc:
            raise ClipboardAdapterError("pyperclip is unavailable.") from exc
        self._pyperclip = pyperclip

    def copy_text(self, value: str) -> None:
        try:
            self._pyperclip.copy(value)
        except Exception as exc:
            raise ClipboardAdapterError("Fallback clipboard write failed.") from exc

    def read_text(self) -> str:
        try:
            return str(self._pyperclip.paste() or "")
        except Exception as exc:
            raise ClipboardAdapterError("Fallback clipboard read failed.") from exc

    def clear(self) -> None:
        self.copy_text("")


class InMemoryClipboardAdapter(PlatformClipboardAdapter):
    """Session-only clipboard that is never exposed to another process."""

    name = "ephemeral-memory"
    supports_access_detection = True

    def __init__(self) -> None:
        self._value = ""
        self._generation = 0

    def copy_text(self, value: str) -> None:
        self._value = value
        self._generation += 1

    def read_text(self) -> str:
        return self._value

    def clear(self) -> None:
        self._value = ""
        self._generation += 1

    def change_token(self) -> object:
        return self._generation


class FallbackClipboardAdapter(PlatformClipboardAdapter):
    def __init__(
        self, primary: PlatformClipboardAdapter, fallback: PlatformClipboardAdapter
    ) -> None:
        self.primary = primary
        self.fallback = fallback
        self.active = primary
        self.name = f"{primary.name}+fallback"

    def _call(self, method: str, *args):
        try:
            return getattr(self.active, method)(*args)
        except ClipboardAdapterError:
            if self.active is self.fallback:
                raise
            self.active = self.fallback
            return getattr(self.active, method)(*args)

    def copy_text(self, value: str) -> None:
        self._call("copy_text", value)

    def read_text(self) -> str:
        return str(self._call("read_text"))

    def clear(self) -> None:
        self._call("clear")

    def change_token(self) -> object:
        return self._call("change_token")


def create_platform_adapter(private: bool = False) -> PlatformClipboardAdapter:
    if private:
        return InMemoryClipboardAdapter()

    system = platform.system()
    try:
        if system == "Windows":
            primary: PlatformClipboardAdapter = WindowsClipboardAdapter()
        elif system == "Darwin":
            primary = MacOSClipboardAdapter()
        elif system == "Linux":
            primary = LinuxClipboardAdapter()
        else:
            return PyperclipAdapter()
    except ClipboardAdapterError:
        return PyperclipAdapter()

    try:
        fallback = PyperclipAdapter()
    except ClipboardAdapterError:
        return primary
    return FallbackClipboardAdapter(primary, fallback)
