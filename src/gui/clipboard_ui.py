from __future__ import annotations

import threading

import customtkinter as ctk

from src.core.clipboard.clipboard_service import ClipboardSnapshot

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"


class ClipboardToast(ctk.CTkToplevel):
    def __init__(self, master, message: str, warning: bool = False) -> None:
        super().__init__(master)
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(fg_color="#5b3543" if warning else "#2f4a3a")
        ctk.CTkLabel(self, text=message, wraplength=330, padx=18, pady=13).pack()
        self.update_idletasks()
        x = max(
            20, master.winfo_rootx() + master.winfo_width() - self.winfo_width() - 28
        )
        y = max(
            20, master.winfo_rooty() + master.winfo_height() - self.winfo_height() - 54
        )
        self.geometry(f"+{x}+{y}")
        self.after(2600, self.destroy)


class ClipboardPreviewDialog(ctk.CTkToplevel):
    def __init__(self, master, snapshot: ClipboardSnapshot, reveal_callback) -> None:
        super().__init__(master)
        self.title("Secure Clipboard Preview")
        self.geometry("470x330")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        frame = ctk.CTkFrame(self)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(
            frame,
            text="Secure Clipboard",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(18, 12))
        item_type = snapshot.data_type.value if snapshot.data_type else "none"
        ctk.CTkLabel(frame, text=f"Type: {item_type}").pack(anchor="w", padx=20, pady=4)
        ctk.CTkLabel(frame, text=f"Source: {snapshot.source or 'unknown'}").pack(
            anchor="w", padx=20, pady=4
        )
        ctk.CTkLabel(frame, text="Preview:").pack(anchor="w", padx=20, pady=(14, 4))
        self.preview = ctk.CTkEntry(frame, show="•")
        self.preview.pack(fill="x", padx=20)
        self.preview.insert(0, snapshot.masked_preview)
        self.preview.configure(state="disabled")

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(24, 10))
        ctk.CTkButton(
            buttons,
            text="Close",
            command=self.destroy,
            fg_color="gray45",
            hover_color="gray35",
        ).pack(side="right", padx=(10, 0))
        ctk.CTkButton(
            buttons,
            text="Authenticate and Reveal",
            command=lambda: self._reveal(reveal_callback),
            fg_color=PINK,
            hover_color=PINK_HOVER,
        ).pack(side="right")

    def _reveal(self, callback) -> None:
        try:
            value = callback()
        except (PermissionError, RuntimeError):
            return
        self.preview.configure(state="normal", show="")
        self.preview.delete(0, "end")
        self.preview.insert(0, value)
        self.preview.configure(state="readonly")
        self.after(5000, self.destroy)


class TrayStatusIndicator:
    """Optional native tray status; the main status bar remains the fallback."""

    def __init__(self, on_clear, on_exit) -> None:
        self._on_clear = on_clear
        self._on_exit = on_exit
        self._icon = None
        self._lock = threading.Lock()

    def start(self) -> bool:
        try:
            import pystray
            from PIL import Image, ImageDraw
        except Exception:  # noqa: BLE001 - optional tray backends fail differently by OS
            return False
        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((10, 8, 54, 58), radius=10, fill="#d98ca3")
        draw.rectangle((20, 20, 44, 46), fill="#242424")
        menu = pystray.Menu(
            pystray.MenuItem("Clear clipboard", lambda *_: self._on_clear()),
            pystray.MenuItem("Exit", lambda *_: self._on_exit()),
        )
        self._icon = pystray.Icon(
            "cryptosafe", image, "CryptoSafe: clipboard empty", menu
        )
        try:
            self._icon.run_detached()
        except Exception:  # noqa: BLE001 - the tray is an optional UI enhancement
            self._icon = None
            return False
        return True

    def update(self, text: str) -> None:
        with self._lock:
            if self._icon is not None:
                self._icon.title = f"CryptoSafe: {text}"[:120]

    def stop(self) -> None:
        with self._lock:
            if self._icon is not None:
                try:
                    self._icon.stop()
                finally:
                    self._icon = None
