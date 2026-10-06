from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk
from PIL import Image


class QRCodeViewer(ctk.CTkToplevel):
    """Display QR code pages and their validity status."""

    def __init__(
        self,
        parent,
        images: list[bytes],
        *,
        payload_info: str,
        copy_value: str,
        copy_callback: Callable[[str], None],
        validity_seconds: int = 300,
        refresh_callback: Callable[[], list[bytes]] | None = None,
    ) -> None:
        super().__init__(parent)
        self.title("Secure QR Code")
        self.geometry("620x720")
        self.transient(parent)
        self.images = images
        self.payload_info = payload_info
        self.copy_value = copy_value
        self.copy_callback = copy_callback
        self.validity_seconds = validity_seconds
        self.refresh_callback = refresh_callback
        self.index = 0
        self.remaining = validity_seconds
        self.current_image = None
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self, text="Secure QR Code", font=ctk.CTkFont(size=22, weight="bold")
        ).grid(row=0, column=0, pady=(20, 8))
        self.image_label = ctk.CTkLabel(self, text="")
        self.image_label.grid(row=1, column=0, padx=24, pady=10)
        self.info_label = ctk.CTkLabel(self, text=payload_info, wraplength=540)
        self.info_label.grid(row=2, column=0, padx=24, pady=8)
        self.counter = ctk.CTkLabel(self, text="")
        self.counter.grid(row=3, column=0, pady=4)
        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.grid(row=4, column=0, pady=12)
        ctk.CTkButton(controls, text="Previous", command=self._previous).pack(
            side="left", padx=5
        )
        ctk.CTkButton(controls, text="Next", command=self._next).pack(
            side="left", padx=5
        )
        ctk.CTkButton(
            controls, text="Copy", command=lambda: self.copy_callback(self.copy_value)
        ).pack(side="left", padx=5)
        ctk.CTkButton(controls, text="Save PNG", command=self._save).pack(
            side="left", padx=5
        )
        ctk.CTkButton(controls, text="Close", command=self.destroy).pack(
            side="left", padx=5
        )
        self._show_current()
        self.after(1000, self._tick)

    def _show_current(self) -> None:
        if not self.images:
            self.image_label.configure(text="No QR images")
            return
        image = Image.open(io.BytesIO(self.images[self.index]))
        image.thumbnail((500, 500), Image.Resampling.NEAREST)
        self.current_image = ctk.CTkImage(image, size=image.size)
        self.image_label.configure(image=self.current_image, text="")
        self.counter.configure(
            text=f"Part {self.index + 1} of {len(self.images)} | refresh in {self.remaining}s"
        )

    def _previous(self) -> None:
        self.index = (self.index - 1) % len(self.images)
        self._show_current()

    def _next(self) -> None:
        self.index = (self.index + 1) % len(self.images)
        self._show_current()

    def _save(self) -> None:
        selected = filedialog.asksaveasfilename(
            parent=self,
            title="Save QR Code",
            defaultextension=".png",
            filetypes=[("PNG image", "*.png")],
        )
        if selected:
            Path(selected).write_bytes(self.images[self.index])

    def _tick(self) -> None:
        if not self.winfo_exists():
            return
        self.remaining -= 1
        if self.remaining <= 0 and self.refresh_callback is not None:
            self.images = self.refresh_callback()
            self.index = 0
            self.remaining = self.validity_seconds
        self._show_current()
        self.after(1000, self._tick)
