from __future__ import annotations

from tkinter import messagebox
from typing import ClassVar

import customtkinter as ctk

from src.core.clipboard.clipboard_service import ClipboardConfig, SecurityLevel

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"


class SettingsDialog(ctk.CTkToplevel):
    TIMEOUTS: ClassVar[dict[str, int | None]] = {
        "5 seconds": 5,
        "15 seconds": 15,
        "30 seconds": 30,
        "1 minute": 60,
        "5 minutes": 300,
        "Never": None,
    }

    def __init__(self, master=None, clipboard_config: ClipboardConfig | None = None):
        super().__init__(master)
        self.result: str | ClipboardConfig | None = None
        self._config = clipboard_config or ClipboardConfig()
        self.title("Settings")
        self.geometry("540x650")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self._create_widgets()
        self._set_config(self._config)

    def _create_widgets(self) -> None:
        frame = ctk.CTkScrollableFrame(self)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(
            frame, text="Settings", font=ctk.CTkFont(size=24, weight="bold")
        ).pack(anchor="w", padx=20, pady=(18, 16))

        self.profile = self._option(
            frame,
            "Clipboard profile",
            ["Custom", "Standard", "Secure", "Public Computer"],
        )
        self.profile.configure(command=self._profile_changed)
        self.timeout = self._option(frame, "Automatic clear", list(self.TIMEOUTS))
        self.security = self._option(
            frame, "Security level", [item.value.title() for item in SecurityLevel]
        )

        self.notifications = ctk.BooleanVar(value=True)
        self.block_suspicious = ctk.BooleanVar(value=False)
        self.ephemeral = ctk.BooleanVar(value=False)
        for label, variable in (
            ("Show clipboard notifications", self.notifications),
            ("Block new copies after suspicious access", self.block_suspicious),
            ("Use session-only in-memory clipboard", self.ephemeral),
        ):
            ctk.CTkCheckBox(
                frame,
                text=label,
                variable=variable,
                fg_color=PINK,
                hover_color=PINK_HOVER,
            ).pack(anchor="w", padx=20, pady=7)

        ctk.CTkLabel(frame, text="Allowed applications, one per line").pack(
            anchor="w", padx=20, pady=(14, 5)
        )
        self.whitelist = ctk.CTkTextbox(frame, height=90)
        self.whitelist.pack(fill="x", padx=20)

        ctk.CTkButton(
            frame,
            text="Change master password",
            command=self._choose_change_password,
            fg_color="gray42",
            hover_color="gray34",
        ).pack(fill="x", padx=20, pady=(20, 8))

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(14, 18))
        ctk.CTkButton(
            buttons,
            text="Cancel",
            command=self.destroy,
            fg_color="gray45",
            hover_color="gray35",
        ).pack(side="right", padx=(10, 0))
        ctk.CTkButton(
            buttons,
            text="Save",
            command=self._save,
            fg_color=PINK,
            hover_color=PINK_HOVER,
        ).pack(side="right")

    @staticmethod
    def _option(frame, label: str, values: list[str]) -> ctk.CTkOptionMenu:
        ctk.CTkLabel(frame, text=label).pack(anchor="w", padx=20, pady=(8, 5))
        widget = ctk.CTkOptionMenu(
            frame, values=values, fg_color=PINK, button_color=PINK_HOVER
        )
        widget.pack(fill="x", padx=20, pady=(0, 8))
        return widget

    def _profile_changed(self, value: str) -> None:
        if value == "Custom":
            return
        self._set_config(ClipboardConfig.profile(value))
        self.profile.set(value)

    def _set_config(self, config: ClipboardConfig) -> None:
        timeout_label = next(
            label
            for label, seconds in self.TIMEOUTS.items()
            if seconds == config.timeout_seconds
        )
        self.timeout.set(timeout_label)
        self.security.set(config.security_level.value.title())
        self.notifications.set(config.notifications_enabled)
        self.block_suspicious.set(config.block_after_suspicious_access)
        self.ephemeral.set(config.ephemeral_mode)
        self.whitelist.delete("1.0", "end")
        self.whitelist.insert("1.0", "\n".join(config.application_whitelist))
        self.profile.set("Custom")

    def _save(self) -> None:
        try:
            self.result = ClipboardConfig(
                timeout_seconds=self.TIMEOUTS[self.timeout.get()],
                notifications_enabled=self.notifications.get(),
                security_level=SecurityLevel(self.security.get().casefold()),
                application_whitelist=tuple(
                    self.whitelist.get("1.0", "end-1c").splitlines()
                ),
                block_after_suspicious_access=self.block_suspicious.get(),
                ephemeral_mode=self.ephemeral.get(),
            )
        except (KeyError, ValueError) as exc:
            messagebox.showerror("Settings", str(exc), parent=self)
            return
        self.destroy()

    def _choose_change_password(self) -> None:
        self.result = "change_master_password"
        self.destroy()
