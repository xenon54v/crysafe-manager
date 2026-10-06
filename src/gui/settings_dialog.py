from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, replace
from tkinter import messagebox
from typing import ClassVar

import customtkinter as ctk

from src.core.clipboard.clipboard_service import ClipboardConfig, SecurityLevel
from src.core.security import (
    ActivitySensitivity,
    DeviceType,
    SecurityHardeningConfig,
    SecurityProfile,
)
from src.gui.theme import PINK, PINK_HOVER


@dataclass(frozen=True)
class ApplicationSettings:
    """Combined clipboard and security settings returned by the dialog."""

    clipboard: ClipboardConfig
    security: SecurityHardeningConfig


class SettingsDialog(ctk.CTkToplevel):
    """Edit validated clipboard and security preferences."""

    CLIPBOARD_TIMEOUTS: ClassVar[dict[str, int | None]] = {
        "5 seconds": 5,
        "15 seconds": 15,
        "30 seconds": 30,
        "1 minute": 60,
        "5 minutes": 300,
        "Never": None,
    }
    AUTO_LOCK_TIMEOUTS: ClassVar[dict[str, int]] = {
        "1 minute": 60,
        "2 minutes": 120,
        "3 minutes": 180,
        "5 minutes": 300,
        "15 minutes": 900,
        "30 minutes": 1800,
        "1 hour": 3600,
        "8 hours": 28_800,
    }

    def __init__(
        self,
        master=None,
        clipboard_config: ClipboardConfig | None = None,
        security_config: SecurityHardeningConfig | None = None,
    ) -> None:
        super().__init__(master)
        self.result: str | ApplicationSettings | None = None
        self._clipboard = clipboard_config or ClipboardConfig()
        self._security = security_config or SecurityHardeningConfig()
        self.title("Settings")
        self.geometry("680x760")
        self.minsize(620, 680)
        self.transient(master)
        self.grab_set()
        self._create_widgets()
        self._set_clipboard_config(self._clipboard)
        self._set_security_config(self._security)

    def _create_widgets(self) -> None:
        frame = ctk.CTkScrollableFrame(self)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(
            frame, text="Settings", font=ctk.CTkFont(size=24, weight="bold")
        ).pack(anchor="w", padx=20, pady=(18, 16))

        ctk.CTkLabel(
            frame, text="Security hardening", font=ctk.CTkFont(size=18, weight="bold")
        ).pack(anchor="w", padx=20, pady=(4, 8))
        self.security_profile = self._option(
            frame, "Security profile", [item.value.title() for item in SecurityProfile]
        )
        self.security_profile.configure(command=self._security_profile_changed)
        self.device_type = self._option(
            frame, "Device type", [item.value.title() for item in DeviceType]
        )
        self.activity_sensitivity = self._option(
            frame,
            "Activity sensitivity",
            [item.value.title() for item in ActivitySensitivity],
        )
        self.auto_lock_timeout = self._option(
            frame, "Auto-lock timeout", list(self.AUTO_LOCK_TIMEOUTS)
        )
        self.profile_changes = ctk.CTkLabel(
            frame,
            text="",
            justify="left",
            anchor="w",
            wraplength=570,
            text_color=("gray35", "gray70"),
        )
        self.profile_changes.pack(fill="x", padx=20, pady=(2, 10))

        self.clear_on_lock = ctk.BooleanVar(value=True)
        self.minimize_to_tray = ctk.BooleanVar(value=True)
        self.start_minimized = ctk.BooleanVar(value=False)
        self.tray_notifications = ctk.BooleanVar(value=True)
        self.panic_close = ctk.BooleanVar(value=False)
        self.panic_fake_error = ctk.BooleanVar(value=False)
        self.lock_on_screen_lock = ctk.BooleanVar(value=True)
        self.hide_sensitive_windows = ctk.BooleanVar(value=True)
        for label, variable in (
            ("Clear clipboard when vault locks", self.clear_on_lock),
            ("Lock when the operating system locks", self.lock_on_screen_lock),
            ("Hide sensitive windows when vault locks", self.hide_sensitive_windows),
            ("Minimize to system tray", self.minimize_to_tray),
            ("Start minimized to tray", self.start_minimized),
            ("Show tray security notifications", self.tray_notifications),
            ("Close application after panic response", self.panic_close),
            ("Show a generic error after panic response", self.panic_fake_error),
        ):
            self._checkbox(frame, label, variable)

        ctk.CTkLabel(
            frame, text="Panic response", font=ctk.CTkFont(size=18, weight="bold")
        ).pack(anchor="w", padx=20, pady=(18, 8))
        self.panic_hotkey = self._entry(frame, "Panic hotkey (Tk sequence)")
        self.panic_decoy_command = self._entry(
            frame, "Optional decoy command (arguments are parsed without a shell)"
        )
        self.panic_decoy_url = self._entry(frame, "Optional decoy website")

        ctk.CTkLabel(
            frame,
            text="Advanced hardening",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(18, 8))
        self.constant_time = ctk.BooleanVar(value=True)
        self.cache_hardening = ctk.BooleanVar(value=True)
        self.algorithmic_noise = ctk.BooleanVar(value=False)
        self.lock_sensitive_memory = ctk.BooleanVar(value=True)
        self.guard_pages = ctk.BooleanVar(value=True)
        for label, variable in (
            ("Constant-time security comparisons", self.constant_time),
            ("Content-independent memory access where supported", self.cache_hardening),
            (
                "Algorithmic noise around cryptographic operations",
                self.algorithmic_noise,
            ),
            ("Lock sensitive memory to prevent swapping", self.lock_sensitive_memory),
            ("Use guard pages around protected allocations", self.guard_pages),
        ):
            self._checkbox(frame, label, variable)
        self.crypto_jitter = self._option(
            frame,
            "Maximum cryptographic jitter",
            ["0 ms", "1 ms", "2 ms", "5 ms", "10 ms", "25 ms"],
        )
        self.wipe_passes = self._option(frame, "Memory wipe passes", ["1", "2", "3"])
        self.lazy_page_size = self._option(
            frame,
            "Vault lazy-load page size",
            ["50", "100", "200", "250", "500", "1000"],
        )

        ctk.CTkLabel(
            frame, text="Secure clipboard", font=ctk.CTkFont(size=18, weight="bold")
        ).pack(anchor="w", padx=20, pady=(18, 8))
        self.clipboard_profile = self._option(
            frame,
            "Clipboard profile",
            ["Custom", "Standard", "Secure", "Public Computer"],
        )
        self.clipboard_profile.configure(command=self._clipboard_profile_changed)
        self.clipboard_timeout = self._option(
            frame, "Automatic clear", list(self.CLIPBOARD_TIMEOUTS)
        )
        self.clipboard_security = self._option(
            frame, "Security level", [item.value.title() for item in SecurityLevel]
        )

        self.clipboard_notifications = ctk.BooleanVar(value=True)
        self.block_suspicious = ctk.BooleanVar(value=False)
        self.ephemeral = ctk.BooleanVar(value=False)
        for label, variable in (
            ("Show clipboard notifications", self.clipboard_notifications),
            ("Block new copies after suspicious access", self.block_suspicious),
            ("Use session-only in-memory clipboard", self.ephemeral),
        ):
            self._checkbox(frame, label, variable)

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

    @staticmethod
    def _checkbox(frame, label: str, variable: ctk.BooleanVar) -> None:
        ctk.CTkCheckBox(
            frame,
            text=label,
            variable=variable,
            fg_color=PINK,
            hover_color=PINK_HOVER,
        ).pack(anchor="w", padx=20, pady=6)

    @staticmethod
    def _entry(frame, label: str) -> ctk.CTkEntry:
        ctk.CTkLabel(frame, text=label).pack(anchor="w", padx=20, pady=(8, 5))
        widget = ctk.CTkEntry(frame)
        widget.pack(fill="x", padx=20, pady=(0, 8))
        return widget

    def _clipboard_profile_changed(self, value: str) -> None:
        if value == "Custom":
            return
        self._set_clipboard_config(ClipboardConfig.profile(value))
        self.clipboard_profile.set(value)

    def _security_profile_changed(self, value: str) -> None:
        selected = SecurityProfile(value.casefold())
        device = DeviceType(self.device_type.get().casefold())
        proposed = SecurityHardeningConfig.for_profile(selected, device)
        changes = proposed.changes_from(self._security)
        self.profile_changes.configure(
            text="Profile changes:\n" + "\n".join(f"- {item}" for item in changes)
            if changes
            else "This profile matches the current security settings."
        )
        self._set_security_config(proposed, keep_change_text=True)

    def _set_clipboard_config(self, config: ClipboardConfig) -> None:
        timeout_label = next(
            label
            for label, seconds in self.CLIPBOARD_TIMEOUTS.items()
            if seconds == config.timeout_seconds
        )
        self.clipboard_timeout.set(timeout_label)
        self.clipboard_security.set(config.security_level.value.title())
        self.clipboard_notifications.set(config.notifications_enabled)
        self.block_suspicious.set(config.block_after_suspicious_access)
        self.ephemeral.set(config.ephemeral_mode)
        self.whitelist.delete("1.0", "end")
        self.whitelist.insert("1.0", "\n".join(config.application_whitelist))
        self.clipboard_profile.set("Custom")

    def _set_security_config(
        self, config: SecurityHardeningConfig, *, keep_change_text: bool = False
    ) -> None:
        self.security_profile.set(config.profile.value.title())
        self.device_type.set(config.device_type.value.title())
        self.activity_sensitivity.set(config.activity_sensitivity.value.title())
        timeout_label = next(
            label
            for label, seconds in self.AUTO_LOCK_TIMEOUTS.items()
            if seconds == config.auto_lock_timeout_seconds
        )
        self.auto_lock_timeout.set(timeout_label)
        self.clear_on_lock.set(config.clear_clipboard_on_lock)
        self.minimize_to_tray.set(config.minimize_to_tray)
        self.start_minimized.set(config.start_minimized_to_tray)
        self.tray_notifications.set(config.tray_notifications)
        self.panic_close.set(config.panic_close_application)
        self.panic_fake_error.set(config.panic_fake_error)
        self.lock_on_screen_lock.set(config.lock_on_screen_lock)
        self.hide_sensitive_windows.set(config.hide_sensitive_windows_on_lock)
        self.constant_time.set(config.constant_time_enabled)
        self.cache_hardening.set(config.cache_hardening_enabled)
        self.algorithmic_noise.set(config.algorithmic_noise_enabled)
        self.lock_sensitive_memory.set(config.lock_sensitive_memory)
        self.guard_pages.set(config.guard_pages_enabled)
        self.crypto_jitter.set(f"{config.crypto_jitter_max_ms:g} ms")
        self.wipe_passes.set(str(config.wipe_passes))
        self.lazy_page_size.set(str(config.lazy_load_page_size))
        for widget, value in (
            (self.panic_hotkey, config.panic_hotkey),
            (self.panic_decoy_command, shlex.join(config.panic_decoy_command)),
            (self.panic_decoy_url, config.panic_decoy_url),
        ):
            widget.delete(0, "end")
            widget.insert(0, value)
        if not keep_change_text:
            self.profile_changes.configure(
                text="Profile settings are validated before they are saved."
            )

    def _save(self) -> None:
        try:
            clipboard = ClipboardConfig(
                timeout_seconds=self.CLIPBOARD_TIMEOUTS[self.clipboard_timeout.get()],
                notifications_enabled=self.clipboard_notifications.get(),
                security_level=SecurityLevel(self.clipboard_security.get().casefold()),
                application_whitelist=tuple(
                    self.whitelist.get("1.0", "end-1c").splitlines()
                ),
                block_after_suspicious_access=self.block_suspicious.get(),
                ephemeral_mode=self.ephemeral.get(),
            )
            profile = SecurityProfile(self.security_profile.get().casefold())
            base = SecurityHardeningConfig.for_profile(
                profile, DeviceType(self.device_type.get().casefold())
            )
            security = replace(
                base,
                auto_lock_timeout_seconds=self.AUTO_LOCK_TIMEOUTS[
                    self.auto_lock_timeout.get()
                ],
                activity_sensitivity=ActivitySensitivity(
                    self.activity_sensitivity.get().casefold()
                ),
                clear_clipboard_on_lock=self.clear_on_lock.get(),
                hide_sensitive_windows_on_lock=self.hide_sensitive_windows.get(),
                lock_on_screen_lock=self.lock_on_screen_lock.get(),
                minimize_to_tray=self.minimize_to_tray.get(),
                start_minimized_to_tray=self.start_minimized.get(),
                tray_notifications=self.tray_notifications.get(),
                panic_close_application=self.panic_close.get(),
                panic_fake_error=self.panic_fake_error.get(),
                panic_hotkey=self.panic_hotkey.get().strip(),
                panic_decoy_command=tuple(
                    shlex.split(self.panic_decoy_command.get(), posix=os.name != "nt")
                ),
                panic_decoy_url=self.panic_decoy_url.get().strip(),
                constant_time_enabled=self.constant_time.get(),
                cache_hardening_enabled=self.cache_hardening.get(),
                algorithmic_noise_enabled=self.algorithmic_noise.get(),
                crypto_jitter_max_ms=float(
                    self.crypto_jitter.get().removesuffix(" ms")
                ),
                lock_sensitive_memory=self.lock_sensitive_memory.get(),
                guard_pages_enabled=self.guard_pages.get(),
                wipe_passes=int(self.wipe_passes.get()),
                lazy_load_page_size=int(self.lazy_page_size.get()),
            )
        except (KeyError, ValueError) as exc:
            messagebox.showerror("Settings", str(exc), parent=self)
            return

        changes = security.changes_from(self._security)
        if changes and not messagebox.askyesno(
            "Apply security profile",
            "The following security controls will change:\n\n"
            + "\n".join(f"- {item}" for item in changes)
            + "\n\nApply these settings?",
            parent=self,
        ):
            return
        self.result = ApplicationSettings(clipboard, security)
        self.destroy()

    def _choose_change_password(self) -> None:
        self.result = "change_master_password"
        self.destroy()
