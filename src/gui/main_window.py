from __future__ import annotations

import sqlite3
import tkinter as tk
from contextlib import suppress
from datetime import datetime, timedelta, timezone

import customtkinter as ctk

from src.core.config import ConfigManager
from src.core.crypto.authentication import AuthenticationService
from src.core.events import (
    ClipboardCleared,
    EventBus,
    UserLoggedIn,
    UserLoggedOut,
    now_utc,
)
from src.core.state_manager import StateManager
from src.core.vault.entry_manager import EntryManager, EntryManagerError
from src.core.vault.search_service import SearchFilters, VaultSearchIndex
from src.core.vault.url_tools import extract_domain
from src.database.audit_repo import AuditRepository
from src.database.db import Database
from src.database.repo import VaultRepository
from src.gui.add_entry_dialog import AddEntryDialog
from src.gui.change_password_dialog import ChangePasswordDialog
from src.gui.edit_entry_dialog import EditEntryDialog
from src.gui.settings_dialog import SettingsDialog
from src.gui.setup_wizard import LoginDialog, SetupWizard
from src.gui.widgets.app_menu_bar import AppMenuBar
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.widgets.custom_dialog import CustomDialog
from src.gui.widgets.secure_table import SecureTable

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"


class MainWindow(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.db: Database | None = None
        self.repo: VaultRepository | None = None
        self.entry_manager: EntryManager | None = None
        self.audit_repo: AuditRepository | None = None
        self.master_password: str | None = None
        self.lock_overlay = None
        self.auth_dialog_open = False
        self._all_entries: list[dict] = []
        self._search_after_id: str | None = None
        self._passwords_visible = False
        self._clipboard_after_id: str | None = None

        self.state_manager = StateManager(on_auto_lock=self._handle_auto_lock)
        self.auth_service = AuthenticationService()
        self.event_bus = EventBus()
        self.search_index = VaultSearchIndex(self.event_bus)

        self.title("CryptoSafe Manager")
        self.geometry("1240x780")
        self.minsize(980, 620)
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._create_app_menu()
        self._create_header()
        self._create_table()
        self._create_status_bar()
        self._bind_shortcuts()

        self.after(100, self._start_auth_flow)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _create_app_menu(self) -> None:
        self.menu_bar = AppMenuBar(
            self,
            actions={
                "new": self._on_new,
                "open": self._on_open,
                "backup": self._on_backup,
                "logout": self._logout,
                "exit": self._on_close,
                "add": self._add_entry,
                "edit": self._edit_entry,
                "delete": self._delete_entry,
                "logs": self._open_logs,
                "settings": self._open_settings,
                "about": self._on_about,
            },
        )
        self.menu_bar.grid(row=0, column=0, sticky="ew")

    def _create_header(self) -> None:
        self.header = ctk.CTkFrame(self, corner_radius=0)
        self.header.grid(row=1, column=0, sticky="ew")
        self.header.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(self.header, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=20, pady=(12, 6))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            top,
            text="CryptoSafe Manager",
            font=ctk.CTkFont(size=24, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        for column, (label, command) in enumerate(
            (
                ("Add", self._add_entry),
                ("Edit", self._edit_entry),
                ("Delete", self._delete_entry),
                ("Show Passwords", self._toggle_all_passwords),
            ),
            start=1,
        ):
            button = ctk.CTkButton(
                top,
                text=label,
                width=120,
                command=command,
                fg_color=PINK,
                hover_color=PINK_HOVER,
            )
            button.grid(row=0, column=column, padx=(8, 0))
            if label == "Show Passwords":
                self.password_toggle_button = button

        filters = ctk.CTkFrame(self.header, fg_color="transparent")
        filters.grid(row=1, column=0, sticky="ew", padx=20, pady=(4, 12))
        filters.grid_columnconfigure(0, weight=1)

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", self._schedule_search)
        self.search_box = ctk.CTkComboBox(
            filters,
            values=[""],
            variable=self.search_var,
            state="normal",
            width=420,
        )
        self.search_box.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.search_box.set("")

        self.category_filter = ctk.CTkComboBox(
            filters,
            values=["All categories"],
            width=170,
            command=lambda _value: self._apply_search(),
        )
        self.category_filter.grid(row=0, column=1, padx=5)
        self.category_filter.set("All categories")

        self.date_filter = ctk.CTkComboBox(
            filters,
            values=["Any date", "Last 7 days", "Last 30 days", "Last year"],
            width=150,
            command=lambda _value: self._apply_search(),
        )
        self.date_filter.grid(row=0, column=2, padx=5)
        self.date_filter.set("Any date")

        self.strength_filter = ctk.CTkComboBox(
            filters,
            values=["Any strength", "Strong", "Very strong"],
            width=150,
            command=lambda _value: self._apply_search(),
        )
        self.strength_filter.grid(row=0, column=3, padx=(5, 0))
        self.strength_filter.set("Any strength")

    def _create_table(self) -> None:
        self.table_frame = ctk.CTkFrame(self, corner_radius=18)
        self.table_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=14)
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        self.table = SecureTable(
            self.table_frame,
            on_edit=self._edit_entry,
            on_delete=self._delete_entry,
            on_copy_username=lambda: self._copy_selected_field("username"),
            on_copy_password=lambda: self._copy_selected_field("password"),
        )
        self.table.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        self.lock_overlay = ctk.CTkFrame(
            self.table_frame,
            corner_radius=18,
            fg_color=("#ececec", "#1f1f1f"),
        )
        self.lock_overlay.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.lock_overlay.grid_columnconfigure(0, weight=1)
        self.lock_overlay.grid_rowconfigure(0, weight=1)
        self.lock_overlay.grid_rowconfigure(4, weight=1)
        ctk.CTkLabel(
            self.lock_overlay,
            text="Vault is locked",
            font=ctk.CTkFont(size=28, weight="bold"),
        ).grid(row=1, column=0, pady=(0, 8))
        ctk.CTkLabel(
            self.lock_overlay,
            text="Unlock the vault to view saved entries.",
            text_color=("gray35", "gray70"),
        ).grid(row=2, column=0, pady=(0, 18))
        ctk.CTkButton(
            self.lock_overlay,
            text="Unlock Vault",
            width=160,
            command=self._unlock_from_overlay,
            fg_color=PINK,
            hover_color=PINK_HOVER,
        ).grid(row=3, column=0, sticky="n")
        self._show_lock_overlay()

    def _create_status_bar(self) -> None:
        self.status = ctk.CTkLabel(
            self,
            text="Status: Locked",
            anchor="w",
            font=ctk.CTkFont(size=13),
        )
        self.status.grid(row=3, column=0, sticky="ew", padx=28, pady=(0, 12))

    def _bind_shortcuts(self) -> None:
        self.bind("<Control-n>", lambda _event: self._add_entry())
        self.bind("<Delete>", lambda _event: self._delete_entry())
        self.bind("<Control-Shift-P>", lambda _event: self._toggle_all_passwords())
        self.bind("<Control-Shift-p>", lambda _event: self._toggle_all_passwords())

    def _start_auth_flow(self) -> None:
        db_path = ConfigManager().load().db_path
        if not db_path.exists():
            self._show_setup_wizard()
            return

        try:
            db = Database(db_path)
            db.connect()
            row = db.execute(
                "SELECT 1 FROM key_store WHERE key_type = ? LIMIT 1;", ("master",)
            ).fetchone()
            has_password = row is not None
            db.close()
        except (OSError, RuntimeError, sqlite3.Error):
            self._show_setup_wizard()
            return

        if has_password:
            self._show_login_dialog(db_path)
        else:
            self._show_setup_wizard()

    def _show_setup_wizard(self) -> None:
        wizard = SetupWizard(self)
        self.wait_window(wizard)
        if wizard.result is None:
            self.destroy()
            return

        result = wizard.result
        self.db = Database(result.db_path)
        self.db.connect()
        self.master_password = result.master_password
        self.repo = VaultRepository(self.db)
        self.repo.key_manager.unlock_with_password(self.db, self.master_password)
        self._finish_unlock(initial_setup=True)

    def _show_login_dialog(self, db_path) -> None:
        if self.auth_dialog_open:
            return
        self.auth_dialog_open = True
        login = LoginDialog(self)
        self.wait_window(login)
        self.auth_dialog_open = False

        if login.result is None:
            self._show_lock_overlay()
            self.status.configure(text="Status: Locked")
            return

        self.db = Database(db_path)
        self.db.connect()
        self.repo = VaultRepository(self.db)
        try:
            self.repo.key_manager.unlock_with_password(
                self.db, login.result.master_password
            )
        except ValueError:
            attempts = self.auth_service.register_failed_attempt()
            delay = self.auth_service.get_backoff_delay()
            AuditRepository(self.db).add_log(
                action="failed_login", details=f"Failed login attempt {attempts}"
            )
            self._show_error(
                "Login Error",
                f"Invalid master password. Try again in {delay} seconds.",
            )
            self.auth_service.apply_backoff_delay()
            self.db.close()
            self.db = None
            self.repo = None
            self.after(100, lambda: self._show_login_dialog(db_path))
            return

        self.master_password = login.result.master_password
        self._finish_unlock(initial_setup=False)

    def _finish_unlock(self, initial_setup: bool) -> None:
        if self.db is None or self.repo is None:
            return
        self.audit_repo = AuditRepository(self.db)
        self.entry_manager = EntryManager(
            self.db,
            self.repo.key_manager,
            event_bus=self.event_bus,
        )
        self.auth_service.login("local_user")
        self.state_manager.login("local_user")
        self.state_manager.start_inactivity_timer(self._get_auto_lock_timeout())
        self.audit_repo.add_log(
            action="login",
            details="Initial vault setup" if initial_setup else "Successful login",
        )
        self.event_bus.publish(UserLoggedIn("UserLoggedIn", now_utc(), "local_user"))
        self._hide_lock_overlay()
        self._load_entries()

    def _load_entries(self) -> None:
        if self.entry_manager is None:
            return
        try:
            self._all_entries = self.entry_manager.get_all_entries()
        except EntryManagerError as exc:
            self._show_error("Vault Error", str(exc))
            return

        self.search_index.rebuild(self._all_entries)
        categories = sorted(
            {
                entry.get("category", "")
                for entry in self._all_entries
                if entry.get("category")
            },
            key=str.casefold,
        )
        self.category_filter.configure(values=["All categories", *categories])
        if self.category_filter.get() not in ["All categories", *categories]:
            self.category_filter.set("All categories")
        self._apply_search()

    def _schedule_search(self, *_args) -> None:
        if self._search_after_id is not None:
            self.after_cancel(self._search_after_id)
        self._search_after_id = self.after(120, self._apply_search)

    def _apply_search(self) -> None:
        self._search_after_id = None
        if self.entry_manager is None:
            return

        now = datetime.now(timezone.utc)
        date_ranges = {
            "Last 7 days": now - timedelta(days=7),
            "Last 30 days": now - timedelta(days=30),
            "Last year": now - timedelta(days=365),
        }
        strength_levels = {"Strong": 3, "Very strong": 4}
        category = self.category_filter.get()
        filters = SearchFilters(
            category="" if category == "All categories" else category,
            updated_from=date_ranges.get(self.date_filter.get()),
            minimum_strength=strength_levels.get(self.strength_filter.get()),
        )
        results = self.search_index.search(self.search_var.get(), filters)
        self.table.set_rows(results)
        if self.search_index.history:
            self.search_box.configure(values=list(reversed(self.search_index.history)))
        self.status.configure(
            text=f"Status: Unlocked | Showing {len(results)} of {len(self._all_entries)} entries"
        )

    def _add_entry(self) -> None:
        if self.entry_manager is None:
            self._show_warning("Add Entry", "Unlock the vault first.")
            return
        dialog = AddEntryDialog(
            self,
            generator=self.entry_manager.password_generator,
            username_suggester=self._suggest_usernames,
        )
        self.wait_window(dialog)
        if dialog.result is None:
            return
        try:
            self.entry_manager.create_entry(dialog.result.to_dict())
        except EntryManagerError as exc:
            self._show_error("Add Entry", str(exc))
            return
        self._load_entries()

    def _edit_entry(self) -> None:
        if self.entry_manager is None:
            self._show_warning("Edit Entry", "Unlock the vault first.")
            return
        selected = self.table.get_selected_row()
        if selected is None:
            self._show_warning("Edit Entry", "Select one entry first.")
            return

        dialog = EditEntryDialog(
            self,
            entry=selected,
            generator=self.entry_manager.password_generator,
            username_suggester=self._suggest_usernames,
        )
        self.wait_window(dialog)
        if dialog.result is None:
            return
        try:
            self.entry_manager.update_entry(
                str(selected["id"]), dialog.result.to_dict()
            )
        except EntryManagerError as exc:
            self._show_error("Edit Entry", str(exc))
            return
        self._load_entries()

    def _delete_entry(self) -> None:
        if self.entry_manager is None:
            self._show_warning("Delete Entry", "Unlock the vault first.")
            return
        entry_ids = self.table.get_selected_entry_ids()
        if not entry_ids:
            self._show_warning("Delete Entry", "Select at least one entry first.")
            return
        if not self._ask_yes_no(
            "Delete Entry",
            f"Move {len(entry_ids)} selected entr{'y' if len(entry_ids) == 1 else 'ies'} to deleted items?",
        ):
            return
        try:
            for entry_id in entry_ids:
                self.entry_manager.delete_entry(entry_id, soft_delete=True)
        except EntryManagerError as exc:
            self._show_error("Delete Entry", str(exc))
            return
        self._load_entries()

    def _copy_selected_field(self, field: str) -> None:
        if self.entry_manager is None:
            return
        entry_id = self.table.get_selected_entry_id()
        if entry_id is None:
            self._show_warning("Copy", "Select one entry first.")
            return
        try:
            value = self.entry_manager.get_clipboard_value(str(entry_id), field)
        except EntryManagerError as exc:
            self._show_error("Copy", str(exc))
            return

        self.clipboard_clear()
        self.clipboard_append(value)
        self.state_manager.set_clipboard(value, timeout_seconds=10)
        if self._clipboard_after_id is not None:
            self.after_cancel(self._clipboard_after_id)
        self._clipboard_after_id = self.after(10_000, self._clear_system_clipboard)
        self.status.configure(
            text=f"Status: Unlocked | {field.title()} copied for 10 seconds"
        )

    def _clear_system_clipboard(self) -> None:
        self._clipboard_after_id = None
        with suppress(tk.TclError):
            self.clipboard_clear()
        self.state_manager.clear_clipboard()
        self.event_bus.publish(ClipboardCleared("ClipboardCleared", now_utc(), "timer"))

    def _toggle_all_passwords(self) -> None:
        self._passwords_visible = not self._passwords_visible
        self.table.set_passwords_visible(self._passwords_visible)
        self.password_toggle_button.configure(
            text="Hide Passwords" if self._passwords_visible else "Show Passwords"
        )

    def _suggest_usernames(self, url: str) -> list[str]:
        domain = extract_domain(url)
        return sorted(
            {
                str(entry.get("username", ""))
                for entry in self._all_entries
                if entry.get("username")
                and extract_domain(str(entry.get("url", ""))) == domain
            },
            key=str.casefold,
        )

    def _change_master_password(self) -> None:
        if self.repo is None or self.audit_repo is None:
            self._show_warning("Change Password", "Unlock the vault first.")
            return
        dialog = ChangePasswordDialog(self)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        try:
            self.repo.change_master_password(
                dialog.result["old_password"], dialog.result["new_password"]
            )
        except ValueError:
            self._show_error("Change Password", "Current master password is incorrect.")
            return
        self.master_password = dialog.result["new_password"]
        self.audit_repo.add_log(
            action="change_master_password", details="Vault entries re-encrypted"
        )
        self._show_info("Change Password", "Master password changed successfully.")

    def _open_logs(self) -> None:
        if self.audit_repo is None:
            self._show_warning("Logs", "Unlock the vault first.")
            return
        AuditLogViewer(self, self.audit_repo)

    def _open_settings(self) -> None:
        if self.db is None:
            self._show_warning("Settings", "Unlock the vault first.")
            return
        dialog = SettingsDialog(self)
        self.wait_window(dialog)
        if dialog.result == "change_master_password":
            self._change_master_password()

    def _get_auto_lock_timeout(self) -> int:
        if self.db is None:
            return 300
        row = self.db.execute(
            "SELECT setting_value FROM settings WHERE setting_key = ?;",
            ("auto_lock_timeout",),
        ).fetchone()
        try:
            return int(row[0]) if row is not None else 300
        except (TypeError, ValueError):
            return 300

    def _logout(self) -> None:
        if self.entry_manager is None:
            return
        if self.audit_repo is not None:
            self.audit_repo.add_log(action="logout", details="User logged out")
        self.event_bus.publish(UserLoggedOut("UserLoggedOut", now_utc(), "local_user"))
        db_path = self.db.path if self.db is not None else None
        self._clear_sensitive_data()
        self.auth_service.logout()
        self.state_manager.logout()
        self._show_lock_overlay()
        self.status.configure(text="Status: Locked")
        if self.db is not None:
            self.db.close()
        self.db = None
        self.repo = None
        self.entry_manager = None
        self.audit_repo = None
        if db_path is not None:
            self.after(100, lambda: self._show_login_dialog(db_path))

    def _handle_auto_lock(self) -> None:
        self.after(0, self._logout)

    def _clear_sensitive_data(self) -> None:
        self.master_password = None
        self._all_entries.clear()
        self.search_index.clear()
        self.search_index.clear_history()
        self.table.clear_sensitive_data()
        self._passwords_visible = False
        self.password_toggle_button.configure(text="Show Passwords")
        if self.entry_manager is not None:
            self.entry_manager.password_generator.clear_history()
        if self.repo is not None:
            self.repo.key_manager.lock()
        if self._clipboard_after_id is not None:
            self.after_cancel(self._clipboard_after_id)
            self._clipboard_after_id = None
        self._clear_system_clipboard()

    def _unlock_from_overlay(self) -> None:
        if self.auth_dialog_open:
            return
        db_path = (
            self.db.path if self.db is not None else ConfigManager().load().db_path
        )
        self._show_login_dialog(db_path)

    def _show_lock_overlay(self) -> None:
        if self.lock_overlay is not None:
            self.lock_overlay.lift()

    def _hide_lock_overlay(self) -> None:
        if self.lock_overlay is not None:
            self.lock_overlay.lower()

    def _on_new(self) -> None:
        self._show_info(
            "New Vault", "Vault creation is handled by the first-run setup."
        )

    def _on_open(self) -> None:
        self._show_info(
            "Open Vault", "Set CRYPTOSAFE_DB_PATH before launch to open another vault."
        )

    def _on_backup(self) -> None:
        self._show_info("Backup", "Backup will be implemented in Sprint 8.")

    def _on_about(self) -> None:
        self._show_info(
            "About",
            "CryptoSafe Manager\n\nSprint 3\nAES-256-GCM encrypted local vault\n"
            "Secure password generation, search, filtering, and encrypted CRUD operations.",
        )

    def _on_close(self) -> None:
        if self.audit_repo is not None:
            self.audit_repo.add_log(action="app_close", details="Application closed")
        self._clear_sensitive_data()
        self.state_manager.stop_timers()
        if self.db is not None:
            self.db.close()
        if hasattr(self, "menu_bar"):
            self.menu_bar.close_dropdown()
        self.destroy()

    def _show_info(self, title: str, message: str) -> None:
        dialog = CustomDialog(self, title=title, message=message, dialog_type="info")
        self.wait_window(dialog)

    def _show_warning(self, title: str, message: str) -> None:
        dialog = CustomDialog(self, title=title, message=message, dialog_type="warning")
        self.wait_window(dialog)

    def _show_error(self, title: str, message: str) -> None:
        dialog = CustomDialog(self, title=title, message=message, dialog_type="error")
        self.wait_window(dialog)

    def _ask_yes_no(self, title: str, message: str) -> bool:
        dialog = CustomDialog(
            self, title=title, message=message, dialog_type="question"
        )
        self.wait_window(dialog)
        return bool(dialog.result)


def run() -> None:
    app = MainWindow()
    app.mainloop()
