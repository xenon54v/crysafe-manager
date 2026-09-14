from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import customtkinter as ctk

from src.core.clipboard import (
    ClipboardConfig,
    ClipboardService,
    ClipboardSnapshot,
    ClipboardState,
    ClipboardType,
    create_platform_adapter,
)
from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.config import ConfigManager
from src.core.crypto.authentication import AuthenticationService
from src.core.events import (
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
from src.database.settings_repo import SettingsRepository, SettingsRepositoryError
from src.gui.add_entry_dialog import AddEntryDialog
from src.gui.change_password_dialog import ChangePasswordDialog
from src.gui.clipboard_ui import (
    ClipboardPreviewDialog,
    ClipboardToast,
    TrayStatusIndicator,
)
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
        self.settings_repo: SettingsRepository | None = None
        self.clipboard_service: ClipboardService | None = None
        self.clipboard_monitor: ClipboardMonitor | None = None
        self.clipboard_config = ClipboardConfig()
        self.tray_indicator: TrayStatusIndicator | None = None
        self.master_password: str | None = None
        self.lock_overlay = None
        self.auth_dialog_open = False
        self._all_entries: list[dict] = []
        self._search_after_id: str | None = None
        self._passwords_visible = False
        self._clipboard_status_after_id: str | None = None
        self._last_clipboard_message = ""

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
                ("Clear Clipboard", self._manual_clear_clipboard),
                ("Preview", self._open_clipboard_preview),
            ),
            start=1,
        ):
            button = ctk.CTkButton(
                top,
                text=label,
                width=112,
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
            on_copy_all=self._copy_all_selected,
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
        status_frame = ctk.CTkFrame(self, fg_color="transparent")
        status_frame.grid(row=3, column=0, sticky="ew", padx=28, pady=(0, 12))
        status_frame.grid_columnconfigure(0, weight=1)
        self.status = ctk.CTkLabel(
            status_frame,
            text="Status: Locked",
            anchor="w",
            font=ctk.CTkFont(size=13),
        )
        self.status.grid(row=0, column=0, sticky="w")
        self.clipboard_status = ctk.CTkLabel(
            status_frame,
            text="Clipboard: empty",
            anchor="e",
            font=ctk.CTkFont(size=13),
        )
        self.clipboard_status.grid(row=0, column=1, sticky="e", padx=(18, 0))

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
        self.settings_repo = SettingsRepository(self.db, self.repo.key_manager)
        try:
            self.clipboard_config = self.settings_repo.load_clipboard_config()
        except SettingsRepositoryError as exc:
            self.clipboard_config = ClipboardConfig.profile("standard")
            self._show_error("Clipboard Settings", str(exc))
        self._start_clipboard_subsystem()
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
        if self.entry_manager is None or self.clipboard_service is None:
            return
        selected = self.table.get_selected_row()
        if selected is None:
            self._show_warning("Copy", "Select one entry first.")
            return
        try:
            entry_id = str(selected["id"])
            value = self.entry_manager.get_clipboard_value(
                entry_id, field, publish_event=False
            )
            value_type = {
                "username": ClipboardType.USERNAME,
                "password": ClipboardType.PASSWORD,
                "totp_secret": ClipboardType.TOTP,
            }.get(field, ClipboardType.TEXT)
            self.clipboard_service.copy_text(
                value,
                entry_id=entry_id,
                field=field,
                source=str(selected.get("title", "")),
                data_type=value_type,
            )
        except (EntryManagerError, PermissionError, ValueError, RuntimeError) as exc:
            self._show_error("Copy", str(exc))
            return

    def _copy_all_selected(self) -> None:
        self._copy_selected_field("all")

    def _manual_clear_clipboard(self) -> None:
        if self.clipboard_service is not None:
            self.clipboard_service.clear("manual")

    def _open_clipboard_preview(self) -> None:
        if (
            self.clipboard_service is None
            or not self.clipboard_service.has_sensitive_value
        ):
            self._show_info("Secure Clipboard", "The clipboard is empty.")
            return
        ClipboardPreviewDialog(
            self,
            self.clipboard_service.snapshot,
            self._reveal_clipboard_value,
        )

    def _reveal_clipboard_value(self) -> str:
        if self.clipboard_service is None:
            raise RuntimeError("The clipboard is empty.")
        return self.clipboard_service.reveal_current(
            self._authenticate_clipboard_preview
        )

    def _authenticate_clipboard_preview(self) -> bool:
        if self.repo is None or self.db is None:
            return False
        dialog = ctk.CTkInputDialog(
            text="Enter the master password to reveal the value:",
            title="Clipboard Authentication",
        )
        password = dialog.get_input()
        if password is None:
            return False
        row = self.db.execute(
            "SELECT hash FROM key_store WHERE key_type = ? LIMIT 1;", ("master",)
        ).fetchone()
        if row is None:
            return False
        stored_hash = row[0].decode("utf-8") if isinstance(row[0], bytes) else row[0]
        valid = self.repo.key_manager.verify_password(password, stored_hash)
        if not valid:
            self._show_error("Clipboard Authentication", "Invalid master password.")
        return valid

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

    def _start_clipboard_subsystem(self) -> None:
        if self.audit_repo is None:
            return
        adapter = create_platform_adapter(private=self.clipboard_config.ephemeral_mode)
        self.clipboard_service = ClipboardService(
            adapter,
            event_bus=self.event_bus,
            is_vault_unlocked=lambda: (
                self.repo is not None
                and self.entry_manager is not None
                and not self.state_manager.is_locked()
            ),
            config=self.clipboard_config,
            audit_callback=self.audit_repo.add_clipboard_log,
        )
        self.clipboard_service.add_observer(self)
        self.clipboard_service.install_signal_cleanup()
        self.clipboard_monitor = ClipboardMonitor(
            adapter,
            self.clipboard_service,
            poll_interval=1.0,
            on_degraded=self._clipboard_monitor_degraded,
        )
        self.clipboard_monitor.start()
        self.tray_indicator = TrayStatusIndicator(
            lambda: self.after(0, self._manual_clear_clipboard),
            lambda: self.after(0, self._on_close),
        )
        if not self.tray_indicator.start():
            self.audit_repo.add_clipboard_log(
                "clipboard_error", None, "operation=tray;fallback=status_bar"
            )
        self._apply_screen_capture_protection()
        self._schedule_clipboard_countdown()

    def clipboard_state_changed(self, snapshot: ClipboardSnapshot) -> None:
        try:
            self.after(
                0, lambda current=snapshot: self._apply_clipboard_snapshot(current)
            )
        except RuntimeError:
            pass

    def _apply_clipboard_snapshot(self, snapshot: ClipboardSnapshot) -> None:
        active_entry = (
            snapshot.entry_id
            if snapshot.state
            in {
                ClipboardState.ACTIVE,
                ClipboardState.WARNING,
            }
            else None
        )
        self.table.mark_clipboard_entry(active_entry)
        remaining = snapshot.remaining_seconds()
        if snapshot.state in {ClipboardState.ACTIVE, ClipboardState.WARNING}:
            timeout = "no timeout" if remaining is None else f"{remaining}s remaining"
            text = f"Clipboard: {snapshot.data_type.value if snapshot.data_type else 'text'} | {timeout}"
        elif snapshot.state is ClipboardState.ERROR:
            text = "Clipboard: clear/copy error"
        elif snapshot.state is ClipboardState.BLOCKED:
            text = "Clipboard: copying blocked"
        else:
            text = "Clipboard: empty"
        self.clipboard_status.configure(text=text)
        if self.tray_indicator is not None:
            self.tray_indicator.update(text.replace("Clipboard: ", ""))

        should_notify = (
            self.clipboard_config.notifications_enabled
            and snapshot.message
            and snapshot.message != self._last_clipboard_message
        )
        if should_notify:
            ClipboardToast(
                self,
                snapshot.message,
                warning=snapshot.state
                in {ClipboardState.WARNING, ClipboardState.ERROR},
            )
        self._last_clipboard_message = snapshot.message

    def _schedule_clipboard_countdown(self) -> None:
        if self._clipboard_status_after_id is not None:
            self.after_cancel(self._clipboard_status_after_id)
        self._clipboard_status_after_id = self.after(
            250, self._refresh_clipboard_countdown
        )

    def _refresh_clipboard_countdown(self) -> None:
        self._clipboard_status_after_id = None
        if self.clipboard_service is None:
            return
        snapshot = self.clipboard_service.snapshot
        if snapshot.state in {ClipboardState.ACTIVE, ClipboardState.WARNING}:
            self._apply_clipboard_snapshot(snapshot)
        self._clipboard_status_after_id = self.after(
            250, self._refresh_clipboard_countdown
        )

    def _clipboard_monitor_degraded(self, message: str) -> None:
        if self.audit_repo is not None:
            self.audit_repo.add_clipboard_log(
                "clipboard_error", None, "operation=monitor;mode=degraded"
            )
        try:
            self.after(0, lambda: self._show_warning("Clipboard Monitor", message))
        except RuntimeError:
            pass

    def _apply_screen_capture_protection(self) -> None:
        if (
            sys.platform != "win32"
            or self.clipboard_config.security_level.value == "basic"
        ):
            return
        try:
            import ctypes

            display_affinity_exclude = 0x00000011
            ctypes.windll.user32.SetWindowDisplayAffinity(
                self.winfo_id(), display_affinity_exclude
            )
        except (AttributeError, OSError):
            if self.audit_repo is not None:
                self.audit_repo.add_clipboard_log(
                    "clipboard_error", None, "operation=anti_screenshot"
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
        if self.db is None or self.settings_repo is None:
            self._show_warning("Settings", "Unlock the vault first.")
            return
        dialog = SettingsDialog(self, self.clipboard_config)
        self.wait_window(dialog)
        if dialog.result == "change_master_password":
            self._change_master_password()
        elif isinstance(dialog.result, ClipboardConfig):
            previous_ephemeral = self.clipboard_config.ephemeral_mode
            try:
                self.settings_repo.save_clipboard_config(dialog.result)
            except SettingsRepositoryError as exc:
                self._show_error("Clipboard Settings", str(exc))
                return
            self.clipboard_config = dialog.result
            if self.clipboard_service is not None:
                if previous_ephemeral != dialog.result.ephemeral_mode:
                    if self.clipboard_monitor is not None:
                        self.clipboard_monitor.stop()
                    adapter = create_platform_adapter(
                        private=dialog.result.ephemeral_mode
                    )
                    self.clipboard_service.replace_adapter(adapter)
                    self.clipboard_monitor = ClipboardMonitor(
                        adapter,
                        self.clipboard_service,
                        poll_interval=1.0,
                        on_degraded=self._clipboard_monitor_degraded,
                    )
                    self.clipboard_monitor.start()
                self.clipboard_service.update_config(dialog.result)
            self._apply_screen_capture_protection()

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
        self.settings_repo = None
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
        if self.clipboard_monitor is not None:
            self.clipboard_monitor.stop()
            self.clipboard_monitor = None
        if self.clipboard_service is not None:
            self.clipboard_service.clear("vault_lock")
            self.clipboard_service.remove_observer(self)
            self.clipboard_service = None
        if self.tray_indicator is not None:
            self.tray_indicator.stop()
            self.tray_indicator = None
        if self._clipboard_status_after_id is not None:
            self.after_cancel(self._clipboard_status_after_id)
            self._clipboard_status_after_id = None
        self.clipboard_status.configure(text="Clipboard: empty")
        if self.repo is not None:
            self.repo.key_manager.lock()

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
            "CryptoSafe Manager\n\nSprint 4\nAES-256-GCM encrypted local vault\n"
            "Secure cross-platform clipboard, automatic clearing, monitoring, and encrypted settings.",
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
