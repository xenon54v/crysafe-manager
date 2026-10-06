from __future__ import annotations

import logging
import sqlite3
import subprocess
import sys
import time
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from src.core.audit import (
    AuditConfig,
    AuditEventBridge,
    AuditExportScheduler,
    AuditLogExporter,
    AuditLogger,
)
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
    ConfigurationChanged,
    EventBus,
    MasterPasswordChanged,
    SecurityAlert,
    SystemActivity,
    UserLoggedIn,
    UserLoggedOut,
    now_utc,
)
from src.core.import_export import (
    KeyExchangeService,
    QRCodeService,
    SharingService,
    VaultExporter,
    VaultImporter,
)
from src.core.security import (
    ActivityMonitor,
    MemoryGuard,
    PanicMode,
    SecurityHardeningConfig,
    SideChannelProtection,
)
from src.core.security.panic_mode import MouseShakeDetector
from src.core.state_manager import StateManager
from src.core.vault.encryption_service import AESGCMEncryptionService
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
)
from src.gui.edit_entry_dialog import EditEntryDialog
from src.gui.exchange_dialogs import (
    ContactsDialog,
    ExportDialog,
    ImportDialog,
    ReceiveShareDialog,
    SharingDialog,
)
from src.gui.qr_viewer import QRCodeViewer
from src.gui.settings_dialog import ApplicationSettings, SettingsDialog
from src.gui.theme import ERROR, PINK, PINK_HOVER, SUCCESS, WARNING
from src.gui.setup_wizard import LoginDialog, SetupWizard
from src.gui.tray_service import (
    SecurityTrayService,
    TrayCallbacks,
    TraySecurityState,
)
from src.gui.widgets.app_menu_bar import AppMenuBar
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.widgets.custom_dialog import CustomDialog
from src.gui.widgets.secure_table import SecureTable

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

LOGGER = logging.getLogger(__name__)


class MainWindow(ctk.CTk):
    """Coordinate the desktop interface and all application services."""

    def __init__(self) -> None:
        super().__init__()
        self.db: Database | None = None
        self.repo: VaultRepository | None = None
        self.entry_manager: EntryManager | None = None
        self.audit_repo: AuditRepository | None = None
        self.audit_logger: AuditLogger | None = None
        self.audit_bridge: AuditEventBridge | None = None
        self.vault_exporter: VaultExporter | None = None
        self.vault_importer: VaultImporter | None = None
        self.sharing_service: SharingService | None = None
        self.key_exchange_service: KeyExchangeService | None = None
        self.qr_service: QRCodeService | None = None
        self.audit_config = AuditConfig()
        self.settings_repo: SettingsRepository | None = None
        self.clipboard_service: ClipboardService | None = None
        self.clipboard_monitor: ClipboardMonitor | None = None
        self.clipboard_config = ClipboardConfig()
        self.security_config = SecurityHardeningConfig()
        self.tray_service: SecurityTrayService | None = None
        self.activity_monitor: ActivityMonitor | None = None
        self.panic_mode: PanicMode | None = None
        self.memory_guard = MemoryGuard()
        self.side_channel_protection = SideChannelProtection()
        self.master_password: str | None = None
        self.lock_overlay = None
        self.auth_dialog_open = False
        self._all_entries: list[dict] = []
        self._search_after_id: str | None = None
        self._passwords_visible = False
        self._clipboard_status_after_id: str | None = None
        self._audit_verification_after_id: str | None = None
        self._last_clipboard_message = ""
        self._total_entry_count = 0
        self._restore_state: dict | None = None
        self._normal_geometry = "1240x780"
        self._panic_binding: str | None = None
        self._shake_detector = MouseShakeDetector(
            lambda: self._activate_panic("window_shake")
        )

        self.state_manager = StateManager(on_auto_lock=self._handle_auto_lock)
        self.auth_service = AuthenticationService()
        self.event_bus = EventBus()
        self.search_index = VaultSearchIndex(
            self.event_bus,
            side_channel_protection=self.side_channel_protection,
        )

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

        self._ensure_tray_service()
        self.after(100, self._start_auth_flow)
        self.protocol("WM_DELETE_WINDOW", self._minimize_or_close)
        self.bind("<Unmap>", self._handle_minimize, add="+")
        self.bind("<Configure>", self._handle_window_motion, add="+")

    def _create_app_menu(self) -> None:
        self.menu_bar = AppMenuBar(
            self,
            actions={
                "new": self._on_new,
                "open": self._on_open,
                "backup": self._on_backup,
                "export": self._open_export,
                "import": self._open_import,
                "logout": self._logout,
                "exit": self._on_close,
                "add": self._add_entry,
                "edit": self._edit_entry,
                "delete": self._delete_entry,
                "share": self._share_entry,
                "receive_share": self._receive_share,
                "logs": self._open_logs,
                "contacts": self._open_contacts,
                "settings": self._open_settings,
                "lock": lambda: self._logout("manual_lock"),
                "panic": lambda: self._activate_panic("menu"),
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
                ("Share", self._share_entry),
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
        self.load_more_button = ctk.CTkButton(
            status_frame,
            text="Load More",
            width=92,
            height=26,
            command=self._load_more_entries,
            state="disabled",
        )
        self.load_more_button.grid(row=0, column=1, sticky="e", padx=(12, 0))
        self.audit_status = ctk.CTkLabel(
            status_frame,
            text="Audit: locked",
            anchor="e",
            font=ctk.CTkFont(size=13),
            text_color="gray70",
        )
        self.audit_status.grid(row=0, column=2, sticky="e", padx=(18, 0))
        self.security_status = ctk.CTkLabel(
            status_frame,
            text="Security: locked",
            anchor="e",
            font=ctk.CTkFont(size=13),
            text_color=ERROR,
        )
        self.security_status.grid(row=0, column=3, sticky="e", padx=(18, 0))
        self.clipboard_status = ctk.CTkLabel(
            status_frame,
            text="Clipboard: empty",
            anchor="e",
            font=ctk.CTkFont(size=13),
        )
        self.clipboard_status.grid(row=0, column=4, sticky="e", padx=(18, 0))

    def _bind_shortcuts(self) -> None:
        self.bind("<Control-n>", lambda _event: self._add_entry())
        self.bind("<Delete>", lambda _event: self._delete_entry())
        self.bind("<Control-Shift-P>", lambda _event: self._toggle_all_passwords())
        self.bind("<Control-Shift-p>", lambda _event: self._toggle_all_passwords())
        self.bind("<Control-l>", lambda _event: self._logout("keyboard"))
        self.bind("<Control-f>", lambda _event: self._focus_search())
        self.bind("<Control-e>", lambda _event: self._open_export())
        self.bind("<Control-i>", lambda _event: self._open_import())
        self.bind("<Return>", lambda _event: self._edit_entry())
        self._bind_panic_hotkey(self.security_config.panic_hotkey)
        for sequence, activity_type in (
            ("<Motion>", "mouse_move"),
            ("<Button>", "mouse_click"),
            ("<Key>", "keyboard"),
            ("<FocusIn>", "focus"),
        ):
            self.bind_all(
                sequence,
                lambda _event, kind=activity_type: self._record_activity(kind),
                add="+",
            )

    def _bind_panic_hotkey(self, sequence: str) -> None:
        if self._panic_binding:
            self.unbind(self._panic_binding)
        self._panic_binding = sequence
        self.bind(sequence, lambda _event: self._activate_panic("hotkey"), add="+")

    def _focus_search(self) -> None:
        self._restore_main_window()
        self.search_box.focus_set()

    def _record_activity(self, activity_type: str) -> None:
        if self.activity_monitor is not None:
            self.activity_monitor.record_activity(activity_type)

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
                action="AUTH_LOGIN_FAILURE",
                details=f"attempt_count={attempts};source=local",
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
        self.auth_service.login("local_user")
        self.state_manager.login("local_user")
        self.settings_repo = SettingsRepository(self.db, self.repo.key_manager)
        try:
            self.clipboard_config = self.settings_repo.load_clipboard_config()
        except SettingsRepositoryError as exc:
            self.clipboard_config = ClipboardConfig.profile("standard")
            self._show_error("Clipboard Settings", str(exc))
        try:
            self.audit_config = self.settings_repo.load_audit_config()
        except SettingsRepositoryError as exc:
            self.audit_config = AuditConfig()
            self._show_error("Audit Settings", str(exc))
        try:
            self.security_config = self.settings_repo.load_security_config()
        except SettingsRepositoryError as exc:
            self.security_config = SecurityHardeningConfig()
            self._show_error("Security Settings", str(exc))

        self.entry_manager = EntryManager(
            self.db,
            self.repo.key_manager,
            event_bus=self.event_bus,
        )

        self.audit_logger = AuditLogger(
            self.db,
            self.repo.key_manager,
            self.audit_config,
            is_authenticated=lambda: (
                self.entry_manager is not None and not self.state_manager.is_locked()
            ),
            on_tamper=self._handle_audit_tamper,
        )
        self.audit_bridge = AuditEventBridge(self.event_bus, self.audit_logger)
        self.audit_repo = AuditRepository(self.db, self.audit_logger)
        self.vault_exporter = VaultExporter(
            self.entry_manager,
            self.repo.key_manager,
            db=self.db,
            audit_logger=self.audit_logger,
            interrupt_check=self._check_panic_interruption,
        )
        self.vault_importer = VaultImporter(
            self.entry_manager,
            db=self.db,
            audit_logger=self.audit_logger,
            interrupt_check=self._check_panic_interruption,
        )
        self.sharing_service = SharingService(
            self.entry_manager,
            db=self.db,
            audit_logger=self.audit_logger,
        )
        self.key_exchange_service = KeyExchangeService(
            self.db, audit_logger=self.audit_logger
        )
        self.qr_service = QRCodeService(self.db)
        self._start_security_subsystem()
        self._start_clipboard_subsystem()
        self.event_bus.publish(
            SystemActivity(
                "SystemActivity",
                now_utc(),
                "SYSTEM_STARTUP" if initial_setup else "SYSTEM_UNLOCK",
                "INFO",
                {"initial_setup": initial_setup},
            )
        )
        self.event_bus.publish(UserLoggedIn("UserLoggedIn", now_utc(), "local_user"))
        self._hide_lock_overlay()
        if self.tray_service is not None:
            self.tray_service.set_state(TraySecurityState.UNLOCKED)
        self.security_status.configure(
            text=f"Security: {self.security_config.profile.value}",
            text_color=SUCCESS,
        )
        self._load_entries()
        self._restore_previous_state()
        self.audit_status.configure(text="Audit: checking", text_color=WARNING)
        self.after(50, self._run_startup_audit_verification)
        if self.security_config.start_minimized_to_tray:
            self.after(100, self._minimize_to_tray)

    def _load_entries(self) -> None:
        if self.entry_manager is None:
            return
        try:
            self._total_entry_count = self.entry_manager.count_entries()
            self._all_entries = self.entry_manager.get_entries_page(
                offset=0,
                limit=self.security_config.lazy_load_page_size,
            )
        except EntryManagerError as exc:
            self._show_error("Vault Error", str(exc))
            return
        self._refresh_entry_index()

    def _load_more_entries(self, *, refresh: bool = True) -> None:
        if self.entry_manager is None:
            return
        if len(self._all_entries) >= self._total_entry_count:
            return
        try:
            page = self.entry_manager.get_entries_page(
                offset=len(self._all_entries),
                limit=self.security_config.lazy_load_page_size,
            )
        except EntryManagerError as exc:
            self._show_error("Vault Error", str(exc))
            return
        self._all_entries.extend(page)
        if refresh:
            self._refresh_entry_index()

    def _refresh_entry_index(self) -> None:
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
        self.load_more_button.configure(
            state="normal"
            if len(self._all_entries) < self._total_entry_count
            else "disabled"
        )
        self._apply_search()

    def _schedule_search(self, *_args) -> None:
        if self._search_after_id is not None:
            self.after_cancel(self._search_after_id)
        self._search_after_id = self.after(120, self._apply_search)

    def _apply_search(self) -> None:
        self._search_after_id = None
        if self.entry_manager is None:
            return

        if (
            self.search_var.get().strip()
            and len(self._all_entries) < self._total_entry_count
        ):
            loaded_any = False
            while len(self._all_entries) < self._total_entry_count:
                previous_count = len(self._all_entries)
                self._load_more_entries(refresh=False)
                if len(self._all_entries) == previous_count:
                    break
                loaded_any = True
            if loaded_any:
                self._refresh_entry_index()
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
            text=(
                f"Status: Unlocked | Showing {len(results)} of "
                f"{self._total_entry_count} entries "
                f"({len(self._all_entries)} loaded)"
            )
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
        return self._confirm_master_password("Clipboard Authentication")

    def _confirm_master_password(
        self, title: str = "Master Password Confirmation"
    ) -> bool:
        if self.repo is None or self.db is None:
            return False
        dialog = ctk.CTkInputDialog(
            text="Enter the master password to continue:",
            title=title,
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
            self._show_error(title, "Invalid master password.")
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

    def _ensure_tray_service(self) -> None:
        if self.tray_service is not None:
            return
        callbacks = TrayCallbacks(
            lock_or_unlock=lambda: self._schedule_ui(self._tray_lock_or_unlock),
            show_window=lambda: self._schedule_ui(self._restore_main_window),
            quick_search=lambda: self._schedule_ui(self._focus_search),
            clear_clipboard=lambda: self._schedule_ui(self._manual_clear_clipboard),
            panic=lambda: self._schedule_ui(
                lambda: self._activate_panic("system_tray")
            ),
            settings=lambda: self._schedule_ui(self._open_settings),
            exit_application=lambda: self._schedule_ui(self._on_close),
        )
        self.tray_service = SecurityTrayService(callbacks)
        if not self.tray_service.start():
            self.status.configure(
                text="Status: Tray unavailable; main window remains active"
            )

    def _schedule_ui(self, callback) -> None:
        try:
            self.after(0, callback)
        except RuntimeError:
            return

    def _tray_lock_or_unlock(self) -> None:
        if self.state_manager.is_locked():
            self._restore_main_window()
            self._unlock_from_overlay()
        else:
            self._logout("system_tray")

    def _minimize_or_close(self) -> None:
        if (
            self.security_config.minimize_to_tray
            and self.tray_service is not None
            and self.tray_service.available
        ):
            self._minimize_to_tray()
        else:
            self._on_close()

    def _handle_minimize(self, _event=None) -> None:
        if (
            self.state() == "iconic"
            and self.security_config.minimize_to_tray
            and self.tray_service is not None
            and self.tray_service.available
        ):
            self.after_idle(self._minimize_to_tray)

    def _minimize_to_tray(self) -> None:
        if self.state() == "normal":
            self._normal_geometry = self.geometry()
        self.withdraw()
        if self.tray_service is not None and self.security_config.tray_notifications:
            self.tray_service.notify(
                "CryptoSafe Manager", "The vault continues running in the system tray."
            )

    def _restore_main_window(self) -> None:
        self.deiconify()
        if self._normal_geometry:
            self.geometry(self._normal_geometry)
        self.lift()
        self.focus_force()

    def _handle_window_motion(self, event) -> None:
        if event.widget is self and not self.state_manager.is_locked():
            self._shake_detector.record(int(event.x), time.monotonic())

    def _start_security_subsystem(self) -> None:
        if self.activity_monitor is not None:
            self.activity_monitor.stop()
        self.memory_guard.wipe_all()
        self.memory_guard = MemoryGuard(
            lock_memory=self.security_config.lock_sensitive_memory,
            guard_pages=self.security_config.guard_pages_enabled,
            wipe_passes=self.security_config.wipe_passes,
        )
        if self.vault_exporter is not None:
            self.vault_exporter.memory_guard = self.memory_guard
        if self.vault_importer is not None:
            self.vault_importer.memory_guard = self.memory_guard
        self.side_channel_protection.clear()
        self.side_channel_protection = SideChannelProtection(
            jitter_max_ms=self.security_config.crypto_jitter_max_ms,
            algorithmic_noise=self.security_config.algorithmic_noise_enabled,
        )
        self.search_index = VaultSearchIndex(
            self.event_bus,
            side_channel_protection=self.side_channel_protection,
        )
        if self.entry_manager is not None:
            self.entry_manager.encryption_service = AESGCMEncryptionService(
                self.side_channel_protection
            )
        self.activity_monitor = ActivityMonitor(
            lambda reason: self._schedule_ui(
                lambda current=reason: self._handle_security_lock(current)
            ),
            self.security_config,
        )
        self.activity_monitor.start()
        self._bind_panic_hotkey(self.security_config.panic_hotkey)

        if self.panic_mode is None:
            self.panic_mode = PanicMode(
                self.security_config,
                verify_master_password=lambda candidate: bool(
                    self.master_password
                    and SideChannelProtection.secure_string_compare(
                        candidate, self.master_password
                    )
                ),
                audit_callback=self._audit_security_event,
                capture_state=self._capture_session_state,
                restore_state=self._queue_restore_state,
            )
        else:
            self.panic_mode.update_config(self.security_config)

        self.panic_mode.register_handler(
            "clear_clipboard", self._panic_clear_clipboard, priority=10
        )
        self.panic_mode.register_handler(
            "wipe_memory", self._panic_wipe_memory, priority=20
        )
        self.panic_mode.register_handler(
            "close_sensitive_windows", self._close_sensitive_windows, priority=30
        )
        self.panic_mode.register_handler(
            "lock_vault", lambda: self._logout("panic"), priority=40
        )
        self.panic_mode.register_handler(
            "stealth_action", self._execute_stealth_action, priority=50
        )
        self.panic_mode.unregister_handler("close_application")
        if self.security_config.panic_close_application:
            self.panic_mode.register_handler(
                "close_application", self._on_close, priority=60
            )
        key_status = (
            self.repo.key_manager.memory_protection_status
            if self.repo is not None
            else None
        )
        if key_status is not None and (
            not key_status.memory_locked or not key_status.guard_pages_active
        ):
            unavailable = []
            if not key_status.memory_locked:
                unavailable.append("page_lock")
            if not key_status.guard_pages_active:
                unavailable.append("guard_pages")
            self._audit_security_event(
                "MEMORY_PROTECTION_DEGRADED",
                "WARN",
                {"unavailable_controls": unavailable, "fallback": "masked_memory"},
            )
            if (
                self.tray_service is not None
                and self.security_config.tray_notifications
            ):
                self.tray_service.notify(
                    "Security protection limited",
                    "The operating system denied one memory control; masked memory remains active.",
                )
        if self.panic_mode.activated and self.master_password:
            self.panic_mode.recover(self.master_password)

    def _handle_security_lock(self, reason: str) -> None:
        severity = "ERROR" if reason == "monitor_failure" else "INFO"
        self._audit_security_event("AUTO_LOCK_TRIGGERED", severity, {"reason": reason})
        self._logout(reason)

    def _activate_panic(self, method: str) -> None:
        if self.panic_mode is None or self.state_manager.is_locked():
            return
        if self.tray_service is not None:
            self.tray_service.set_state(TraySecurityState.PANIC)
        self.security_status.configure(
            text="Security: panic response", text_color=ERROR
        )
        self.panic_mode.activate(method)

    def _panic_clear_clipboard(self) -> None:
        if self.clipboard_service is not None:
            self.clipboard_service.clear("panic")

    def _panic_wipe_memory(self) -> None:
        self.memory_guard.wipe_all()

    def _close_sensitive_windows(self) -> None:
        for child in tuple(self.winfo_children()):
            if isinstance(child, ctk.CTkToplevel):
                try:
                    child.destroy()
                except Exception:  # noqa: BLE001, S112 - panic cleanup must continue
                    continue
        if self.tray_service is not None and self.tray_service.available:
            self.withdraw()
        else:
            self._show_lock_overlay()

    def _execute_stealth_action(self) -> None:
        if self.security_config.panic_decoy_command:
            try:
                subprocess.Popen(
                    list(self.security_config.panic_decoy_command),
                    close_fds=True,
                )
            except OSError:
                pass
        if self.security_config.panic_decoy_url:
            webbrowser.open(self.security_config.panic_decoy_url, new=2)
        if self.security_config.panic_fake_error:
            messagebox.showerror(
                "Application Error",
                "The application encountered an unexpected error and closed its active session.",
            )

    def _audit_security_event(self, event: str, severity: str, details: dict) -> None:
        if self.audit_logger is not None:
            self.audit_logger.log_event(
                event,
                severity=severity,
                source="security_hardening",
                details=details,
                user_id="local_user",
            )

    def _check_panic_interruption(self) -> None:
        if self.panic_mode is not None:
            self.panic_mode.check_interrupted()

    def _set_crypto_busy(self, busy: bool) -> None:
        if busy:
            self.security_status.configure(
                text="Security: cryptographic operation", text_color=WARNING
            )
            if self.tray_service is not None:
                self.tray_service.begin_crypto_operation()
        else:
            self.security_status.configure(
                text=f"Security: {self.security_config.profile.value}",
                text_color=SUCCESS,
            )
            if self.tray_service is not None:
                self.tray_service.end_crypto_operation(
                    locked=self.state_manager.is_locked()
                )
        self.update_idletasks()

    def _capture_session_state(self) -> dict:
        return {
            "geometry": self.geometry(),
            "search": self.search_var.get(),
            "category": self.category_filter.get(),
            "date": self.date_filter.get(),
            "strength": self.strength_filter.get(),
        }

    def _queue_restore_state(self, state: dict) -> None:
        self._restore_state = dict(state)

    def _restore_previous_state(self) -> None:
        if not self._restore_state:
            return
        state = self._restore_state
        self._restore_state = None
        self._normal_geometry = str(state.get("geometry", self._normal_geometry))
        self.search_var.set(str(state.get("search", "")))
        self.category_filter.set(str(state.get("category", "All categories")))
        self.date_filter.set(str(state.get("date", "Any date")))
        self.strength_filter.set(str(state.get("strength", "Any strength")))
        self._apply_search()

    def _start_clipboard_subsystem(self) -> None:
        if self.audit_logger is None:
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
        self._ensure_tray_service()
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
        if self.tray_service is not None:
            self.tray_service.set_clipboard_status(text.replace("Clipboard: ", ""))

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
        if self.audit_logger is not None:
            self.event_bus.publish(
                SecurityAlert(
                    "SecurityAlert",
                    now_utc(),
                    "CLIPBOARD_MONITOR_DEGRADED",
                    "WARN",
                    "clipboard_monitor",
                    {"operation": "monitor", "mode": "degraded"},
                )
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
            if self.audit_logger is not None:
                self.event_bus.publish(
                    SecurityAlert(
                        "SecurityAlert",
                        now_utc(),
                        "SCREEN_CAPTURE_PROTECTION_ERROR",
                        "WARN",
                        "main_window",
                        {"operation": "anti_screenshot"},
                    )
                )

    def _change_master_password(self) -> None:
        if self.repo is None or self.audit_logger is None:
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
        self.audit_logger.rekey_after_master_password_change()
        self.event_bus.publish(
            MasterPasswordChanged("MasterPasswordChanged", now_utc(), "local_user")
        )
        self._show_info("Change Password", "Master password changed successfully.")

    def _open_logs(self) -> None:
        if self.audit_logger is None or self.state_manager.is_locked():
            self._show_warning("Logs", "Unlock the vault first.")
            return
        AuditLogViewer(
            self,
            self.audit_logger,
            confirm_master_password=self._confirm_master_password,
            on_entry_selected=self._highlight_audit_entry,
        )

    def _open_settings(self) -> None:
        if self.db is None or self.settings_repo is None:
            self._show_warning("Settings", "Unlock the vault first.")
            return
        dialog = SettingsDialog(
            self,
            self.clipboard_config,
            self.security_config,
        )
        self.wait_window(dialog)
        if dialog.result == "change_master_password":
            self._change_master_password()
        elif isinstance(dialog.result, ApplicationSettings):
            previous_ephemeral = self.clipboard_config.ephemeral_mode
            try:
                with self.db.transaction(write=True):
                    self.settings_repo.save_clipboard_config(dialog.result.clipboard)
                    self.settings_repo.save_security_config(dialog.result.security)
            except SettingsRepositoryError as exc:
                self._show_error("Settings", str(exc))
                return
            self.clipboard_config = dialog.result.clipboard
            self.security_config = dialog.result.security
            self.event_bus.publish(
                ConfigurationChanged(
                    "ConfigurationChanged", now_utc(), "security_and_clipboard"
                )
            )
            if self.clipboard_service is not None:
                if previous_ephemeral != self.clipboard_config.ephemeral_mode:
                    if self.clipboard_monitor is not None:
                        self.clipboard_monitor.stop()
                    adapter = create_platform_adapter(
                        private=self.clipboard_config.ephemeral_mode
                    )
                    self.clipboard_service.replace_adapter(adapter)
                    self.clipboard_monitor = ClipboardMonitor(
                        adapter,
                        self.clipboard_service,
                        poll_interval=1.0,
                        on_degraded=self._clipboard_monitor_degraded,
                    )
                    self.clipboard_monitor.start()
                self.clipboard_service.update_config(self.clipboard_config)
            self._start_security_subsystem()
            self._apply_screen_capture_protection()

    def _open_export(self) -> None:
        if self.vault_exporter is None or self.master_password is None:
            self._show_warning("Export", "Unlock the vault first.")
            return
        dialog = ExportDialog(self, self._all_entries, self.vault_exporter)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        if not self._confirm_master_password("Export Authentication"):
            return
        self._set_crypto_busy(True)
        try:
            result = dict(dialog.result)
            destination = result.pop("destination")
            options = result.pop("options")
            artifact = self.vault_exporter.export_to_file(
                destination,
                options,
                master_password=self.master_password,
                **result,
            )
        except Exception as exc:  # noqa: BLE001 - service errors are shown in the GUI
            self._show_error("Export", str(exc))
            return
        finally:
            self._set_crypto_busy(False)
        self._show_info(
            "Export Complete",
            f"Exported {artifact.entry_count} entries to {destination}.\n"
            f"SHA-256: {artifact.checksum}",
        )

    def _open_import(self) -> None:
        if self.vault_importer is None:
            self._show_warning("Import", "Unlock the vault first.")
            return
        dialog = ImportDialog(self, self.vault_importer)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        self._set_crypto_busy(True)
        try:
            result = dict(dialog.result)
            source = result.pop("source")
            options = result.pop("options")
            imported = self.vault_importer.import_data(source, options, **result)
        except Exception as exc:  # noqa: BLE001 - service errors are shown in the GUI
            self._show_error("Import", str(exc))
            return
        finally:
            self._set_crypto_busy(False)
        self._load_entries()
        self._show_info(
            "Import Complete",
            f"Created: {imported.created}\nUpdated: {imported.updated}\n"
            f"Skipped: {imported.skipped}",
        )

    def _share_entry(self) -> None:
        if self.sharing_service is None or self.key_exchange_service is None:
            self._show_warning("Share Entry", "Unlock the vault first.")
            return
        selected = self.table.get_selected_row()
        if selected is None:
            self._show_warning("Share Entry", "Select one entry first.")
            return
        dialog = SharingDialog(
            self,
            selected,
            self.sharing_service,
            self.key_exchange_service.list_contacts(),
        )
        self.wait_window(dialog)
        if dialog.result is None:
            return
        self._set_crypto_busy(True)
        try:
            artifact = self.sharing_service.share_entry(**dialog.result)
        except Exception as exc:  # noqa: BLE001 - service errors are shown in the GUI
            self._show_error("Share Entry", str(exc))
            return
        finally:
            self._set_crypto_busy(False)
        if artifact.delivery_method == "file":
            destination = filedialog.asksaveasfilename(
                parent=self,
                title="Save Share Package",
                defaultextension=".csmshare.json",
                filetypes=[("CryptoSafe share", "*.json"), ("All files", "*")],
            )
            if destination:
                Path(destination).write_bytes(artifact.package)
                self._show_info("Share Entry", f"Share package saved to {destination}.")
        elif artifact.delivery_method == "link":
            link = artifact.delivery_data.decode("utf-8")
            self._copy_exchange_value(link)
            self._show_info(
                "Share Entry",
                "The encrypted, time-limited link was copied to the secure clipboard.",
            )
        else:
            self._show_share_qr(artifact.package, artifact.expires_at)

    def _show_share_qr(self, package: bytes, expires_at: str) -> None:
        if self.qr_service is None:
            return

        def build_images() -> list[bytes]:
            envelope = self.qr_service.create_payload("encrypted_entry", package)
            return self.qr_service.generate_qr_codes(envelope)

        QRCodeViewer(
            self,
            build_images(),
            payload_info=f"Encrypted shared entry | package expires {expires_at}",
            copy_value=package.decode("utf-8"),
            copy_callback=self._copy_exchange_value,
            refresh_callback=build_images,
        )

    def _receive_share(self) -> None:
        if self.sharing_service is None or self.qr_service is None:
            self._show_warning("Receive Share", "Unlock the vault first.")
            return
        dialog = ReceiveShareDialog(self, self.qr_service)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        self._set_crypto_busy(True)
        try:
            received = self.sharing_service.receive_share(**dialog.result)
        except Exception as exc:  # noqa: BLE001 - service errors are shown in the GUI
            self._show_error("Receive Share", str(exc))
            return
        finally:
            self._set_crypto_busy(False)
        if received.saved_entry_id is not None:
            self._load_entries()
            message = f"Shared entry saved as {received.entry['title']}."
        else:
            message = (
                f"Temporary entry: {received.entry['title']}\n"
                f"Username: {received.entry.get('username', '')}\n"
                "The password remains hidden because the entry was not saved."
            )
        self._show_info("Receive Share", message)

    def _open_contacts(self) -> None:
        if self.key_exchange_service is None:
            self._show_warning("Contacts", "Unlock the vault first.")
            return
        ContactsDialog(self, self.key_exchange_service)

    def _copy_exchange_value(self, value: str) -> None:
        if self.clipboard_service is None:
            raise RuntimeError("Secure clipboard is not available.")
        self.clipboard_service.copy_text(
            value,
            entry_id="secure-share",
            field="share_link",
            source="Secure sharing",
            data_type=ClipboardType.ENCRYPTED_BLOB,
        )

    def _run_startup_audit_verification(self) -> None:
        if self.audit_logger is None:
            return
        try:
            report = self.audit_logger.verify_integrity(full=True)
        except Exception as exc:  # noqa: BLE001 - the GUI must remain available
            self.audit_status.configure(text="Audit: error", text_color=ERROR)
            self._show_error("Audit Verification", str(exc))
            return
        self._apply_audit_status(report.verified)
        self._schedule_periodic_audit_verification()

    def _run_periodic_audit_verification(self) -> None:
        self._audit_verification_after_id = None
        if self.audit_logger is None or self.db is None or self.repo is None:
            return
        try:
            report = self.audit_logger.verify_integrity(full=False)
            self._apply_audit_status(report.verified)
            self.audit_logger.rotate_if_needed()
            scheduler = AuditExportScheduler(
                AuditLogExporter(self.audit_logger, self.repo.key_manager),
                self.db.path.parent / "audit_exports",
            )
            scheduler.run_if_due()
        except Exception as exc:  # noqa: BLE001 - periodic work must not close the app
            self.audit_status.configure(text="Audit: error", text_color=ERROR)
            if self.audit_logger is not None:
                self.audit_logger.record_incident(
                    "AUDIT_PERIODIC_CHECK_ERROR",
                    {"error_type": type(exc).__name__},
                    severity="ERROR",
                )
        self._schedule_periodic_audit_verification()

    def _schedule_periodic_audit_verification(self) -> None:
        if self._audit_verification_after_id is not None:
            self.after_cancel(self._audit_verification_after_id)
        delay_ms = self.audit_config.verification_interval_hours * 60 * 60 * 1000
        self._audit_verification_after_id = self.after(
            delay_ms, self._run_periodic_audit_verification
        )

    def _apply_audit_status(self, verified: bool) -> None:
        self.audit_status.configure(
            text="Audit: valid" if verified else "Audit: tampered",
            text_color=SUCCESS if verified else ERROR,
        )

    def _handle_audit_tamper(self, report) -> None:
        def notify() -> None:
            self._apply_audit_status(False)
            first_issue = (
                report.invalid_entries[0]
                if report.invalid_entries
                else report.chain_breaks[0]
                if report.chain_breaks
                else {"reason": "signed head mismatch"}
            )
            self._show_error(
                "Audit Integrity Warning",
                "The protected audit trail failed verification.\n\n"
                f"First issue: {first_issue}\n"
                "The incident was written to the separate security log.",
            )
            if self.audit_config.lock_on_tamper and self.entry_manager is not None:
                self._logout("audit_tamper")

        try:
            self.after(0, notify)
        except RuntimeError:
            pass

    def _highlight_audit_entry(self, entry_id: str) -> None:
        if self.table.select_entry(entry_id):
            self.status.configure(text=f"Status: Audit entry selected {entry_id}")
            return
        self.search_var.set("")
        self.category_filter.set("All categories")
        self.date_filter.set("Any date")
        self.strength_filter.set("Any strength")
        self._apply_search()
        if not self.table.select_entry(entry_id):
            self._show_info(
                "Audit Trail", "The linked vault entry is no longer active."
            )

    def _close_audit_subsystem(self) -> None:
        if self._audit_verification_after_id is not None:
            self.after_cancel(self._audit_verification_after_id)
            self._audit_verification_after_id = None
        if self.audit_bridge is not None:
            self.audit_bridge.close()
            self.audit_bridge = None
        if self.audit_logger is not None:
            try:
                self.audit_logger.close()
            except Exception as exc:  # noqa: BLE001 - shutdown must continue safely
                self.audit_status.configure(
                    text=f"Audit: close error {type(exc).__name__}",
                    text_color=ERROR,
                )
            self.audit_logger = None

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

    def _logout(self, reason: str = "manual") -> None:
        if self.entry_manager is None:
            return
        self._restore_state = self._capture_session_state()
        self.event_bus.publish(
            SystemActivity(
                "SystemActivity",
                now_utc(),
                "SYSTEM_LOCK",
                "INFO",
                {"reason": reason},
            )
        )
        self.event_bus.publish(UserLoggedOut("UserLoggedOut", now_utc(), "local_user"))
        db_path = self.db.path if self.db is not None else None
        self._clear_sensitive_data()
        self.auth_service.logout()
        self.state_manager.logout()
        self._close_audit_subsystem()
        if self.repo is not None:
            self.repo.key_manager.lock()
        self._show_lock_overlay()
        self.status.configure(text="Status: Locked")
        self.audit_status.configure(text="Audit: locked", text_color="gray70")
        self.security_status.configure(text="Security: locked", text_color=ERROR)
        if self.tray_service is not None:
            self.tray_service.set_state(TraySecurityState.LOCKED)
        if self.db is not None:
            self.db.close()
        self.db = None
        self.repo = None
        self.entry_manager = None
        self.audit_repo = None
        self.settings_repo = None
        self.vault_exporter = None
        self.vault_importer = None
        self.sharing_service = None
        self.key_exchange_service = None
        self.qr_service = None
        if reason == "panic":
            if self.tray_service is None or not self.tray_service.available:
                self._restore_main_window()
            return
        if db_path is not None:
            self.after(100, lambda: self._show_login_dialog(db_path))

    def _handle_auto_lock(self) -> None:
        self.after(0, lambda: self._logout("auto_lock"))

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
        if self.activity_monitor is not None:
            self.activity_monitor.stop()
            self.activity_monitor = None
        self.memory_guard.wipe_all()
        if self.clipboard_monitor is not None:
            self.clipboard_monitor.stop()
            self.clipboard_monitor = None
        if self.clipboard_service is not None:
            self.clipboard_service.clear("vault_lock")
            self.clipboard_service.remove_observer(self)
            self.clipboard_service = None
        if self._clipboard_status_after_id is not None:
            self.after_cancel(self._clipboard_status_after_id)
            self._clipboard_status_after_id = None
        self.clipboard_status.configure(text="Clipboard: empty")
        if self.tray_service is not None:
            self.tray_service.set_clipboard_status("empty")

    def _unlock_from_overlay(self) -> None:
        if self.auth_dialog_open:
            return
        self._restore_main_window()
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
        self._open_export()

    def _on_about(self) -> None:
        self._show_info(
            "About",
            "CryptoSafe Manager\n\nSprint 7\nAES-256-GCM encrypted local vault\n"
            "Secure clipboard, signed audit trail, validated import/export, "
            "encrypted entry sharing, protected memory, auto-lock, tray, and panic mode.",
        )

    def _on_close(self) -> None:
        if self.audit_logger is not None:
            self.event_bus.publish(
                SystemActivity(
                    "SystemActivity",
                    now_utc(),
                    "SYSTEM_SHUTDOWN",
                    "INFO",
                    {"reason": "application_close"},
                )
            )
        self._clear_sensitive_data()
        self.state_manager.close()
        self._close_audit_subsystem()
        if self.repo is not None:
            self.repo.key_manager.lock()
        if self.db is not None:
            self.db.close()
        if hasattr(self, "menu_bar"):
            self.menu_bar.close_dropdown()
        if self.tray_service is not None:
            self.tray_service.stop()
            self.tray_service = None
        self.side_channel_protection.clear()
        self.destroy()

    def _show_info(self, title: str, message: str) -> None:
        dialog = CustomDialog(self, title=title, message=message, dialog_type="info")
        self.wait_window(dialog)

    def _show_warning(self, title: str, message: str) -> None:
        dialog = CustomDialog(self, title=title, message=message, dialog_type="warning")
        self.wait_window(dialog)

    def _show_error(self, title: str, message: str) -> None:
        LOGGER.error("%s: %s", title, message)
        suggestions = {
            "Export": "Check the destination permissions and export password, then try again.",
            "Import": "Check the file format, password, and size limit, then try again.",
            "Settings": "Review the selected security options and try again.",
            "Vault Error": "Lock and unlock the vault, then repeat the operation.",
        }
        suggestion = suggestions.get(title)
        friendly_message = (
            f"{message}\n\nSuggested action: {suggestion}" if suggestion else message
        )
        dialog = CustomDialog(
            self, title=title, message=friendly_message, dialog_type="error"
        )
        self.wait_window(dialog)

    def _ask_yes_no(self, title: str, message: str) -> bool:
        dialog = CustomDialog(
            self, title=title, message=message, dialog_type="question"
        )
        self.wait_window(dialog)
        return bool(dialog.result)


def run() -> None:
    """Start the desktop application."""

    app = MainWindow()
    app.mainloop()
