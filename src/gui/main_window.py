import customtkinter as ctk
import tkinter as tk

from src.core.config import ConfigManager
from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.widgets.custom_dialog import CustomDialog
from src.gui.setup_wizard import SetupWizard, LoginDialog
from src.core.state_manager import StateManager
from src.database.db import Database
from src.database.repo import VaultRepository
from src.gui.add_entry_dialog import AddEntryDialog
from src.core.crypto.authentication import AuthenticationService
from src.core.events import EventBus, UserLoggedIn, UserLoggedOut, now_utc
from src.database.audit_repo import AuditRepository
from src.gui.edit_entry_dialog import EditEntryDialog
from src.gui.change_password_dialog import ChangePasswordDialog
from src.gui.settings_dialog import SettingsDialog

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"

class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.db = None
        self.repo = None
        self.audit_repo = None
        self.master_password = None
        self.dropdown_window = None

        self.state_manager = StateManager(on_auto_lock=self._handle_auto_lock)
        self.auth_service = AuthenticationService()
        self.event_bus = EventBus()

        self.title("CryptoSafe Manager")
        self.geometry("1100x700")

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._create_custom_menu_bar()
        self._create_header()
        self._create_table()
        self._create_status_bar()

        self.after(100, self._start_auth_flow)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # Custom dialogs

    def _show_info(self, title: str, message: str) -> None:
        dialog = CustomDialog(
            self,
            title=title,
            message=message,
            dialog_type="info"
        )
        self.wait_window(dialog)

    def _show_warning(self, title: str, message: str) -> None:
        dialog = CustomDialog(
            self,
            title=title,
            message=message,
            dialog_type="warning"
        )
        self.wait_window(dialog)

    def _show_error(self, title: str, message: str) -> None:
        dialog = CustomDialog(
            self,
            title=title,
            message=message,
            dialog_type="error"
        )
        self.wait_window(dialog)

    def _ask_yes_no(self, title: str, message: str) -> bool:
        dialog = CustomDialog(
            self,
            title=title,
            message=message,
            dialog_type="question"
        )
        self.wait_window(dialog)
        return bool(dialog.result)

    # Custom menu bar

    def _create_custom_menu_bar(self) -> None:
        self.menu_frame = ctk.CTkFrame(self, height=36, corner_radius=0)
        self.menu_frame.grid(row=0, column=0, sticky="ew")
        self.menu_frame.grid_columnconfigure(10, weight=1)

        self.file_menu_button = self._create_menu_button(
            text="File",
            column=0,
            items=[
                ("New", self._on_new),
                ("Open", self._on_open),
                ("Backup", self._on_backup),
                ("separator", None),
                ("Exit", self._on_close),
            ],
            padx=(10, 2),
        )

        self.edit_menu_button = self._create_menu_button(
            text="Edit",
            column=1,
            items=[
                ("Add", self._add_entry),
                ("Edit", self._edit_entry),
                ("Delete", self._delete_entry),
            ],
        )

        self.view_menu_button = self._create_menu_button(
            text="View",
            column=2,
            items=[
                ("Logs", self._open_logs),
                ("Settings", self._open_settings),
            ],
        )

        self.help_menu_button = self._create_menu_button(
            text="Help",
            column=3,
            items=[
                ("About", self._on_about),
            ],
        )

    def _create_menu_button(self, text: str, column: int, items: list, padx=2):
        button = ctk.CTkButton(
            self.menu_frame,
            text=text,
            width=70,
            height=28,
            fg_color="transparent",
            hover_color=("gray80", "gray25"),
            text_color=("gray10", "gray90"),
            command=lambda: self._show_custom_dropdown(button, items)
        )
        button.grid(row=0, column=column, padx=padx, pady=4)
        return button

    def _show_custom_dropdown(self, widget, items) -> None:
        if self.dropdown_window is not None:
            try:
                self.dropdown_window.destroy()
            except tk.TclError:
                pass
            self.dropdown_window = None

        self.dropdown_window = ctk.CTkToplevel(self)
        self.dropdown_window.overrideredirect(True)
        self.dropdown_window.attributes("-topmost", True)

        frame = ctk.CTkFrame(
            self.dropdown_window,
            corner_radius=10,
            border_width=1
        )
        frame.pack(fill="both", expand=True, padx=2, pady=2)

        row = 0

        for label, command in items:
            if label == "separator":
                separator = ctk.CTkFrame(
                    frame,
                    height=1,
                    fg_color=("gray70", "gray35")
                )
                separator.grid(row=row, column=0, sticky="ew", padx=8, pady=4)
                row += 1
                continue

            item_button = ctk.CTkButton(
                frame,
                text=label,
                width=150,
                height=34,
                anchor="w",
                fg_color="transparent",
                hover_color=("gray80", "gray25"),
                text_color=("gray10", "gray90"),
                command=lambda cmd=command: self._run_dropdown_command(cmd)
            )
            item_button.grid(row=row, column=0, sticky="ew", padx=6, pady=3)
            row += 1

        x = widget.winfo_rootx()
        y = widget.winfo_rooty() + widget.winfo_height() + 2

        self.dropdown_window.geometry(f"+{x}+{y}")
        self.dropdown_window.focus_force()

        self.dropdown_window.bind("<FocusOut>", lambda event: self._close_dropdown())
        self.dropdown_window.bind("<Escape>", lambda event: self._close_dropdown())

    def _run_dropdown_command(self, command) -> None:
        self._close_dropdown()

        if command is not None:
            command()

    def _close_dropdown(self) -> None:
        if self.dropdown_window is not None:
            try:
                self.dropdown_window.destroy()
            except tk.TclError:
                pass

            self.dropdown_window = None

    #  Menu actions

    def _on_new(self) -> None:
        self._show_info(
            "New",
            "Creating a new vault will be implemented in the next sprints."
        )

    def _on_open(self) -> None:
        self._show_info(
            "Open",
            "Opening an existing vault will be implemented in the next sprints."
        )

    def _on_backup(self) -> None:
        self._show_info(
            "Backup",
            "Backup functionality will be implemented in Sprint 8."
        )

    def _on_about(self) -> None:
        self._show_info(
            "About",
            "CryptoSafe Manager\nSprint 1 GUI shell"
        )

    # Main layout

    def _create_header(self):
        self.header = ctk.CTkFrame(self, corner_radius=0)
        self.header.grid(row=1, column=0, sticky="ew")
        self.header.grid_columnconfigure(1, weight=1)

        self.title_label = ctk.CTkLabel(
            self.header,
            text="CryptoSafe Manager",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.title_label.grid(row=0, column=0, padx=20, pady=15, sticky="w")

        self.logs_button = ctk.CTkButton(
            self.header,
            text="Logs",
            width=100,
            command=self._open_logs,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.logs_button.grid(row=0, column=2, padx=10, pady=15)

        self.settings_button = ctk.CTkButton(
            self.header,
            text="Settings",
            width=100,
            command=self._open_settings,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.settings_button.grid(row=0, column=3, padx=10, pady=15)

        self.logout_button = ctk.CTkButton(
            self.header,
            text="Logout",
            width=100,
            command=self._logout,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.logout_button.grid(row=0, column=4, padx=(0, 20), pady=15)

    def _create_table(self):
        self.table_frame = ctk.CTkFrame(self, corner_radius=18)
        self.table_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=20)
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        self.table = SecureTable(self.table_frame)
        self.table.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 5))

        self.actions_frame = ctk.CTkFrame(self.table_frame, fg_color="transparent")
        self.actions_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(5, 10))
        self.actions_frame.grid_columnconfigure(0, weight=1)

        self.add_button = ctk.CTkButton(
            self.actions_frame,
            text="Add",
            width=110,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white",
            command=self._add_entry
        )
        self.add_button.pack(side="left", padx=(0, 10))

        self.edit_button = ctk.CTkButton(
            self.actions_frame,
            text="Edit",
            width=110,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white",
            command=self._edit_entry
        )
        self.edit_button.pack(side="left", padx=(0, 10))

        self.delete_button = ctk.CTkButton(
            self.actions_frame,
            text="Delete",
            width=110,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white",
            command=self._delete_entry
        )
        self.delete_button.pack(side="left")

    def _create_status_bar(self):
        self.status_frame = ctk.CTkFrame(self, corner_radius=14)
        self.status_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 15))

        self.status = ctk.CTkLabel(
            self.status_frame,
            text="Status: Locked | Clipboard: --",
            anchor="w",
            font=ctk.CTkFont(size=13)
        )
        self.status.pack(fill="x", padx=14, pady=8)

    # Auth flow

    def _start_auth_flow(self):
        default_db_path = ConfigManager().load().db_path

        print("DB PATH:", default_db_path)
        print("DB EXISTS:", default_db_path.exists())

        if not default_db_path.exists():
            print("FIRST RUN: database file not found")
            self._show_setup_wizard()
            return

        try:
            db = Database(default_db_path)
            db.connect()

            cursor = db.execute(
                """
                SELECT COUNT(*)
                FROM key_store
                WHERE key_type = ?;
                """,
                ("master",)
            )

            count = cursor.fetchone()[0]
            db.close()

            print("MASTER COUNT:", count)

        except Exception as e:
            print("FIRST RUN: key_store check failed:", e)
            self._show_setup_wizard()
            return

        if count > 0:
            print("LOGIN: master key exists")
            self._show_login_dialog(default_db_path)
        else:
            print("FIRST RUN: master key not found")
            self._show_setup_wizard()

    def _show_setup_wizard(self):
        wiz = SetupWizard(self)
        self.wait_window(wiz)

        if wiz.result is None:
            self.destroy()
            return

        r = wiz.result

        self.db = Database(r.db_path)
        self.db.connect()

        self.master_password = r.master_password

        self.repo = VaultRepository(self.db)
        self.audit_repo = AuditRepository(self.db)
        self.repo.insert_sample_entries(r.master_password)

        rows = self.repo.get_entries_for_table()
        self.table.set_rows(rows)

        self.state_manager.login("local_user")
        self.state_manager.start_inactivity_timer(self._get_auto_lock_timeout())
        self.auth_service.login("local_user")

        self.audit_repo.add_log(
            action="login",
            details="Initial vault setup and login"
        )

        self.status.configure(
            text=f"Status: Unlocked | DB: {r.db_path} | ENC: {r.enc_scheme}"
        )

    def _show_login_dialog(self, db_path):
        login = LoginDialog(self)
        self.wait_window(login)

        if login.result is None:
            self.destroy()
            return

        self.db = Database(db_path)
        self.db.connect()

        self.repo = VaultRepository(self.db)
        self.audit_repo = AuditRepository(self.db)

        try:
            self.repo.key_manager.unlock_with_password(
                self.db,
                login.result.master_password
            )

        except ValueError:
            attempts = self.auth_service.register_failed_attempt()
            delay = self.auth_service.get_backoff_delay()

            if self.audit_repo is not None:
                self.audit_repo.add_log(
                    action="failed_login",
                    details=f"Failed login attempt #{attempts}"
                )

            self._show_error(
                "Login error",
                f"Invalid master password.\n"
                f"Attempt: {attempts}\n"
                f"Next attempt will be available in {delay} sec."
            )

            self.auth_service.apply_backoff_delay()

            self.db.close()
            self.db = None
            self.repo = None
            self.audit_repo = None

            self._show_login_dialog(db_path)
            return

        self.auth_service.login("local_user")

        self.audit_repo.add_log(
            action="login",
            details="Successful login"
        )

        self.event_bus.publish(
            UserLoggedIn(
                name="UserLoggedIn",
                timestamp=now_utc(),
                user="local_user"
            )
        )

        self.master_password = login.result.master_password

        rows = self.repo.get_entries_for_table()
        self.table.set_rows(rows)

        self.state_manager.login("local_user")
        self.state_manager.start_inactivity_timer(self._get_auto_lock_timeout())

        self.status.configure(
            text=f"Status: Unlocked | DB: {db_path}"
        )

    def _get_auto_lock_timeout(self) -> int:
        if self.db is None:
            return 300

        cursor = self.db.execute(
            """
            SELECT setting_value
            FROM settings
            WHERE setting_key = ?;
            """,
            ("auto_lock_timeout",)
        )

        row = cursor.fetchone()

        if row is None:
            return 300

        try:
            return int(row[0])
        except (TypeError, ValueError):
            return 300

    # Logs and settings

    def _open_logs(self):
        if self.audit_repo is None:
            self._show_warning(
                "Logs",
                "Audit log is not available yet. Please unlock the vault first."
            )
            return

        AuditLogViewer(self, self.audit_repo)

    def _open_settings(self):
        if self.db is None or self.repo is None:
            self._show_warning(
                "Settings",
                "Settings are not available yet. Please unlock the vault first."
            )
            return

        dialog = SettingsDialog(self)
        self.wait_window(dialog)

        if dialog.result == "change_master_password":
            self._change_master_password()

    # Entries

    def _add_entry(self):
        if self.repo is None or self.master_password is None:
            self._show_warning(
                "Add entry",
                "Please unlock the vault first."
            )
            return

        dialog = AddEntryDialog(self)
        self.wait_window(dialog)

        if dialog.result is None:
            return

        r = dialog.result

        self.repo.add_entry(
            master_password=self.master_password,
            title=r.title,
            username=r.username,
            password=r.password,
            url=r.url,
            notes=r.notes,
            tags=r.tags
        )

        rows = self.repo.get_entries_for_table()
        self.table.set_rows(rows)

        self.audit_repo.add_log(
            action="add_entry",
            details=f"Added entry: {r.title}"
        )

        self._show_info(
            "Add entry",
            "Entry added successfully."
        )

    def _edit_entry(self):
        if self.repo is None or self.master_password is None:
            self._show_warning(
                "Edit entry",
                "Please unlock the vault first."
            )
            return

        entry_id = self.table.get_selected_entry_id()

        if entry_id is None:
            self._show_warning(
                "Edit entry",
                "Please select an entry in the table first."
            )
            return

        entry = self.repo.get_entry_by_id(entry_id)

        if entry is None:
            self._show_error(
                "Edit entry",
                "Entry not found."
            )
            return

        dialog = EditEntryDialog(self, entry=entry)
        self.wait_window(dialog)

        if dialog.result is None:
            return

        r = dialog.result

        if not r["password"]:
            self._show_warning(
                "Edit entry",
                "Please enter a new password for this entry."
            )
            return

        updated = self.repo.update_entry(
            entry_id=entry_id,
            master_password=self.master_password,
            title=r["title"],
            username=r["username"],
            password=r["password"],
            url=r["url"],
            notes=r["notes"],
            tags=r["tags"],
        )

        if not updated:
            self._show_error(
                "Edit entry",
                "Failed to update the entry."
            )
            return

        rows = self.repo.get_entries_for_table()
        self.table.set_rows(rows)

        self.audit_repo.add_log(
            action="edit_entry",
            entry_id=entry_id,
            details=f"Edited entry id={entry_id}"
        )

        self._show_info(
            "Edit entry",
            "Entry updated successfully."
        )

    def _delete_entry(self):
        if self.repo is None:
            self._show_warning(
                "Delete entry",
                "Please unlock the vault first."
            )
            return

        entry_id = self.table.get_selected_entry_id()

        if entry_id is None:
            self._show_warning(
                "Delete entry",
                "Please select an entry in the table first."
            )
            return

        confirm = self._ask_yes_no(
            "Delete entry",
            f"Delete entry with ID {entry_id}?"
        )

        if not confirm:
            return

        deleted = self.repo.delete_entry(entry_id)

        if not deleted:
            self._show_error(
                "Delete entry",
                "Entry was not found or has already been deleted."
            )
            return

        rows = self.repo.get_entries_for_table()
        self.table.set_rows(rows)

        self.audit_repo.add_log(
            action="delete_entry",
            entry_id=entry_id,
            details=f"Deleted entry id={entry_id}"
        )

        self._show_info(
            "Delete entry",
            "Entry deleted successfully."
        )

    # Password and session

    def _change_master_password(self):
        if self.repo is None:
            self._show_warning(
                "Change password",
                "Please unlock the vault first."
            )
            return

        dialog = ChangePasswordDialog(self)
        self.wait_window(dialog)

        if dialog.result is None:
            return

        old_password = dialog.result["old_password"]
        new_password = dialog.result["new_password"]

        try:
            self.repo.change_master_password(
                old_password=old_password,
                new_password=new_password,
            )

        except ValueError:
            self._show_error(
                "Change password",
                "Current master password is incorrect."
            )
            return

        self.master_password = new_password

        self.audit_repo.add_log(
            action="change_master_password",
            details="Master password changed and vault re-encrypted"
        )

        self._show_info(
            "Change password",
            "Master password changed successfully."
        )

    def _logout(self):
        if self.audit_repo is not None:
            self.audit_repo.add_log(
                action="logout",
                details="User logged out"
            )

        self.event_bus.publish(
            UserLoggedOut(
                name="UserLoggedOut",
                timestamp=now_utc(),
                user="local_user"
            )
        )

        db_path = None

        if self.db is not None:
            db_path = self.db.path

        self._clear_sensitive_data()
        self.auth_service.logout()
        self.state_manager.logout()
        self.table.set_rows([])
        self.status.configure(text="Status: Locked | Logged out")

        if self.db is not None:
            self.db.close()
            self.db = None
            self.repo = None
            self.audit_repo = None

        if db_path is not None:
            self.after(100, lambda: self._show_login_dialog(db_path))

    def _handle_auto_lock(self):
        if self.audit_repo is not None:
            self.audit_repo.add_log(
                action="auto_lock",
                details="Session locked due to inactivity"
            )

        self.after(0, self._logout)

    def _clear_sensitive_data(self):
        self.master_password = None

        if self.repo is not None:
            self.repo.key_manager.lock()

    def _on_close(self):
        if self.audit_repo is not None:
            self.audit_repo.add_log(
                action="app_close",
                details="Application closed"
            )

        self._close_dropdown()
        self._clear_sensitive_data()
        self.state_manager.stop_timers()

        if self.db is not None:
            self.db.close()
            self.db = None
            self.repo = None
            self.audit_repo = None

        self.destroy()


def run():
    app = MainWindow()
    app.mainloop()