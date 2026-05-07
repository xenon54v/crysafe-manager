import customtkinter as ctk

from tkinter import messagebox
from src.core.config import ConfigManager

from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.setup_wizard import SetupWizard, LoginDialog
from src.core.state_manager import StateManager
from src.database.db import Database
from src.database.repo import VaultRepository
from src.gui.add_entry_dialog import AddEntryDialog
from src.core.crypto.authentication import AuthenticationService
from src.core.events import EventBus, UserLoggedIn, UserLoggedOut, now_utc
from src.database.audit_repo import AuditRepository

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
        self.state_manager = StateManager(on_auto_lock=self._handle_auto_lock)

        self.auth_service = AuthenticationService()
        self.event_bus = EventBus()

        self.title("CryptoSafe Manager")
        self.geometry("1100x700")

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._create_header()
        self._create_table()
        self._create_status_bar()

        self.after(100, self._start_auth_flow)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _create_header(self):
        self.header = ctk.CTkFrame(self, corner_radius=0)
        self.header.grid(row=0, column=0, sticky="ew")
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
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )

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

        self.settings_button.grid(row=0, column=3, padx=10, pady=15)

    def _create_table(self):
        self.table_frame = ctk.CTkFrame(self, corner_radius=18)
        self.table_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
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
        self.status_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 15))

        self.status = ctk.CTkLabel(
            self.status_frame,
            text="Status: Locked | Clipboard: --",
            anchor="w",
            font=ctk.CTkFont(size=13)
        )
        self.status.pack(fill="x", padx=14, pady=8)

    def _start_auth_flow(self):
        default_db_path = ConfigManager().load().db_path

        if default_db_path.exists():
            self._show_login_dialog(default_db_path)
        else:
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

        self.state_manager.start_inactivity_timer(300)
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

            messagebox.showerror(
                "Ошибка входа",
                f"Неверный мастер-пароль.\n"
                f"Попытка: {attempts}\n"
                f"Следующая попытка будет доступна через {delay} сек."
            )

            self.auth_service.apply_backoff_delay()

            self.db.close()
            self.db = None
            self.repo = None

            self._show_login_dialog(db_path)

            self.event_bus.publish(
                UserLoggedIn(
                    name="UserLoggedIn",
                    timestamp=now_utc(),
                    user="local_user"
                )
            )

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
        self.state_manager.start_inactivity_timer(300)

        self.status.configure(
            text=f"Status: Unlocked | DB: {db_path}"
        )

    def _open_logs(self):
        AuditLogViewer(self, self.audit_repo)

    def _on_close(self):
        if self.audit_repo is not None:
            self.audit_repo.add_log(
                action="app_close",
                details="Application closed"
            )

        self._clear_sensitive_data()
        self.state_manager.stop_timers()

        if self.db is not None:
            self.db.close()

        self.destroy()

    def _add_entry(self):
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

    def _clear_sensitive_data(self):
        self.master_password = None

        if self.repo is not None:
            self.repo.key_manager.lock()

    def _handle_auto_lock(self):
        if self.audit_repo is not None:
            self.audit_repo.add_log(
                action="auto_lock",
                details="Session locked due to inactivity"
            )

        self.after(0, self._logout)

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

        if db_path is not None:
            self.after(100, lambda: self._show_login_dialog(db_path))

    def _edit_entry(self):
        print("Edit entry clicked")

    def _delete_entry(self):
        entry_id = self.table.get_selected_entry_id()

        if entry_id is None:
            messagebox.showwarning(
                "Удаление записи",
                "Сначала выберите запись в таблице."
            )
            return

        confirm = messagebox.askyesno(
            "Удаление записи",
            f"Удалить запись с ID {entry_id}?"
        )

        if not confirm:
            return

        deleted = self.repo.delete_entry(entry_id)

        if not deleted:
            messagebox.showerror(
                "Ошибка удаления",
                "Запись не найдена или уже была удалена."
            )
            return

        rows = self.repo.get_entries_for_table()
        self.table.set_rows(rows)

        self.audit_repo.add_log(
            action="delete_entry",
            details=f"Deleted entry id={entry_id}"
        )

        messagebox.showinfo(
            "Удаление записи",
            "Запись успешно удалена."
        )


def run():
    app = MainWindow()
    app.mainloop()
