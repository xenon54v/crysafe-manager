import customtkinter as ctk

from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.setup_wizard import SetupWizard
from src.core.config import ConfigManager
from src.database.db import Database
from src.database.repo import VaultRepository


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


PINK = "#d98ca3"
PINK_HOVER = "#c97c93"


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.db = None
        self.repo = None

        self.title("CryptoSafe Manager - Sprint 1")
        self.geometry("1100x700")

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._create_header()
        self._create_table()
        self._create_status_bar()

        self.after(100, self._show_setup_wizard)
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
        self.settings_button.grid(row=0, column=3, padx=(0, 20), pady=15)

    def _create_table(self):
        self.table_frame = ctk.CTkFrame(self, corner_radius=18)
        self.table_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        self.table = SecureTable(self.table_frame)
        self.table.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

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

    def _show_setup_wizard(self):
        wiz = SetupWizard(self)
        self.wait_window(wiz)

        if wiz.result is None:
            self.destroy()
            return

        r = wiz.result

        self.db = Database(r.db_path)
        self.db.connect()

        self.repo = VaultRepository(self.db)
        self.repo.insert_sample_entries(r.master_password)

        rows = self.repo.get_entries_for_table()
        self.table.set_rows(rows)

        self.status.configure(text=f"Status: Locked | DB: {r.db_path} | ENC: {r.enc_scheme}")

    def _open_logs(self):
        AuditLogViewer(self)

    def _on_close(self):
        if self.db is not None:
            self.db.close()
        self.destroy()


def run():
    app = MainWindow()
    app.mainloop()