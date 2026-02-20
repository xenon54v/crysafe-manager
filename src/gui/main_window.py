import tkinter as tk
from tkinter import messagebox

from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.setup_wizard import SetupWizard


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("CryptoSafe Manager - Sprint 1")
        self.geometry("800x500")

        self._create_menu()
        self._create_table()
        self._create_status_bar()

        # Sprint 1: always show setup wizard as a stub for first-run flow (GUI-3)
        self.after(100, self._show_setup_wizard)

    def _show_setup_wizard(self):
        wiz = SetupWizard(self)

        # обновляем статус, пока мастер открыт
        def poll():
            if not wiz.winfo_exists():
                return
            st = wiz.get_partial_state()
            parts = ["Status: Locked"]
            if "db_path" in st:
                parts.append(f"DB: {st['db_path']}")
            if "enc_scheme" in st:
                parts.append(f"ENC: {st['enc_scheme']}")
            if "pw_len" in st:
                parts.append(f"PW chars: {st['pw_len']}")
            self.status.config(text=" | ".join(parts))
            self.after(200, poll)

        poll()

        self.wait_window(wiz)

        if wiz.result is None:
            self.quit()
            return

        r = wiz.result
        self.status.config(text=f"Status: Locked | DB: {r.db_path} | ENC: {r.enc_scheme}")

    def _create_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New")
        file_menu.add_command(label="Open")
        file_menu.add_command(label="Backup")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Add")
        edit_menu.add_command(label="Edit")
        edit_menu.add_command(label="Delete")

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Logs", command=self._open_logs)
        view_menu.add_command(label="Settings")

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)

        menubar.add_cascade(label="File", menu=file_menu)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        menubar.add_cascade(label="View", menu=view_menu)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _create_table(self):
        self.table = SecureTable(self)
        self.table.pack(fill=tk.BOTH, expand=True)

        self.table.set_rows([
            (1, "Example Entry", "admin", "https://example.com")
        ])

    def _create_status_bar(self):
        self.status = tk.Label(self, text="Status: Locked | Clipboard: --", anchor="w")
        self.status.pack(fill=tk.X)

    def _show_about(self):
        messagebox.showinfo("About", "CryptoSafe Manager\nSprint 1 Foundation")

    def _open_logs(self):
        AuditLogViewer(self)


def run():
    app = MainWindow()
    app.mainloop()
