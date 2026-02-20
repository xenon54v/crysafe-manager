import tkinter as tk
from tkinter import ttk, messagebox


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("CryptoSafe Manager - Sprint 1")
        self.geometry("800x500")

        self._create_menu()
        self._create_table()
        self._create_status_bar()

    # ---------------- Menu ----------------

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
        view_menu.add_command(label="Logs")
        view_menu.add_command(label="Settings")

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)

        menubar.add_cascade(label="File", menu=file_menu)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        menubar.add_cascade(label="View", menu=view_menu)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    # ---------------- Table ----------------

    def _create_table(self):
        columns = ("ID", "Title", "Username", "URL")

        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Placeholder data
        self.tree.insert("", tk.END, values=(1, "Example Entry", "admin", "https://example.com"))

    # ---------------- Status Bar ----------------

    def _create_status_bar(self):
        self.status = tk.Label(self, text="Status: Locked | Clipboard: --", anchor="w")
        self.status.pack(fill=tk.X)

    # ---------------- About ----------------

    def _show_about(self):
        messagebox.showinfo("About", "CryptoSafe Manager\nSprint 1 Foundation")


def run():
    app = MainWindow()
    app.mainloop()
