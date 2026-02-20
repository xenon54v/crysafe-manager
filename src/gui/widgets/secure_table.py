import tkinter as tk
from tkinter import ttk


class SecureTable(tk.Frame):
    """
    Table widget for vault entries (placeholder for Sprint 1).
    Later we will add sorting, filtering, tags, context menu, etc.
    """

    def __init__(self, master=None):
        super().__init__(master)

        columns = ("ID", "Title", "Username", "URL")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)

        self.tree.pack(fill=tk.BOTH, expand=True)

    def set_rows(self, rows):
        self.tree.delete(*self.tree.get_children())
        for row in rows:
            self.tree.insert("", tk.END, values=row)
