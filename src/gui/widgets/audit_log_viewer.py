import tkinter as tk
from tkinter import ttk


class AuditLogViewer(tk.Toplevel):
    """
    Stub window for Sprint 5 audit log viewer.
    """

    def __init__(self, master=None):
        super().__init__(master)

        self.title("Audit Log (Stub)")
        self.geometry("600x400")

        label = tk.Label(self, text="Audit Log Viewer will be implemented in Sprint 5")
        label.pack(pady=10)

        self.table = ttk.Treeview(self, columns=("Time", "Action", "Entry"), show="headings")
        self.table.heading("Time", text="Time")
        self.table.heading("Action", text="Action")
        self.table.heading("Entry", text="Entry")
        self.table.pack(fill=tk.BOTH, expand=True)
