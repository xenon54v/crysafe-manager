import customtkinter as ctk
import tkinter as tk
from tkinter import ttk


class SecureTable(ctk.CTkFrame):
    def __init__(self, master=None):
        super().__init__(master, corner_radius=16)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "Treeview",
            background="#2b2b2b",
            foreground="white",
            fieldbackground="#2b2b2b",
            rowheight=42,
            borderwidth=0,
            font=("Segoe UI", 14)
        )
        style.map(
            "Treeview",
            background=[("selected", "#d98ca3")],
            foreground=[("selected", "white")]
        )

        style.configure(
            "Treeview.Heading",
            background="#3a3a3a",
            foreground="white",
            font=("Segoe UI", 14, "bold"),
            relief="flat",
            borderwidth=0
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#4a4a4a")]
        )

        columns = ("ID", "Title", "Username", "URL")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")

        self.tree.heading("ID", text="ID")
        self.tree.heading("Title", text="Title")
        self.tree.heading("Username", text="Username")
        self.tree.heading("URL", text="URL")

        self.tree.column("ID", width=120, anchor="center")
        self.tree.column("Title", width=320, anchor="center")
        self.tree.column("Username", width=220, anchor="center")
        self.tree.column("URL", width=420, anchor="center")

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(12, 0), pady=12)

        self.scrollbar = ctk.CTkScrollbar(self, orientation="vertical", command=self.tree.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns", padx=(8, 12), pady=12)

        self.tree.configure(yscrollcommand=self.scrollbar.set)

    def set_rows(self, rows):
        self.tree.delete(*self.tree.get_children())
        for row in rows:
            self.tree.insert("", tk.END, values=row)