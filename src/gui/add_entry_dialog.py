from dataclasses import dataclass
from tkinter import messagebox

import customtkinter as ctk

from src.gui.widgets.password_entry import PasswordEntry


PINK = "#d98ca3"
PINK_HOVER = "#c97c93"


@dataclass(frozen=True)
class EntryResult:
    title: str
    username: str
    password: str
    url: str
    notes: str
    tags: str


class AddEntryDialog(ctk.CTkToplevel):
    def __init__(self, master=None):
        super().__init__(master)

        self.title("Add Entry")
        self.geometry("560x650")
        self.resizable(False, False)

        self._result = None

        self.grid_columnconfigure(0, weight=1)

        self.form = ctk.CTkFrame(self)
        self.form.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

        ctk.CTkLabel(
            self.form,
            text="Add New Entry",
            font=ctk.CTkFont(size=22, weight="bold")
        ).pack(anchor="w", pady=(10, 20), padx=20)

        self.title_entry = self._add_entry_field("Title")
        self.username_entry = self._add_entry_field("Username")

        ctk.CTkLabel(self.form, text="Password").pack(anchor="w", padx=20, pady=(10, 5))
        self.password_entry = PasswordEntry(self.form)
        self.password_entry.pack(fill="x", padx=20)

        self.url_entry = self._add_entry_field("URL")
        self.notes_entry = self._add_entry_field("Notes")
        self.tags_entry = self._add_entry_field("Tags")

        self.buttons = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))

        self.cancel_button = ctk.CTkButton(
            self.buttons,
            text="Cancel",
            width=110,
            command=self._cancel,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.cancel_button.pack(side="right", padx=(10, 0))

        self.save_button = ctk.CTkButton(
            self.buttons,
            text="Save",
            width=110,
            command=self._save,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.save_button.pack(side="right")

        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    @property
    def result(self):
        return self._result

    def _add_entry_field(self, label_text: str):
        ctk.CTkLabel(self.form, text=label_text).pack(anchor="w", padx=20, pady=(10, 5))
        entry = ctk.CTkEntry(self.form)
        entry.pack(fill="x", padx=20)
        return entry

    def _save(self):
        title = self.title_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        url = self.url_entry.get().strip()
        notes = self.notes_entry.get().strip()
        tags = self.tags_entry.get().strip()

        if not title:
            messagebox.showerror("Error", "Title is required.")
            return

        if not password:
            messagebox.showerror("Error", "Password is required.")
            return

        self._result = EntryResult(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            tags=tags
        )
        self.destroy()

    def _cancel(self):
        self._result = None
        self.destroy()