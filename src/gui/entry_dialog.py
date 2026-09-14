from __future__ import annotations

import json
import queue
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from tkinter import messagebox

import customtkinter as ctk

from src.core.vault.password_generator import PasswordGenerator
from src.core.vault.url_tools import fetch_favicon, normalize_url
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
    category: str
    tags: list[str]
    totp_secret: str
    sharing_metadata: dict

    def to_dict(self) -> dict:
        return asdict(self)


class PasswordGeneratorDialog(ctk.CTkToplevel):
    def __init__(self, master, generator: PasswordGenerator) -> None:
        super().__init__(master)
        self.generator = generator
        self.result: str | None = None

        self.title("Generate Password")
        self.geometry("430x470")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        frame = ctk.CTkFrame(self)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            frame,
            text="Password Generator",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(18, 16))

        self.length_var = ctk.StringVar(value=str(PasswordGenerator.DEFAULT_LENGTH))
        self._add_labeled_entry(frame, "Length from 8 to 64", self.length_var)

        self.uppercase_var = ctk.BooleanVar(value=True)
        self.lowercase_var = ctk.BooleanVar(value=True)
        self.digits_var = ctk.BooleanVar(value=True)
        self.symbols_var = ctk.BooleanVar(value=True)
        self.ambiguous_var = ctk.BooleanVar(value=True)

        for label, variable in (
            ("Uppercase letters", self.uppercase_var),
            ("Lowercase letters", self.lowercase_var),
            ("Digits", self.digits_var),
            ("Symbols !@#$%^&*", self.symbols_var),
            ("Exclude ambiguous characters l I 1 0 O", self.ambiguous_var),
        ):
            ctk.CTkCheckBox(
                frame,
                text=label,
                variable=variable,
                fg_color=PINK,
                hover_color=PINK_HOVER,
            ).pack(anchor="w", padx=20, pady=6)

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(22, 15))
        ctk.CTkButton(
            buttons,
            text="Cancel",
            command=self.destroy,
            fg_color="gray45",
            hover_color="gray35",
        ).pack(side="right", padx=(10, 0))
        ctk.CTkButton(
            buttons,
            text="Generate",
            command=self._generate,
            fg_color=PINK,
            hover_color=PINK_HOVER,
        ).pack(side="right")

    @staticmethod
    def _add_labeled_entry(frame, label: str, variable: ctk.StringVar) -> None:
        ctk.CTkLabel(frame, text=label).pack(anchor="w", padx=20, pady=(4, 5))
        ctk.CTkEntry(frame, textvariable=variable).pack(fill="x", padx=20, pady=(0, 10))

    def _generate(self) -> None:
        try:
            length = int(self.length_var.get())
            self.result = self.generator.generate(
                length=length,
                use_uppercase=self.uppercase_var.get(),
                use_lowercase=self.lowercase_var.get(),
                use_digits=self.digits_var.get(),
                use_symbols=self.symbols_var.get(),
                exclude_ambiguous=self.ambiguous_var.get(),
            )
        except (TypeError, ValueError) as exc:
            messagebox.showerror("Password generator", str(exc), parent=self)
            return
        self.destroy()


class EntryDialog(ctk.CTkToplevel):
    def __init__(
        self,
        master=None,
        entry: dict | None = None,
        generator: PasswordGenerator | None = None,
        username_suggester: Callable[[str], list[str]] | None = None,
        window_title: str = "Entry",
        heading: str = "Vault Entry",
    ) -> None:
        super().__init__(master)
        self.result: EntryResult | None = None
        self.favicon_data: bytes | None = None
        self._entry = entry or {}
        self._generator = generator or PasswordGenerator()
        self._username_suggester = username_suggester
        self._password_was_generated = False
        self._favicon_results: queue.Queue[tuple[str, bytes | None]] = queue.Queue()

        self.title(window_title)
        self.geometry("680x820")
        self.minsize(620, 700)
        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.form = ctk.CTkScrollableFrame(self)
        self.form.grid(row=0, column=0, sticky="nsew", padx=20, pady=(20, 10))
        self.form.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.form,
            text=heading,
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(12, 16))

        self.title_entry = self._add_entry(1, "Title")

        self._add_label(3, "Username")
        self.username_entry = ctk.CTkComboBox(self.form, values=[""])
        self.username_entry.grid(row=4, column=0, sticky="ew", padx=20, pady=(0, 8))

        self._add_label(5, "Password")
        self.password_entry = PasswordEntry(self.form)
        self.password_entry.grid(row=6, column=0, sticky="ew", padx=20)
        self.password_entry.entry.bind("<KeyRelease>", self._update_strength, add="+")

        strength_row = ctk.CTkFrame(self.form, fg_color="transparent")
        strength_row.grid(row=7, column=0, sticky="ew", padx=20, pady=(7, 8))
        strength_row.grid_columnconfigure(0, weight=1)
        self.strength_bar = ctk.CTkProgressBar(strength_row, progress_color=PINK)
        self.strength_bar.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.strength_label = ctk.CTkLabel(strength_row, text="Very weak", width=90)
        self.strength_label.grid(row=0, column=1, padx=(0, 10))
        ctk.CTkButton(
            strength_row,
            text="Generate Password",
            width=150,
            command=self._open_generator,
            fg_color=PINK,
            hover_color=PINK_HOVER,
        ).grid(row=0, column=2)

        self.url_entry = self._add_entry(8, "URL")
        self.url_entry.bind("<FocusOut>", self._on_url_changed, add="+")
        self.favicon_status = ctk.CTkLabel(
            self.form,
            text="",
            anchor="w",
            text_color="gray60",
        )
        self.favicon_status.grid(row=10, column=0, sticky="w", padx=20)

        self.category_entry = self._add_entry(11, "Category")
        self.tags_entry = self._add_entry(13, "Tags separated by commas")
        self.totp_entry = self._add_entry(15, "TOTP Secret")
        self.sharing_entry = self._add_entry(17, "Sharing metadata")

        self._add_label(19, "Notes")
        self.notes_entry = ctk.CTkTextbox(self.form, height=110)
        self.notes_entry.grid(row=20, column=0, sticky="ew", padx=20, pady=(0, 16))

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        ctk.CTkButton(
            buttons,
            text="Cancel",
            width=110,
            command=self.destroy,
            fg_color="gray45",
            hover_color="gray35",
        ).pack(side="right", padx=(10, 0))
        ctk.CTkButton(
            buttons,
            text="Save",
            width=110,
            command=self._save,
            fg_color=PINK,
            hover_color=PINK_HOVER,
        ).pack(side="right")

        self._fill_fields()
        self._update_strength()

    def _add_label(self, row: int, text: str) -> None:
        ctk.CTkLabel(self.form, text=text).grid(
            row=row, column=0, sticky="w", padx=20, pady=(8, 5)
        )

    def _add_entry(self, row: int, label: str):
        self._add_label(row, label)
        entry = ctk.CTkEntry(self.form)
        entry.grid(row=row + 1, column=0, sticky="ew", padx=20, pady=(0, 8))
        return entry

    def _fill_fields(self) -> None:
        values = (
            (self.title_entry, self._entry.get("title", "")),
            (self.username_entry, self._entry.get("username", "")),
            (self.password_entry, self._entry.get("password", "")),
            (self.url_entry, self._entry.get("url", "")),
            (self.category_entry, self._entry.get("category", "")),
            (self.tags_entry, ", ".join(self._entry.get("tags", []))),
            (self.totp_entry, self._entry.get("totp_secret", "")),
        )
        for widget, value in values:
            if hasattr(widget, "set"):
                widget.set(str(value))
            else:
                widget.insert(0, str(value))

        sharing = self._entry.get("sharing_metadata", {})
        if sharing:
            self.sharing_entry.insert(0, json.dumps(sharing, ensure_ascii=False))
        self.notes_entry.insert("1.0", str(self._entry.get("notes", "")))

    def _open_generator(self) -> None:
        dialog = PasswordGeneratorDialog(self, self._generator)
        self.wait_window(dialog)
        if dialog.result is not None:
            self.password_entry.set(dialog.result)
            self._password_was_generated = True
            self._update_strength()

    def _update_strength(self, _event=None) -> None:
        strength = self._generator.strength(self.password_entry.get())
        self.strength_bar.set(strength.score / 4)
        self.strength_label.configure(text=strength.label)

    def _on_url_changed(self, _event=None) -> None:
        value = self.url_entry.get().strip()
        if not value:
            self.favicon_status.configure(text="")
            return

        try:
            normalized = normalize_url(value)
        except ValueError:
            self.favicon_status.configure(
                text="Invalid URL format", text_color="#d96c6c"
            )
            return

        self.url_entry.delete(0, "end")
        self.url_entry.insert(0, normalized)
        self._update_username_suggestions(normalized)
        self.favicon_status.configure(text="Checking favicon", text_color="gray60")

        def load() -> None:
            data = fetch_favicon(normalized)
            self._favicon_results.put((normalized, data))

        threading.Thread(target=load, daemon=True).start()
        self.after(100, self._poll_favicon_result)

    def _poll_favicon_result(self) -> None:
        try:
            requested_url, data = self._favicon_results.get_nowait()
        except queue.Empty:
            if self.winfo_exists():
                self.after(100, self._poll_favicon_result)
            return

        if requested_url == self.url_entry.get().strip():
            self._set_favicon_result(data)

    def _set_favicon_result(self, data: bytes | None) -> None:
        if not self.winfo_exists():
            return
        self.favicon_data = data
        if data:
            self.favicon_status.configure(text="Favicon loaded", text_color="#7ccf91")
        else:
            self.favicon_status.configure(
                text="Favicon is not available", text_color="gray60"
            )

    def _update_username_suggestions(self, url: str) -> None:
        if self._username_suggester is None:
            return
        suggestions = self._username_suggester(url)
        if suggestions:
            self.username_entry.configure(values=suggestions)

    def _save(self) -> None:
        title = self.title_entry.get().strip()
        password = self.password_entry.get()
        if not title:
            messagebox.showerror("Entry", "Title is required.", parent=self)
            return
        if not password.strip():
            messagebox.showerror("Entry", "Password is required.", parent=self)
            return

        strength = self._generator.strength(password)
        if not self._password_was_generated and strength.score < 3:
            messagebox.showerror(
                "Entry",
                "Password strength must be Strong or Very strong.",
                parent=self,
            )
            return

        try:
            url = normalize_url(self.url_entry.get())
        except ValueError as exc:
            messagebox.showerror("Entry", str(exc), parent=self)
            return

        sharing_text = self.sharing_entry.get().strip()
        try:
            sharing_metadata = json.loads(sharing_text) if sharing_text else {}
        except json.JSONDecodeError:
            sharing_metadata = {"description": sharing_text}
        if not isinstance(sharing_metadata, dict):
            messagebox.showerror(
                "Entry",
                "Sharing metadata must be a JSON object or plain text.",
                parent=self,
            )
            return

        self.result = EntryResult(
            title=title,
            username=self.username_entry.get().strip(),
            password=password,
            url=url,
            notes=self.notes_entry.get("1.0", "end-1c"),
            category=self.category_entry.get().strip(),
            tags=[
                tag.strip() for tag in self.tags_entry.get().split(",") if tag.strip()
            ],
            totp_secret=self.totp_entry.get().strip(),
            sharing_metadata=sharing_metadata,
        )
        self.destroy()
