from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from datetime import datetime
from functools import partial
from tkinter import ttk

import customtkinter as ctk

from src.core.vault.url_tools import extract_domain


def mask_username(username: str) -> str:
    if not username:
        return ""
    return f"{username[:4]}••••"


def format_modified(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return value or ""
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M")


class SecureTable(ctk.CTkFrame):
    COLUMNS = (
        "Title",
        "Username",
        "Password",
        "Domain",
        "Modified",
        "CopyUser",
        "CopyPass",
        "Clipboard",
    )

    def __init__(
        self,
        master=None,
        on_edit: Callable[[], None] | None = None,
        on_delete: Callable[[], None] | None = None,
        on_copy_username: Callable[[], None] | None = None,
        on_copy_password: Callable[[], None] | None = None,
        on_copy_all: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(master, corner_radius=16)
        self._entries: dict[str, dict] = {}
        self._visible_password_ids: set[str] = set()
        self._all_passwords_visible = False
        self._sort_reverse: dict[str, bool] = {}
        self._heading_drag_start: int | None = None
        self._clipboard_entry_id: str | None = None
        self._on_copy_username = on_copy_username
        self._on_copy_password = on_copy_password

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._configure_style()

        self.tree = ttk.Treeview(
            self,
            columns=self.COLUMNS,
            show="headings",
            selectmode="extended",
        )
        headings = {
            "Title": "Title",
            "Username": "Username",
            "Password": "Password  👁",
            "Domain": "Domain",
            "Modified": "Last Modified",
            "CopyUser": "Copy User",
            "CopyPass": "Copy Pass",
            "Clipboard": "Clipboard",
        }
        widths = {
            "Title": 220,
            "Username": 180,
            "Password": 190,
            "Domain": 220,
            "Modified": 155,
            "CopyUser": 90,
            "CopyPass": 90,
            "Clipboard": 90,
        }
        for column in self.COLUMNS:
            command = None
            if column not in {"CopyUser", "CopyPass", "Clipboard"}:
                command = partial(self.sort_by, column)
            if command is not None:
                self.tree.heading(
                    column,
                    text=headings[column],
                    command=command
                )
            else:
                self.tree.heading(
                    column,
                    text=headings[column]
                )
            anchor = (
                "center" if column in {"CopyUser", "CopyPass", "Clipboard"} else "w"
            )
            self.tree.column(column, width=widths[column], minwidth=75, anchor=anchor)

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(12, 0), pady=12)
        self.scrollbar = ctk.CTkScrollbar(
            self, orientation="vertical", command=self.tree.yview
        )
        self.scrollbar.grid(row=0, column=1, sticky="ns", padx=(8, 12), pady=12)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self._context_menu = tk.Menu(self, tearoff=False)
        for label, callback in (
            ("Edit", on_edit),
            ("Delete", on_delete),
            ("Copy username", on_copy_username),
            ("Copy password", on_copy_password),
            ("Copy all", on_copy_all),
        ):
            if callback is not None:
                self._context_menu.add_command(label=label, command=callback)

        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<ButtonPress-1>", self._start_heading_drag, add="+")
        self.tree.bind("<ButtonRelease-1>", self._finish_pointer_action, add="+")
        if on_edit is not None:
            self.tree.bind("<Double-1>", lambda _event: on_edit())

    def set_rows(self, rows) -> None:
        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        self._entries = {}

        for row in rows:
            entry = self._coerce_row(row)
            entry_id = str(entry["id"])
            self._entries[entry_id] = entry
            self.tree.insert(
                "", tk.END, iid=entry_id, values=self._display_values(entry)
            )

        existing_selection = [
            entry_id for entry_id in selected if entry_id in self._entries
        ]
        if existing_selection:
            self.tree.selection_set(existing_selection)

    def get_selected_rows(self) -> list[dict]:
        return [
            self._entries[entry_id]
            for entry_id in self.tree.selection()
            if entry_id in self._entries
        ]

    def get_selected_row(self) -> dict | None:
        rows = self.get_selected_rows()
        return rows[0] if rows else None

    def get_selected_entry_ids(self) -> list[str]:
        return [str(row["id"]) for row in self.get_selected_rows()]

    def get_selected_values(self):
        selected = self.tree.selection()
        if not selected:
            return None
        return self.tree.item(selected[0]).get("values")

    def get_selected_entry_id(self):
        row = self.get_selected_row()
        return None if row is None else row["id"]

    def select_entry(self, entry_id: str) -> bool:
        entry_id = str(entry_id)
        if entry_id not in self._entries or not self.tree.exists(entry_id):
            return False
        self.tree.selection_set(entry_id)
        self.tree.focus(entry_id)
        self.tree.see(entry_id)
        return True

    def delete_selected_row(self) -> bool:
        selected = self.tree.selection()
        if not selected:
            return False
        for entry_id in selected:
            self.tree.delete(entry_id)
            self._entries.pop(entry_id, None)
        return True

    def set_passwords_visible(self, visible: bool) -> None:
        self._all_passwords_visible = visible
        self._visible_password_ids.clear()
        self._refresh_visible_rows()

    def toggle_selected_password(self) -> None:
        entry_id = self.tree.focus()
        if not entry_id or entry_id not in self._entries:
            return
        if entry_id in self._visible_password_ids:
            self._visible_password_ids.remove(entry_id)
        else:
            self._visible_password_ids.add(entry_id)
        self._refresh_row(entry_id)

    def sort_by(self, column: str) -> None:
        reverse = self._sort_reverse.get(column, False)
        key_functions = {
            "Title": lambda entry: str(entry.get("title", "")).casefold(),
            "Username": lambda entry: str(entry.get("username", "")).casefold(),
            "Password": lambda entry: str(entry.get("password", "")).casefold(),
            "Domain": lambda entry: extract_domain(
                str(entry.get("url", ""))
            ).casefold(),
            "Modified": lambda entry: str(entry.get("updated_at", "")),
        }
        ordered = sorted(
            self._entries.values(), key=key_functions[column], reverse=reverse
        )
        for position, entry in enumerate(ordered):
            self.tree.move(str(entry["id"]), "", position)
        self._sort_reverse[column] = not reverse

    def clear_sensitive_data(self) -> None:
        self._visible_password_ids.clear()
        self._all_passwords_visible = False
        self._entries.clear()
        self._clipboard_entry_id = None
        self.tree.delete(*self.tree.get_children())

    def mark_clipboard_entry(self, entry_id: str | None) -> None:
        previous = self._clipboard_entry_id
        self._clipboard_entry_id = str(entry_id) if entry_id is not None else None
        if previous:
            self._refresh_row(previous)
        if self._clipboard_entry_id:
            self._refresh_row(self._clipboard_entry_id)

    def _display_values(self, entry: dict) -> tuple[str, ...]:
        entry_id = str(entry["id"])
        visible = self._all_passwords_visible or entry_id in self._visible_password_ids
        password = str(entry.get("password", "")) if visible else "••••••••"
        return (
            str(entry.get("title", "")),
            mask_username(str(entry.get("username", ""))),
            f"{password}  👁",
            extract_domain(str(entry.get("url", ""))),
            format_modified(str(entry.get("updated_at", ""))),
            "⧉ User",
            "⧉ Pass",
            "● Active" if entry_id == self._clipboard_entry_id else "",
        )

    def _refresh_visible_rows(self) -> None:
        for entry_id in tuple(self._entries):
            self._refresh_row(entry_id)

    def _refresh_row(self, entry_id: str) -> None:
        if self.tree.exists(entry_id):
            self.tree.item(
                entry_id, values=self._display_values(self._entries[entry_id])
            )

    def _show_context_menu(self, event) -> None:
        entry_id = self.tree.identify_row(event.y)
        if not entry_id:
            return
        if entry_id not in self.tree.selection():
            self.tree.selection_set(entry_id)
        self.tree.focus(entry_id)
        if self._context_menu.index("end") is not None:
            self._context_menu.tk_popup(event.x_root, event.y_root)

    def _start_heading_drag(self, event) -> None:
        if self.tree.identify_region(event.x, event.y) == "heading":
            self._heading_drag_start = self._column_position(event.x)

    def _finish_pointer_action(self, event) -> None:
        region = self.tree.identify_region(event.x, event.y)
        column = self.tree.identify_column(event.x)
        if region == "cell" and column == "#3":
            entry_id = self.tree.identify_row(event.y)
            if entry_id:
                self.tree.focus(entry_id)
                self.toggle_selected_password()
        elif region == "cell" and column in {"#6", "#7"}:
            entry_id = self.tree.identify_row(event.y)
            if entry_id:
                self.tree.selection_set(entry_id)
                self.tree.focus(entry_id)
                callback = (
                    self._on_copy_username if column == "#6" else self._on_copy_password
                )
                if callback is not None:
                    callback()

        if region == "heading" and self._heading_drag_start is not None:
            end = self._column_position(event.x)
            if end is not None and end != self._heading_drag_start:
                display_columns = list(self.tree["displaycolumns"])
                if display_columns == ["#all"]:
                    display_columns = list(self.COLUMNS)
                moved = display_columns.pop(self._heading_drag_start)
                display_columns.insert(end, moved)
                self.tree.configure(displaycolumns=display_columns)
        self._heading_drag_start = None

    def _column_position(self, x: int) -> int | None:
        identifier = self.tree.identify_column(x)
        if not identifier.startswith("#"):
            return None
        position = int(identifier[1:]) - 1
        return position if 0 <= position < len(self.COLUMNS) else None

    @staticmethod
    def _coerce_row(row) -> dict:
        if isinstance(row, dict):
            return row
        if len(row) >= 4:
            return {
                "id": row[0],
                "title": row[1],
                "username": row[2],
                "password": "",
                "url": row[3],
                "updated_at": "",
            }
        raise ValueError(
            "SecureTable rows must be dictionaries or four-value sequences."
        )

    @staticmethod
    def _configure_style() -> None:
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background="#2b2b2b",
            foreground="white",
            fieldbackground="#2b2b2b",
            rowheight=38,
            borderwidth=0,
            font=("Segoe UI", 12),
        )
        style.map(
            "Treeview",
            background=[("selected", "#d98ca3")],
            foreground=[("selected", "white")],
        )
        style.configure(
            "Treeview.Heading",
            background="#3a3a3a",
            foreground="white",
            font=("Segoe UI", 12, "bold"),
            relief="flat",
            borderwidth=0,
        )
