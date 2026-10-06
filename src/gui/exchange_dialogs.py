from __future__ import annotations

import os
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any

import customtkinter as ctk

from src.core.import_export import ExportOptions, ImportOptions, SharePermissions

FORMAT_LABELS = {
    "Encrypted JSON": "encrypted_json",
    "CSV migration": "csv",
    "Bitwarden JSON": "bitwarden_json",
    "LastPass CSV": "lastpass_csv",
}


class SecretInputDialog(ctk.CTkToplevel):
    """Small modal prompt that masks a secret while it is entered."""

    def __init__(self, parent, *, title: str, prompt: str) -> None:
        super().__init__(parent)
        self.title(title)
        self.geometry("480x190")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result: str | None = None

        ctk.CTkLabel(self, text=prompt, wraplength=430, justify="left").pack(
            fill="x", padx=22, pady=(22, 10)
        )
        self.entry = ctk.CTkEntry(self, show="•")
        self.entry.pack(fill="x", padx=22, pady=6)
        self.entry.bind("<Return>", lambda _event: self._accept())

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", padx=22, pady=(10, 18))
        ctk.CTkButton(buttons, text="Cancel", command=self.destroy).pack(
            side="right", padx=(6, 0)
        )
        ctk.CTkButton(buttons, text="Continue", command=self._accept).pack(side="right")
        self.after(50, self.entry.focus_set)

    def _accept(self) -> None:
        self.result = self.entry.get()
        self.entry.delete(0, "end")
        self.destroy()

    def get_input(self) -> str | None:
        self.wait_window()
        return self.result


class ExportDialog(ctk.CTkToplevel):
    """Present the export dialog interface."""

    def __init__(self, parent, entries: list[dict[str, Any]], exporter) -> None:
        super().__init__(parent)
        self.title("Export Vault")
        self.geometry("820x670")
        self.minsize(760, 600)
        self.transient(parent)
        self.grab_set()
        self.exporter = exporter
        self.entries = entries
        self.result: dict[str, Any] | None = None
        self._selected = {str(entry["id"]) for entry in entries}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)
        ctk.CTkLabel(
            self,
            text="Secure Vault Export",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=22, pady=(20, 10))

        format_frame = ctk.CTkFrame(self)
        format_frame.grid(row=1, column=0, sticky="ew", padx=22, pady=6)
        format_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(format_frame, text="Format").grid(
            row=0, column=0, padx=12, pady=12
        )
        self.format_var = ctk.StringVar(value="Encrypted JSON")
        self.format_box = ctk.CTkComboBox(
            format_frame,
            values=list(FORMAT_LABELS),
            variable=self.format_var,
            command=self._update_description,
            width=190,
        )
        self.format_box.grid(row=0, column=1, sticky="w", padx=8, pady=12)
        self.description = ctk.CTkLabel(format_frame, text="", anchor="w")
        self.description.grid(
            row=1, column=0, columnspan=3, sticky="ew", padx=12, pady=(0, 12)
        )

        encryption = ctk.CTkFrame(self)
        encryption.grid(row=2, column=0, sticky="ew", padx=22, pady=6)
        for column in range(4):
            encryption.grid_columnconfigure(column, weight=1)
        ctk.CTkLabel(encryption, text="Encryption").grid(
            row=0, column=0, padx=10, pady=10
        )
        self.encryption_var = ctk.StringVar(value="Password")
        ctk.CTkComboBox(
            encryption,
            values=["Password", "Public key file", "Plaintext migration"],
            variable=self.encryption_var,
            command=self._encryption_changed,
        ).grid(row=0, column=1, padx=10, pady=10)
        self.password_entry = ctk.CTkEntry(
            encryption, show="•", placeholder_text="Export password"
        )
        self.password_entry.grid(row=0, column=2, sticky="ew", padx=10, pady=10)
        self.key_button = ctk.CTkButton(
            encryption,
            text="Choose Public Key",
            command=self._choose_key,
            state="disabled",
        )
        self.key_button.grid(row=0, column=3, padx=10, pady=10)
        self.key_path: Path | None = None
        self.bits_var = ctk.StringVar(value="256-bit")
        ctk.CTkComboBox(
            encryption,
            values=["128-bit", "256-bit"],
            variable=self.bits_var,
            width=120,
        ).grid(row=1, column=1, padx=10, pady=(0, 10))
        self.compress_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            encryption, text="GZIP compression", variable=self.compress_var
        ).grid(row=1, column=2, padx=10, pady=(0, 10))
        self.notes_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(encryption, text="Include notes", variable=self.notes_var).grid(
            row=1, column=3, padx=10, pady=(0, 10)
        )

        selection_header = ctk.CTkFrame(self, fg_color="transparent")
        selection_header.grid(row=3, column=0, sticky="ew", padx=22, pady=(8, 2))
        ctk.CTkLabel(selection_header, text="Entries").pack(side="left")
        ctk.CTkButton(
            selection_header, text="Select All", width=90, command=self._select_all
        ).pack(side="right", padx=4)
        ctk.CTkButton(
            selection_header, text="Clear", width=70, command=self._clear_all
        ).pack(side="right", padx=4)

        tree_frame = ctk.CTkFrame(self)
        tree_frame.grid(row=4, column=0, sticky="nsew", padx=22, pady=6)
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            tree_frame, columns=("selected", "title", "username"), show="headings"
        )
        self.tree.heading("selected", text="Use")
        self.tree.heading("title", text="Title")
        self.tree.heading("username", text="Username")
        self.tree.column("selected", width=55, anchor="center")
        self.tree.column("title", width=260)
        self.tree.column("username", width=280)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.tree.bind("<Double-1>", self._toggle_entry)
        for entry in entries:
            entry_id = str(entry["id"])
            self.tree.insert(
                "",
                "end",
                iid=entry_id,
                values=("☑", entry.get("title", ""), entry.get("username", "")),
            )

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=5, column=0, sticky="ew", padx=22, pady=(6, 18))
        footer.grid_columnconfigure(0, weight=1)
        self.preview_label = ctk.CTkLabel(footer, text="", anchor="w")
        self.preview_label.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(footer, text="Preview", command=self._preview).grid(
            row=0, column=1, padx=6
        )
        ctk.CTkButton(footer, text="Cancel", command=self.destroy).grid(
            row=0, column=2, padx=6
        )
        ctk.CTkButton(footer, text="Export", command=self._accept).grid(
            row=0, column=3, padx=6
        )
        self._update_description()
        self._preview()

    def _update_description(self, _value: str | None = None) -> None:
        descriptions = {
            "Encrypted JSON": "Native format with complete metadata and integrity protection.",
            "CSV migration": "Portable columns for migration; encryption remains enabled by default.",
            "Bitwarden JSON": "Login items compatible with Bitwarden import.",
            "LastPass CSV": "Columns compatible with LastPass import and export.",
        }
        self.description.configure(text=descriptions[self.format_var.get()])

    def _encryption_changed(self, value: str) -> None:
        self.password_entry.configure(
            state="normal" if value == "Password" else "disabled"
        )
        self.key_button.configure(
            state="normal" if value == "Public key file" else "disabled"
        )

    def _choose_key(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Choose Recipient Public Key",
            filetypes=[("PEM public key", "*.pem"), ("All files", "*")],
        )
        if selected:
            self.key_path = Path(selected)
            self.key_button.configure(text=self.key_path.name)

    def _toggle_entry(self, _event=None) -> None:
        selected = self.tree.focus()
        if not selected:
            return
        if selected in self._selected:
            self._selected.remove(selected)
            marker = "☐"
        else:
            self._selected.add(selected)
            marker = "☑"
        values = list(self.tree.item(selected, "values"))
        values[0] = marker
        self.tree.item(selected, values=values)
        self._preview()

    def _select_all(self) -> None:
        self._selected = {str(entry["id"]) for entry in self.entries}
        for item in self.tree.get_children():
            values = list(self.tree.item(item, "values"))
            values[0] = "☑"
            self.tree.item(item, values=values)
        self._preview()

    def _clear_all(self) -> None:
        self._selected.clear()
        for item in self.tree.get_children():
            values = list(self.tree.item(item, "values"))
            values[0] = "☐"
            self.tree.item(item, values=values)
        self._preview()

    def _options(self) -> ExportOptions:
        encryption = self.encryption_var.get()
        return ExportOptions(
            format_name=FORMAT_LABELS[self.format_var.get()],
            entry_ids=tuple(self._selected),
            excluded_fields=frozenset()
            if self.notes_var.get()
            else frozenset({"notes"}),
            encryption_bits=128 if self.bits_var.get() == "128-bit" else 256,
            compress=self.compress_var.get(),
            encrypt=encryption != "Plaintext migration",
            allow_plaintext=encryption == "Plaintext migration",
        )

    def _preview(self) -> None:
        try:
            preview = self.exporter.preview(self._options())
            self.preview_label.configure(
                text=f"{preview['entry_count']} entries | {preview['format']} | "
                f"{'encrypted' if preview['encrypted'] else 'plaintext migration'}"
            )
        except ValueError as exc:
            self.preview_label.configure(text=str(exc))

    def _accept(self) -> None:
        if not self._selected:
            self.preview_label.configure(text="Select at least one entry.")
            return
        encryption = self.encryption_var.get()
        password = self.password_entry.get() if encryption == "Password" else None
        if encryption == "Password" and not password:
            self.preview_label.configure(text="Enter an export password.")
            return
        if encryption == "Public key file" and self.key_path is None:
            self.preview_label.configure(text="Choose a recipient public key.")
            return
        destination = filedialog.asksaveasfilename(
            parent=self,
            title="Save Export",
            defaultextension=".csm.json",
            filetypes=[("CryptoSafe export", "*.json *.csv"), ("All files", "*")],
        )
        if not destination:
            return
        self.result = {
            "destination": Path(destination),
            "options": self._options(),
            "export_password": password,
            "recipient_public_key": self.key_path.read_bytes()
            if self.key_path
            else None,
        }
        self.destroy()


class ImportDialog(ctk.CTkToplevel):
    """Present the import dialog interface."""

    def __init__(self, parent, importer) -> None:
        super().__init__(parent)
        self.title("Import Vault")
        self.geometry("820x650")
        self.transient(parent)
        self.grab_set()
        self.importer = importer
        self.result: dict[str, Any] | None = None
        self.path: Path | None = None
        self.private_key_path: Path | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(
            self,
            text="Validated Vault Import",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=22, pady=(20, 10))
        source = ctk.CTkFrame(self)
        source.grid(row=1, column=0, sticky="ew", padx=22, pady=6)
        source.grid_columnconfigure(0, weight=1)
        self.path_label = ctk.CTkLabel(source, text="No file selected", anchor="w")
        self.path_label.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
        ctk.CTkButton(source, text="Choose File", command=self._choose_file).grid(
            row=0, column=1, padx=12, pady=12
        )

        options = ctk.CTkFrame(self)
        options.grid(row=2, column=0, sticky="ew", padx=22, pady=6)
        for column in range(4):
            options.grid_columnconfigure(column, weight=1)
        self.format_var = ctk.StringVar(value="Auto detect")
        ctk.CTkComboBox(
            options, values=["Auto detect", *FORMAT_LABELS], variable=self.format_var
        ).grid(row=0, column=0, padx=8, pady=10)
        self.mode_var = ctk.StringVar(value="Merge")
        ctk.CTkComboBox(
            options, values=["Merge", "Replace", "Dry run"], variable=self.mode_var
        ).grid(row=0, column=1, padx=8, pady=10)
        self.conflict_var = ctk.StringVar(value="Update existing")
        ctk.CTkComboBox(
            options,
            values=["Update existing", "Skip duplicates", "Keep both"],
            variable=self.conflict_var,
        ).grid(row=0, column=2, padx=8, pady=10)
        self.password_entry = ctk.CTkEntry(
            options, show="•", placeholder_text="Export password"
        )
        self.password_entry.grid(row=0, column=3, sticky="ew", padx=8, pady=10)
        self.key_button = ctk.CTkButton(
            options, text="Private Key", command=self._choose_private_key
        )
        self.key_button.grid(row=1, column=3, padx=8, pady=(0, 10))

        ctk.CTkLabel(self, text="Preview").grid(
            row=3, column=0, sticky="w", padx=24, pady=(8, 2)
        )
        tree_frame = ctk.CTkFrame(self)
        tree_frame.grid(row=4, column=0, sticky="nsew", padx=22, pady=6)
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            tree_frame, columns=("title", "username", "url"), show="headings"
        )
        for column, label, width in (
            ("title", "Title", 220),
            ("username", "Username", 220),
            ("url", "URL", 300),
        ):
            self.tree.heading(column, text=label)
            self.tree.column(column, width=width)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=5, column=0, sticky="ew", padx=22, pady=(6, 18))
        footer.grid_columnconfigure(0, weight=1)
        self.summary = ctk.CTkLabel(
            footer, text="Choose a file to inspect it.", anchor="w"
        )
        self.summary.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(footer, text="Preview", command=self._preview).grid(
            row=0, column=1, padx=6
        )
        ctk.CTkButton(footer, text="Cancel", command=self.destroy).grid(
            row=0, column=2, padx=6
        )
        ctk.CTkButton(footer, text="Import", command=self._accept).grid(
            row=0, column=3, padx=6
        )

    def _choose_file(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Choose Import File",
            filetypes=[("Supported exports", "*.json *.csv"), ("All files", "*")],
        )
        if selected:
            self.path = Path(selected)
            self.path_label.configure(text=str(self.path))
            self._preview()

    def _choose_private_key(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Choose Private Key",
            filetypes=[("PEM private key", "*.pem"), ("All files", "*")],
        )
        if selected:
            self.private_key_path = Path(selected)
            self.key_button.configure(text=self.private_key_path.name)

    def _options(self, *, preview: bool) -> ImportOptions:
        modes = {"Merge": "merge", "Replace": "replace", "Dry run": "dry_run"}
        conflicts = {
            "Update existing": "update",
            "Skip duplicates": "skip",
            "Keep both": "duplicate",
        }
        selected_format = self.format_var.get()
        return ImportOptions(
            mode="dry_run" if preview else modes[self.mode_var.get()],
            conflict_action=conflicts[self.conflict_var.get()],
            format_name=None
            if selected_format == "Auto detect"
            else FORMAT_LABELS[selected_format],
        )

    def _credentials(self) -> dict[str, Any]:
        password = self.password_entry.get() or None
        return {
            "password": password,
            "private_key": self.private_key_path.read_bytes()
            if self.private_key_path
            else None,
        }

    def _preview(self) -> None:
        if self.path is None:
            return
        try:
            preview = self.importer.preview(
                self.path, self._options(preview=True), **self._credentials()
            )
        except Exception as exc:  # noqa: BLE001 - validation errors are shown in the dialog
            self.summary.configure(text=str(exc))
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        for entry in preview.entries[:500]:
            self.tree.insert(
                "",
                "end",
                values=(
                    entry.get("title", ""),
                    entry.get("username", ""),
                    entry.get("url", ""),
                ),
            )
        totals = preview.summary()
        self.summary.configure(
            text=f"Detected {preview.format_name}: {totals['entries']} entries, "
            f"{totals['new']} new, {totals['updated']} updates, "
            f"{totals['skipped']} skipped, {totals['warnings']} warnings"
        )

    def _accept(self) -> None:
        if self.path is None:
            self.summary.configure(text="Choose an import file first.")
            return
        self.result = {
            "source": self.path,
            "options": self._options(preview=False),
            **self._credentials(),
        }
        self.destroy()


class SharingDialog(ctk.CTkToplevel):
    """Present the sharing dialog interface."""

    def __init__(
        self, parent, entry: dict[str, Any], service, contacts: list[dict[str, Any]]
    ) -> None:
        super().__init__(parent)
        self.title("Share Entry")
        self.geometry("760x650")
        self.transient(parent)
        self.grab_set()
        self.entry = entry
        self.service = service
        self.contacts = contacts
        self.result: dict[str, Any] | None = None
        self.public_key_path: Path | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)
        ctk.CTkLabel(
            self,
            text=f"Share {entry.get('title', '')}",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=22, pady=(20, 10))

        form = ctk.CTkFrame(self)
        form.grid(row=1, column=0, sticky="ew", padx=22, pady=6)
        for column in range(4):
            form.grid_columnconfigure(column, weight=1)
        contact_values = [f"{item['name']} <{item['identifier']}>" for item in contacts]
        self.recipient_var = ctk.StringVar(
            value=contact_values[0] if contact_values else ""
        )
        self.recipient_box = ctk.CTkComboBox(
            form,
            values=contact_values or [""],
            variable=self.recipient_var,
            state="normal",
        )
        self.recipient_box.grid(
            row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=10
        )
        self.method_var = ctk.StringVar(value="Password")
        ctk.CTkComboBox(
            form,
            values=["Password", "RSA", "ECC P-256"],
            variable=self.method_var,
            command=self._method_changed,
        ).grid(row=0, column=2, padx=8, pady=10)
        self.delivery_var = ctk.StringVar(value="File")
        ctk.CTkComboBox(
            form, values=["File", "QR", "Link"], variable=self.delivery_var
        ).grid(row=0, column=3, padx=8, pady=10)
        self.password_entry = ctk.CTkEntry(
            form, show="•", placeholder_text="Share password"
        )
        self.password_entry.grid(
            row=1, column=0, columnspan=2, sticky="ew", padx=8, pady=10
        )
        self.key_button = ctk.CTkButton(
            form,
            text="Choose Public Key",
            command=self._choose_public_key,
            state="disabled",
        )
        self.key_button.grid(row=1, column=2, padx=8, pady=10)
        self.days_var = ctk.StringVar(value="7 days")
        ctk.CTkComboBox(
            form,
            values=["1 day", "3 days", "7 days", "14 days", "30 days"],
            variable=self.days_var,
        ).grid(row=1, column=3, padx=8, pady=10)

        permissions = ctk.CTkFrame(self)
        permissions.grid(row=2, column=0, sticky="ew", padx=22, pady=6)
        self.edit_var = ctk.BooleanVar(value=False)
        self.notes_var = ctk.BooleanVar(value=True)
        self.totp_var = ctk.BooleanVar(value=False)
        ctk.CTkLabel(
            permissions, text="Permissions: read access is always required"
        ).pack(side="left", padx=12, pady=12)
        ctk.CTkCheckBox(permissions, text="Allow editing", variable=self.edit_var).pack(
            side="left", padx=10
        )
        ctk.CTkCheckBox(
            permissions, text="Include notes", variable=self.notes_var
        ).pack(side="left", padx=10)
        ctk.CTkCheckBox(permissions, text="Include TOTP", variable=self.totp_var).pack(
            side="left", padx=10
        )

        ctk.CTkLabel(self, text="Share history and status").grid(
            row=3, column=0, sticky="w", padx=24, pady=(8, 2)
        )
        history = ctk.CTkFrame(self)
        history.grid(row=5, column=0, sticky="nsew", padx=22, pady=6)
        history.grid_rowconfigure(0, weight=1)
        history.grid_columnconfigure(0, weight=1)
        self.history_tree = ttk.Treeview(
            history,
            columns=("recipient", "method", "expires", "status"),
            show="headings",
        )
        for column, label in (
            ("recipient", "Recipient"),
            ("method", "Encryption"),
            ("expires", "Expires"),
            ("status", "Status"),
        ):
            self.history_tree.heading(column, text=label)
        self.history_tree.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        for item in service.share_history():
            self.history_tree.insert(
                "",
                "end",
                values=(
                    item["recipient_info"],
                    item["encryption_method"],
                    item["expires_at"],
                    item["status"],
                ),
            )

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=6, column=0, sticky="ew", padx=22, pady=(6, 18))
        footer.grid_columnconfigure(0, weight=1)
        self.message = ctk.CTkLabel(footer, text="", anchor="w")
        self.message.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(footer, text="Cancel", command=self.destroy).grid(
            row=0, column=1, padx=6
        )
        ctk.CTkButton(footer, text="Create Share", command=self._accept).grid(
            row=0, column=2, padx=6
        )

    def _method_changed(self, value: str) -> None:
        self.password_entry.configure(
            state="normal" if value == "Password" else "disabled"
        )
        self.key_button.configure(state="disabled" if value == "Password" else "normal")

    def _choose_public_key(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Choose Recipient Public Key",
            filetypes=[("PEM public key", "*.pem"), ("All files", "*")],
        )
        if selected:
            self.public_key_path = Path(selected)
            self.key_button.configure(text=self.public_key_path.name)

    def _accept(self) -> None:
        recipient = self.recipient_var.get().strip()
        if not recipient:
            self.message.configure(text="Enter or select a recipient.")
            return
        method_label = self.method_var.get()
        contact_key = None
        if method_label != "Password":
            contact_key = self._selected_contact_key()
            if contact_key is None and self.public_key_path is not None:
                contact_key = self.public_key_path.read_bytes()
            if contact_key is None:
                self.message.configure(text="Choose a contact or a public-key file.")
                return
        password = self.password_entry.get() if method_label == "Password" else None
        if method_label == "Password" and not password:
            self.message.configure(text="Enter a share password.")
            return
        fields = {"title", "username", "password", "url", "category", "tags"}
        if self.notes_var.get():
            fields.add("notes")
        if self.totp_var.get():
            fields.add("totp_secret")
        days = int(self.days_var.get().split()[0])
        self.result = {
            "entry_id": str(self.entry["id"]),
            "recipient": recipient,
            "method": {"Password": "password", "RSA": "rsa", "ECC P-256": "ecc"}[
                method_label
            ],
            "password": password,
            "recipient_public_key": contact_key,
            "delivery_method": self.delivery_var.get().casefold(),
            "permissions": SharePermissions(
                edit=self.edit_var.get(), expires_in_days=days, fields=frozenset(fields)
            ),
        }
        self.destroy()

    def _selected_contact_key(self) -> bytes | None:
        label = self.recipient_var.get()
        for contact in self.contacts:
            if (
                label == f"{contact['name']} <{contact['identifier']}>"
                and not contact.get("revoked_at")
            ):
                return bytes(contact["public_key"])
        return None


class ReceiveShareDialog(ctk.CTkToplevel):
    """Present the receive share dialog interface."""

    def __init__(self, parent, qr_service) -> None:
        super().__init__(parent)
        self.title("Receive Shared Entry")
        self.geometry("820x430")
        self.minsize(780, 400)
        self.transient(parent)
        self.grab_set()
        self.qr_service = qr_service
        self.result: dict[str, Any] | None = None
        self.package_path: Path | None = None
        self.private_key_path: Path | None = None
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self, text="Receive Shared Entry", font=ctk.CTkFont(size=22, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=22, pady=(20, 10))
        self.link_box = ctk.CTkTextbox(self, height=100)
        self.link_box.grid(row=1, column=0, sticky="ew", padx=22, pady=6)
        self.link_box.insert(
            "1.0", "Paste a cryptosafe:// share link here, or choose a package file."
        )
        buttons = ctk.CTkFrame(self)
        buttons.grid(row=2, column=0, sticky="ew", padx=22, pady=6)
        for label, command in (
            ("Package File", self._choose_package),
            ("QR Image", self._scan_image),
            ("Camera", self._scan_camera),
            ("Clipboard QR", self._scan_clipboard),
            ("Private Key", self._choose_private_key),
        ):
            ctk.CTkButton(buttons, text=label, command=command).pack(
                side="left", expand=True, fill="x", padx=5, pady=10
            )
        form = ctk.CTkFrame(self)
        form.grid(row=3, column=0, sticky="ew", padx=22, pady=6)
        self.password_entry = ctk.CTkEntry(
            form, show="•", placeholder_text="Share password, if required"
        )
        self.password_entry.pack(side="left", expand=True, fill="x", padx=12, pady=12)
        self.save_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(form, text="Save to vault", variable=self.save_var).pack(
            side="left", padx=12
        )
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=4, column=0, sticky="ew", padx=22, pady=(8, 18))
        footer.grid_columnconfigure(0, weight=1)
        self.message = ctk.CTkLabel(footer, text="", anchor="w")
        self.message.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(footer, text="Cancel", command=self.destroy).grid(
            row=0, column=1, padx=6
        )
        ctk.CTkButton(footer, text="Open Share", command=self._accept).grid(
            row=0, column=2, padx=6
        )

    def _choose_package(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Choose Share Package",
            filetypes=[("CryptoSafe share", "*.json *.csmshare"), ("All files", "*")],
        )
        if selected:
            self.package_path = Path(selected)
            self.message.configure(text=str(self.package_path))

    def _choose_private_key(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Choose Private Key",
            filetypes=[("PEM private key", "*.pem"), ("All files", "*")],
        )
        if selected:
            self.private_key_path = Path(selected)
            self.message.configure(text=f"Private key: {self.private_key_path.name}")

    def _scan_image(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Choose QR Image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*")],
        )
        if not selected:
            return
        try:
            chunk = self.qr_service.scan_image(selected)
            payload = self.qr_service.decode_chunks([chunk])
            self._load_qr_payload(payload)
        except Exception as exc:  # noqa: BLE001 - scanner errors are shown to the user
            self.message.configure(text=str(exc))

    def _scan_camera(self) -> None:
        try:
            chunk = self.qr_service.scan_camera(timeout_seconds=10)
            payload = self.qr_service.decode_chunks([chunk])
            self._load_qr_payload(payload)
        except Exception as exc:  # noqa: BLE001 - scanner errors are shown to the user
            self.message.configure(text=str(exc))

    def _scan_clipboard(self) -> None:
        try:
            chunk = self.qr_service.scan_clipboard_image()
            payload = self.qr_service.decode_chunks([chunk])
            self._load_qr_payload(payload)
        except Exception as exc:  # noqa: BLE001 - scanner errors are shown to the user
            self.message.configure(text=str(exc))

    def _load_qr_payload(self, payload) -> None:
        if payload.payload_type == "share_link":
            self.link_box.delete("1.0", "end")
            self.link_box.insert("1.0", payload.data.decode("utf-8"))
        elif payload.payload_type == "encrypted_entry":
            self.package_path = None
            self.link_box.delete("1.0", "end")
            self.link_box.insert("1.0", payload.data.decode("utf-8"))
        else:
            self.message.configure(
                text="This QR code contains a public key, not a shared entry."
            )

    def _accept(self) -> None:
        if self.package_path is not None:
            package = self.package_path.read_bytes()
        else:
            package = self.link_box.get("1.0", "end").strip()
        if not package or str(package).startswith("Paste a cryptosafe"):
            self.message.configure(text="Choose a package or paste a share link.")
            return
        self.result = {
            "package_or_link": package,
            "password": self.password_entry.get() or None,
            "private_key": self.private_key_path.read_bytes()
            if self.private_key_path
            else None,
            "save_to_vault": self.save_var.get(),
        }
        self.destroy()


class ContactsDialog(ctk.CTkToplevel):
    """Present the contacts dialog interface."""

    def __init__(self, parent, service) -> None:
        super().__init__(parent)
        self.title("Key Exchange Contacts")
        self.geometry("840x560")
        self.transient(parent)
        self.grab_set()
        self.service = service
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            self, text="Public Key Contacts", font=ctk.CTkFont(size=22, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=22, pady=(20, 10))
        frame = ctk.CTkFrame(self)
        frame.grid(row=1, column=0, sticky="nsew", padx=22, pady=6)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            frame,
            columns=(
                "name",
                "identifier",
                "algorithm",
                "fingerprint",
                "verified",
                "status",
            ),
            show="headings",
        )
        for column, label in (
            ("name", "Name"),
            ("identifier", "Identifier"),
            ("algorithm", "Algorithm"),
            ("fingerprint", "Fingerprint"),
            ("verified", "Verified"),
            ("status", "Status"),
        ):
            self.tree.heading(column, text=label)
        self.tree.column("fingerprint", width=280)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", padx=22, pady=(6, 18))
        for label, command in (
            ("Add", self._add),
            ("Verify", self._verify),
            ("Rotate", self._rotate),
            ("Revoke", self._revoke),
            ("Generate My Keys", self._generate),
            ("Close", self.destroy),
        ):
            ctk.CTkButton(actions, text=label, command=command).pack(
                side="left", padx=4
            )
        self.message = ctk.CTkLabel(actions, text="")
        self.message.pack(side="right", padx=8)
        self._reload()

    def _reload(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for contact in self.service.list_contacts(include_revoked=True):
            self.tree.insert(
                "",
                "end",
                iid=contact["contact_id"],
                values=(
                    contact["name"],
                    contact["identifier"],
                    contact["algorithm"],
                    contact["fingerprint"],
                    "yes" if contact["verified"] else "no",
                    "revoked" if contact["revoked_at"] else "active",
                ),
            )

    def _add(self) -> None:
        name = ctk.CTkInputDialog(text="Contact name:", title="Add Contact").get_input()
        identifier = ctk.CTkInputDialog(
            text="Email or identifier:", title="Add Contact"
        ).get_input()
        path = filedialog.askopenfilename(
            parent=self,
            title="Choose Public Key",
            filetypes=[("PEM public key", "*.pem"), ("All files", "*")],
        )
        if not name or not identifier or not path:
            return
        try:
            self.service.add_contact(name, identifier, Path(path).read_bytes())
            self._reload()
        except Exception as exc:  # noqa: BLE001 - validation errors are shown in the dialog
            self.message.configure(text=str(exc))

    def _verify(self) -> None:
        contact_id = self.tree.focus()
        if not contact_id:
            return
        fingerprint = ctk.CTkInputDialog(
            text="Fingerprint confirmed over a second channel:", title="Verify Key"
        ).get_input()
        if fingerprint:
            ok = self.service.verify_contact_fingerprint(contact_id, fingerprint)
            self.message.configure(text="Verified" if ok else "Fingerprint mismatch")
            self._reload()

    def _rotate(self) -> None:
        contact_id = self.tree.focus()
        if not contact_id:
            return
        path = filedialog.askopenfilename(
            parent=self,
            title="Choose New Public Key",
            filetypes=[("PEM public key", "*.pem"), ("All files", "*")],
        )
        if path:
            self.service.rotate_contact_key(contact_id, Path(path).read_bytes())
            self._reload()

    def _revoke(self) -> None:
        contact_id = self.tree.focus()
        if contact_id:
            self.service.revoke_contact_key(contact_id)
            self._reload()

    def _generate(self) -> None:
        algorithm = ctk.CTkInputDialog(
            text="Enter RSA-2048 or ECC-P256:", title="Generate Key Pair"
        ).get_input()
        if not algorithm:
            return
        folder = filedialog.askdirectory(parent=self, title="Choose Key Folder")
        if not folder:
            return
        passphrase = SecretInputDialog(
            self,
            title="Protect Private Key",
            prompt="Password phrase for the private key (at least 12 characters):",
        ).get_input()
        if passphrase is None:
            return
        if len(passphrase) < 12:
            self.message.configure(text="The private-key password is too short.")
            return
        try:
            pair = self.service.generate_key_pair(
                algorithm, private_key_password=passphrase.encode("utf-8")
            )
            base = Path(folder)
            private_path = base / "cryptosafe_private_key.pem"
            public_path = base / "cryptosafe_public_key.pem"
            private_path.write_bytes(pair.private_key)
            os.chmod(private_path, 0o600)
            public_path.write_bytes(pair.public_key)
            self.message.configure(text=f"Fingerprint: {pair.fingerprint}")
        except Exception as exc:  # noqa: BLE001 - validation errors are shown in the dialog
            self.message.configure(text=str(exc))
