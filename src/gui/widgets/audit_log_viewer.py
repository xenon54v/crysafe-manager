from __future__ import annotations

import json
import tkinter as tk
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, ttk
from typing import ClassVar

import customtkinter as ctk

from src.core.audit import AuditLogExporter, AuditQuery
from src.core.audit.log_verifier import AuditLogVerifier, VerificationReport

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"
WINDOW_BG = "#1f1f1f"
CARD_BG = "#2b2b2b"
BORDER = "#3a3a3a"


class AuditLogViewer(ctk.CTkToplevel):
    COLUMN_MAP: ClassVar[dict[str, str]] = {
        "Seq": "sequence_number",
        "Time": "timestamp",
        "Event": "event_type",
        "Severity": "severity",
        "User": "user_id",
        "Source": "source",
        "Entry": "entry_id",
    }

    def __init__(
        self,
        parent,
        audit_logger,
        *,
        confirm_master_password: Callable[[], bool] | None = None,
        on_entry_selected: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.parent = parent
        self.audit_logger = audit_logger
        self.exporter = AuditLogExporter(audit_logger, audit_logger.key_manager)
        self.confirm_master_password = confirm_master_password or (lambda: False)
        self.on_entry_selected = on_entry_selected
        self.current_page = 1
        self.current_pages = 1
        self.current_entries: dict[str, dict] = {}
        self.sort_by = "sequence_number"
        self.sort_descending = True
        self.last_report: VerificationReport | None = None

        self.title("Secure Audit Trail")
        self.geometry("1280x760")
        self.minsize(1050, 650)
        self.configure(fg_color=WINDOW_BG)
        self.transient(parent)
        self.grab_set()
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._configure_tree_style()
        self._create_header()
        self._create_filters()
        self._create_tabs()
        self._create_footer()
        self._bind_shortcuts()
        self._center_window()
        self._load_logs()

    def _create_header(self) -> None:
        header = ctk.CTkFrame(self, corner_radius=0, fg_color="#242424")
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Secure Audit Trail",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).grid(row=0, column=0, padx=22, pady=18, sticky="w")
        self.integrity_label = ctk.CTkLabel(
            header,
            text="Integrity unknown",
            text_color="#fbbf24",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.integrity_label.grid(row=0, column=1, padx=12)
        for column, (text, command) in enumerate(
            (
                ("Verify", self._verify_full),
                ("Export", self._export),
                ("Close", self.destroy),
            ),
            start=2,
        ):
            ctk.CTkButton(
                header,
                text=text,
                width=100,
                command=command,
                fg_color=PINK,
                hover_color=PINK_HOVER,
            ).grid(row=0, column=column, padx=(0, 12), pady=18)

    def _create_filters(self) -> None:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(12, 0))
        frame.grid_columnconfigure(0, weight=1)
        self.search_entry = ctk.CTkEntry(
            frame,
            placeholder_text="Search in event details",
        )
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.search_entry.bind("<Return>", lambda _event: self._reset_and_load())
        self.event_filter = ctk.CTkComboBox(
            frame,
            width=190,
            values=["All events"],
            command=lambda _value: self._reset_and_load(),
        )
        self.event_filter.grid(row=0, column=1, padx=4)
        self.event_filter.set("All events")
        self.severity_filter = ctk.CTkComboBox(
            frame,
            width=125,
            values=["All severities", "INFO", "WARN", "ERROR", "CRITICAL"],
            command=lambda _value: self._reset_and_load(),
        )
        self.severity_filter.grid(row=0, column=2, padx=4)
        self.severity_filter.set("All severities")
        self.user_filter = ctk.CTkEntry(frame, width=150, placeholder_text="User")
        self.user_filter.grid(row=0, column=3, padx=4)
        self.date_filter = ctk.CTkComboBox(
            frame,
            width=135,
            values=["Any date", "Last 7 days", "Last 30 days", "Last 90 days"],
            command=lambda _value: self._reset_and_load(),
        )
        self.date_filter.grid(row=0, column=4, padx=4)
        self.date_filter.set("Any date")
        ctk.CTkButton(
            frame,
            text="Apply",
            width=80,
            command=self._reset_and_load,
            fg_color=PINK,
            hover_color=PINK_HOVER,
        ).grid(row=0, column=5, padx=(8, 0))

    def _create_tabs(self) -> None:
        self.tabs = ctk.CTkTabview(
            self,
            fg_color=CARD_BG,
            segmented_button_selected_color=PINK,
            segmented_button_selected_hover_color=PINK_HOVER,
        )
        self.tabs.grid(row=2, column=0, sticky="nsew", padx=20, pady=14)
        logs_tab = self.tabs.add("Events")
        dashboard_tab = self.tabs.add("Dashboard")
        logs_tab.grid_rowconfigure(0, weight=1)
        logs_tab.grid_columnconfigure(0, weight=3)
        logs_tab.grid_columnconfigure(1, weight=2)
        self._create_log_table(logs_tab)
        self._create_details_panel(logs_tab)
        self._create_dashboard(dashboard_tab)

    def _create_log_table(self, parent) -> None:
        table_frame = ctk.CTkFrame(parent, fg_color="transparent")
        table_frame.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        columns = tuple(self.COLUMN_MAP)
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        widths = {
            "Seq": 55,
            "Time": 145,
            "Event": 190,
            "Severity": 85,
            "User": 110,
            "Source": 120,
            "Entry": 110,
        }
        for column in columns:
            self.tree.heading(
                column,
                text=column,
                command=lambda selected=column: self._change_sort(selected),
            )
            self.tree.column(column, width=widths[column], minwidth=50, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ctk.CTkScrollbar(table_frame, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(6, 0))
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self._show_selected_details)
        self.tree.bind("<Double-1>", lambda _event: self._highlight_selected_entry())
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.context_menu = tk.Menu(self, tearoff=False)
        self.context_menu.add_command(
            label="Highlight vault entry", command=self._highlight_selected_entry
        )
        self.context_menu.add_command(
            label="Verify this record", command=self._verify_selected
        )
        self.context_menu.add_command(
            label="Show investigation details", command=self._show_investigation
        )

    def _create_details_panel(self, parent) -> None:
        frame = ctk.CTkFrame(
            parent,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
        )
        frame.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            frame,
            text="Entry Details",
            font=ctk.CTkFont(size=17, weight="bold"),
        ).grid(row=0, column=0, padx=14, pady=(14, 6), sticky="w")
        self.entry_status = ctk.CTkLabel(
            frame,
            text="Select an event",
            text_color="gray70",
            anchor="w",
        )
        self.entry_status.grid(row=1, column=0, padx=14, pady=(0, 6), sticky="ew")
        self.details_box = ctk.CTkTextbox(frame, wrap="word", font=("Consolas", 12))
        self.details_box.grid(row=2, column=0, sticky="nsew", padx=14, pady=6)
        self.details_box.configure(state="disabled")
        self.chain_label = ctk.CTkLabel(
            frame,
            text="Hash chain not selected",
            justify="left",
            anchor="w",
            wraplength=380,
            text_color="gray70",
        )
        self.chain_label.grid(row=3, column=0, sticky="ew", padx=14, pady=(6, 14))

    def _create_dashboard(self, parent) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)
        controls = ctk.CTkFrame(parent, fg_color="transparent")
        controls.grid(row=0, column=0, sticky="ew", padx=14, pady=12)
        self.stats_range = ctk.CTkComboBox(
            controls,
            width=140,
            values=["7 days", "30 days", "90 days"],
            command=lambda _value: self._load_dashboard(),
        )
        self.stats_range.pack(side="left")
        self.stats_range.set("30 days")
        self.metrics_label = ctk.CTkLabel(
            parent,
            text="",
            font=ctk.CTkFont(size=15),
            anchor="w",
            justify="left",
        )
        self.metrics_label.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 10))
        self.chart = tk.Canvas(
            parent,
            bg="#242424",
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        self.chart.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.chart.bind("<Configure>", lambda _event: self._load_dashboard())

    def _create_footer(self) -> None:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=3, column=0, sticky="ew", padx=22, pady=(0, 14))
        frame.grid_columnconfigure(0, weight=1)
        self.status_label = ctk.CTkLabel(frame, text="Ready", anchor="w")
        self.status_label.grid(row=0, column=0, sticky="w")
        self.previous_button = ctk.CTkButton(
            frame,
            text="Previous",
            width=90,
            command=self._previous_page,
            fg_color=PINK,
            hover_color=PINK_HOVER,
        )
        self.previous_button.grid(row=0, column=1, padx=5)
        self.page_label = ctk.CTkLabel(frame, text="Page 1 of 1", width=110)
        self.page_label.grid(row=0, column=2, padx=5)
        self.next_button = ctk.CTkButton(
            frame,
            text="Next",
            width=90,
            command=self._next_page,
            fg_color=PINK,
            hover_color=PINK_HOVER,
        )
        self.next_button.grid(row=0, column=3, padx=5)

    def _load_logs(self) -> None:
        try:
            result = self.audit_logger.query_entries(self._build_query())
        except Exception as exc:  # noqa: BLE001 - GUI reports repository failures
            self.status_label.configure(text=f"Failed to load audit log: {exc}")
            return
        self.tree.delete(*self.tree.get_children())
        self.current_entries.clear()
        for entry in result["entries"]:
            sequence = str(entry["sequence_number"])
            self.current_entries[sequence] = entry
            self.tree.insert(
                "",
                "end",
                iid=sequence,
                values=(
                    sequence,
                    str(entry.get("timestamp", ""))[:19].replace("T", " "),
                    entry.get("event_type", ""),
                    entry.get("severity", ""),
                    entry.get("user_id", ""),
                    entry.get("source", ""),
                    entry.get("entry_id") or "-",
                ),
            )
        self.current_pages = int(result["pages"])
        self.page_label.configure(
            text=f"Page {self.current_page} of {self.current_pages}"
        )
        self.previous_button.configure(
            state="normal" if self.current_page > 1 else "disabled"
        )
        self.next_button.configure(
            state="normal" if self.current_page < self.current_pages else "disabled"
        )
        self.status_label.configure(
            text=f"Showing {len(result['entries'])} of {result['total']} protected events"
        )
        event_types = self.audit_logger.db.execute(
            "SELECT DISTINCT event_type FROM audit_log ORDER BY event_type;"
        ).fetchall()
        values = ["All events", *[str(row[0]) for row in event_types]]
        self.event_filter.configure(values=values)
        self._update_integrity_label()
        self._load_dashboard()

    def _build_query(self) -> AuditQuery:
        days = {
            "Last 7 days": 7,
            "Last 30 days": 30,
            "Last 90 days": 90,
        }.get(self.date_filter.get())
        date_from = ""
        if days is not None:
            date_from = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        return AuditQuery(
            event_type=(
                ""
                if self.event_filter.get() == "All events"
                else self.event_filter.get()
            ),
            severity=(
                ""
                if self.severity_filter.get() == "All severities"
                else self.severity_filter.get()
            ),
            user_id=self.user_filter.get().strip(),
            date_from=date_from,
            search_text=self.search_entry.get().strip(),
            page=self.current_page,
            page_size=self.audit_logger.config.page_size,
            sort_by=self.sort_by,
            descending=self.sort_descending,
        )

    def _show_selected_details(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        entry = self.current_entries[selected[0]]
        visible = {
            key: value for key, value in entry.items() if key not in {"signature"}
        }
        visible["signature"] = str(entry.get("signature", ""))[:48] + "..."
        self.details_box.configure(state="normal")
        self.details_box.delete("1.0", "end")
        self.details_box.insert(
            "1.0", json.dumps(visible, ensure_ascii=False, indent=2, sort_keys=True)
        )
        self.details_box.configure(state="disabled")
        self.entry_status.configure(text="Signature not checked", text_color="#fbbf24")
        previous_hash = str(entry.get("previous_hash", ""))
        entry_hash = str(entry.get("entry_hash", ""))
        self.chain_label.configure(
            text=(
                f"Previous {previous_hash[:18]}...\n"
                f"Current  {entry_hash[:18]}...\n"
                f"Key      {str(entry.get('key_id', ''))[:18]}..."
            )
        )

    def _verify_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        sequence = int(selected[0])
        report = AuditLogVerifier(
            self.audit_logger.db, self.audit_logger.key_manager
        ).verify(start_sequence=sequence, end_sequence=sequence)
        valid = report.verified
        self.entry_status.configure(
            text="Signature and chain link valid" if valid else "Verification failed",
            text_color="#4ade80" if valid else "#f87171",
        )

    def _verify_full(self) -> None:
        try:
            self.last_report = self.audit_logger.verify_integrity(full=True)
        except Exception as exc:  # noqa: BLE001 - GUI reports verification failures
            self.status_label.configure(text=f"Verification failed to run: {exc}")
            return
        report = self.last_report
        self._update_integrity_label()
        self.status_label.configure(
            text=(
                f"Verified {report.valid_entries}/{report.total_entries} entries "
                f"in {report.duration_seconds:.3f} seconds"
            )
        )
        self._load_logs()

    def _export(self) -> None:
        if not self.confirm_master_password():
            self.status_label.configure(text="Export cancelled: authentication failed")
            return
        export_format = self._choose_export_format()
        if export_format is None:
            return
        extensions = {
            "json": ("Signed JSON", "*.json"),
            "csv": ("CSV", "*.csv"),
            "pdf": ("PDF", "*.pdf"),
        }
        encrypted = self.audit_logger.config.encrypt_exports
        default_extension = (
            f".{export_format}.enc" if encrypted else f".{export_format}"
        )
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export protected audit log",
            defaultextension=default_extension,
            filetypes=[extensions[export_format], ("All files", "*.*")],
        )
        if not path:
            return
        try:
            self.exporter.export(
                Path(path),
                export_format,
                query=self._build_query(),
                master_password_confirmed=True,
            )
        except Exception as exc:  # noqa: BLE001 - GUI reports export failures
            self.status_label.configure(text=f"Export failed: {exc}")
            return
        self.status_label.configure(text=f"Exported to {path}")
        self._load_logs()

    def _choose_export_format(self) -> str | None:
        dialog = ctk.CTkInputDialog(
            text="Enter export format: json, csv, or pdf",
            title="Audit Export",
        )
        value = dialog.get_input()
        if value is None:
            return None
        value = value.strip().casefold()
        if value not in {"json", "csv", "pdf"}:
            self.status_label.configure(text="Export format must be json, csv, or pdf")
            return None
        return value

    def _load_dashboard(self) -> None:
        try:
            days = int(self.stats_range.get().split()[0])
            stats = self.audit_logger.get_statistics(days)
        except (ValueError, RuntimeError, PermissionError):
            return
        self.metrics_label.configure(
            text=(
                f"Entries: {stats['total_entries']}     "
                f"Failed logins: {stats['failed_logins']}     "
                f"Critical events: {stats['critical_events']}     "
                f"Integrity: {stats['integrity_status']}"
            )
        )
        self._draw_frequency_chart(stats["daily_frequency"])

    def _draw_frequency_chart(self, points: list[dict]) -> None:
        self.chart.delete("all")
        width = max(self.chart.winfo_width(), 500)
        height = max(self.chart.winfo_height(), 280)
        margin = 42
        self.chart.create_text(
            margin,
            20,
            text="Event frequency",
            fill="white",
            anchor="w",
            font=("Segoe UI", 13, "bold"),
        )
        if not points:
            self.chart.create_text(
                width / 2,
                height / 2,
                text="No events in this period",
                fill="#a3a3a3",
            )
            return
        maximum = max(int(point["count"]) for point in points) or 1
        available = width - margin * 2
        bar_width = max(3, min(24, available / max(len(points), 1) - 2))
        step = available / max(len(points), 1)
        for index, point in enumerate(points):
            value = int(point["count"])
            bar_height = (height - 90) * value / maximum
            x0 = margin + index * step + (step - bar_width) / 2
            y0 = height - 42 - bar_height
            self.chart.create_rectangle(
                x0,
                y0,
                x0 + bar_width,
                height - 42,
                fill=PINK,
                outline="",
            )
            if len(points) <= 14 or index % max(1, len(points) // 10) == 0:
                self.chart.create_text(
                    x0 + bar_width / 2,
                    height - 28,
                    text=str(point["day"])[5:],
                    fill="#d4d4d4",
                    angle=45,
                    font=("Segoe UI", 8),
                )

    def _show_context_menu(self, event) -> None:
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        self.tree.focus(row)
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def _highlight_selected_entry(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        entry_id = self.current_entries[selected[0]].get("entry_id")
        if entry_id and self.on_entry_selected is not None:
            self.on_entry_selected(str(entry_id))
            self.status_label.configure(text=f"Vault entry highlighted: {entry_id}")
        else:
            self.status_label.configure(
                text="This event is not linked to a vault entry"
            )

    def _show_investigation(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        entry = self.current_entries[selected[0]]
        details = entry.get("details", {})
        self.details_box.configure(state="normal")
        self.details_box.delete("1.0", "end")
        self.details_box.insert(
            "1.0",
            "Investigation view\n\n"
            + f"Time: {entry.get('timestamp')}\n"
            + f"Source: {entry.get('source')}\n"
            + f"Event: {entry.get('event_type')}\n"
            + f"Severity: {entry.get('severity')}\n\n"
            + json.dumps(details, ensure_ascii=False, indent=2, sort_keys=True),
        )
        self.details_box.configure(state="disabled")

    def _change_sort(self, column: str) -> None:
        selected = self.COLUMN_MAP[column]
        if self.sort_by == selected:
            self.sort_descending = not self.sort_descending
        else:
            self.sort_by = selected
            self.sort_descending = False
        self._reset_and_load()

    def _previous_page(self) -> None:
        if self.current_page > 1:
            self.current_page -= 1
            self._load_logs()

    def _next_page(self) -> None:
        if self.current_page < self.current_pages:
            self.current_page += 1
            self._load_logs()

    def _reset_and_load(self) -> None:
        self.current_page = 1
        self._load_logs()

    def _update_integrity_label(self) -> None:
        row = self.audit_logger.db.execute(
            "SELECT integrity_status FROM audit_state WHERE state_id = 1;"
        ).fetchone()
        status = "UNKNOWN" if row is None else str(row[0])
        colors_by_status = {
            "VALID": "#4ade80",
            "TAMPERED": "#f87171",
            "UNKNOWN": "#fbbf24",
        }
        self.integrity_label.configure(
            text=f"Integrity {status.lower()}",
            text_color=colors_by_status.get(status, "#fbbf24"),
        )

    def _bind_shortcuts(self) -> None:
        self.bind("<Control-f>", lambda _event: self.search_entry.focus_set())
        self.bind("<F5>", lambda _event: self._load_logs())
        self.bind("<Escape>", lambda _event: self.destroy())

    def _center_window(self) -> None:
        self.update_idletasks()
        width = 1280
        height = 760
        x = self.parent.winfo_x() + (self.parent.winfo_width() - width) // 2
        y = self.parent.winfo_y() + (self.parent.winfo_height() - height) // 2
        self.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

    @staticmethod
    def _configure_tree_style() -> None:
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background="#272727",
            foreground="white",
            fieldbackground="#272727",
            rowheight=31,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.map(
            "Treeview",
            background=[("selected", PINK)],
            foreground=[("selected", "white")],
        )
        style.configure(
            "Treeview.Heading",
            background="#3a3a3a",
            foreground="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
        )
