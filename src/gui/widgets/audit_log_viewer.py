import sys
import ctypes
import customtkinter as ctk

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"

WINDOW_BG = "#1f1f1f"
HEADER_BG = "#242424"
CARD_BG = "#2b2b2b"
BORDER = "#3a3a3a"

def enable_dark_title_bar(window) -> None:
    if sys.platform != "win32":
        return

    try:
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())

        value = ctypes.c_int(1)

        # Windows 11 / recent Windows 10
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd,
            20,
            ctypes.byref(value),
            ctypes.sizeof(value)
        )

        # Older Windows 10 fallback
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd,
            19,
            ctypes.byref(value),
            ctypes.sizeof(value)
        )

    except Exception:
        pass

class AuditLogViewer(ctk.CTkToplevel):
    def __init__(self, parent, audit_repo=None):
        super().__init__(parent)

        self.parent = parent
        self.audit_repo = audit_repo

        self.title("Audit Log")
        self.geometry("950x560")
        self.minsize(800, 450)
        self.configure(fg_color=WINDOW_BG)

        self.transient(parent)
        self.grab_set()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._create_header()
        self._create_logs_area()
        self._create_footer()

        self._center_window()
        self._load_logs()

        self.lift()
        self.focus_force()

        # Делаем системную шапку окна тёмной, но сохраняем скруглённые края Windows
        self.after(50, lambda: enable_dark_title_bar(self))

    def _create_header(self):
        self.header = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=HEADER_BG
        )
        self.header.grid(row=0, column=0, sticky="ew")
        self.header.grid_columnconfigure(0, weight=1)

        self.title_label = ctk.CTkLabel(
            self.header,
            text="Audit Log Viewer",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#f2f2f2"
        )
        self.title_label.grid(row=0, column=0, padx=24, pady=22, sticky="w")

        self.close_button = ctk.CTkButton(
            self.header,
            text="Close",
            width=130,
            height=38,
            command=self.destroy,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.close_button.grid(row=0, column=1, padx=(0, 12), pady=22)

        self.refresh_button = ctk.CTkButton(
            self.header,
            text="Refresh",
            width=130,
            height=38,
            command=self._load_logs,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.refresh_button.grid(row=0, column=2, padx=(0, 24), pady=22)

    def _create_logs_area(self):
        self.content_frame = ctk.CTkFrame(
            self,
            corner_radius=20,
            fg_color=CARD_BG,
            border_width=1,
            border_color=BORDER
        )
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=24, pady=20)

        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        self.body = ctk.CTkScrollableFrame(
            self.content_frame,
            corner_radius=14,
            fg_color="#292929",
            scrollbar_button_color="#6b6b6b",
            scrollbar_button_hover_color="#7a7a7a"
        )
        self.body.grid(row=0, column=0, sticky="nsew", padx=14, pady=14)

    def _create_footer(self):
        self.footer = ctk.CTkFrame(
            self,
            corner_radius=14,
            fg_color=HEADER_BG,
            border_width=1,
            border_color=BORDER
        )
        self.footer.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 16))

        self.status_label = ctk.CTkLabel(
            self.footer,
            text="Ready",
            anchor="w",
            font=ctk.CTkFont(size=13),
            text_color="#e8e8e8"
        )
        self.status_label.pack(fill="x", padx=14, pady=8)

    def _center_window(self):
        self.update_idletasks()

        width = 950
        height = 560

        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (width // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (height // 2)

        self.geometry(f"{width}x{height}+{x}+{y}")

    def _clear_body(self):
        for widget in self.body.winfo_children():
            widget.destroy()

    def _load_logs(self):
        self._clear_body()

        if self.audit_repo is None:
            self._show_empty_message("Audit repository is not connected.")
            self.status_label.configure(text="Audit repository is not connected.")
            return

        try:
            rows = self.audit_repo.get_logs()
        except Exception as error:
            self._show_empty_message(f"Failed to load audit logs: {error}")
            self.status_label.configure(text="Failed to load audit logs.")
            return

        if not rows:
            self._show_empty_message("Audit log is empty.")
            self.status_label.configure(text="Audit log is empty.")
            return

        self._create_table_header()

        for row in rows:
            self._create_log_row(row)

        self.status_label.configure(text=f"Loaded {len(rows)} audit log records.")

    def _show_empty_message(self, text: str):
        label = ctk.CTkLabel(
            self.body,
            text=text,
            text_color="gray",
            font=ctk.CTkFont(size=14)
        )
        label.pack(anchor="w", padx=12, pady=12)

    def _create_table_header(self):
        header = ctk.CTkFrame(self.body, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=(6, 8))

        columns = [
            ("ID", 60),
            ("Action", 150),
            ("Timestamp", 260),
            ("Entry ID", 90),
            ("Details", 360),
        ]

        for text, width in columns:
            label = ctk.CTkLabel(
                header,
                text=text,
                width=width,
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold")
            )
            label.pack(side="left", padx=4)

    def _create_log_row(self, row):
        log_id, action, timestamp, entry_id, details = row

        line = ctk.CTkFrame(self.body, fg_color="transparent")
        line.pack(fill="x", padx=10, pady=3)

        values = [
            (str(log_id), 60),
            (str(action), 150),
            (str(timestamp), 260),
            (str(entry_id) if entry_id is not None else "-", 90),
            (str(details) if details else "-", 360),
        ]

        for value, width in values:
            label = ctk.CTkLabel(
                line,
                text=value,
                width=width,
                anchor="w",
                font=ctk.CTkFont(size=13)
            )
            label.pack(side="left", padx=4)