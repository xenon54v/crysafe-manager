import customtkinter as ctk

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"


class AuditLogViewer(ctk.CTkToplevel):
    def __init__(self, master=None, audit_repo=None):
        super().__init__(master)

        self.audit_repo = audit_repo

        self.title("Audit Log")
        self.geometry("850x500")

        self.transient(master)

        if master is not None:
            self.grab_set()

        self.lift()
        self.focus_force()
        self.attributes("-topmost", True)
        self.after(200, lambda: self.attributes("-topmost", False))

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.header = ctk.CTkFrame(self, corner_radius=0)
        self.header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)

        self.title_label = ctk.CTkLabel(
            self.header,
            text="Audit Log Viewer",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.title_label.pack(side="left", padx=20, pady=15)

        self.refresh_button = ctk.CTkButton(
            self.header,
            text="Refresh",
            width=100,
            command=self._load_logs,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.refresh_button.pack(side="right", padx=(0, 20), pady=15)

        self.close_button = ctk.CTkButton(
            self.header,
            text="Close",
            width=100,
            command=self.destroy,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.close_button.pack(side="right", padx=10, pady=15)

        self.body = ctk.CTkScrollableFrame(self, corner_radius=16)
        self.body.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)

        self._load_logs()

    def _clear_body(self):
        for widget in self.body.winfo_children():
            widget.destroy()

    def _load_logs(self):
        self._clear_body()

        if self.audit_repo is None:
            ctk.CTkLabel(
                self.body,
                text="Audit repository is not connected.",
                text_color="gray"
            ).pack(anchor="w", padx=10, pady=10)
            return

        rows = self.audit_repo.get_logs()

        if not rows:
            ctk.CTkLabel(
                self.body,
                text="Audit log is empty.",
                text_color="gray"
            ).pack(anchor="w", padx=10, pady=10)
            return

        header = ctk.CTkFrame(self.body, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=(5, 8))

        for text, width in [
            ("ID", 50),
            ("Action", 140),
            ("Timestamp", 220),
            ("Entry ID", 80),
            ("Details", 300),
        ]:
            ctk.CTkLabel(
                header,
                text=text,
                width=width,
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold")
            ).pack(side="left", padx=4)

        for row in rows:
            log_id, action, timestamp, entry_id, details = row

            line = ctk.CTkFrame(self.body, fg_color="transparent")
            line.pack(fill="x", padx=10, pady=3)

            values = [
                (str(log_id), 50),
                (str(action), 140),
                (str(timestamp), 220),
                (str(entry_id) if entry_id is not None else "-", 80),
                (str(details) if details else "-", 300),
            ]

            for value, width in values:
                ctk.CTkLabel(
                    line,
                    text=value,
                    width=width,
                    anchor="w"
                ).pack(side="left", padx=4)