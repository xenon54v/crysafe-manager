import customtkinter as ctk

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"

class AuditLogViewer(ctk.CTkToplevel):
    def __init__(self, master=None):
        super().__init__(master)

        self.title("Audit Log")
        self.geometry("700x450")

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

        self.close_button = ctk.CTkButton(
            self.header,
            text="Close",
            width=100,
            command=self.destroy,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.close_button.pack(side="right", padx=20, pady=15)

        self.body = ctk.CTkFrame(self, corner_radius=16)
        self.body.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)

        self.info_label = ctk.CTkLabel(
            self.body,
            text="Audit Log Viewer will be implemented in Sprint 5",
            font=ctk.CTkFont(size=16)
        )
        self.info_label.pack(pady=(30, 10))

        self.note_label = ctk.CTkLabel(
            self.body,
            text="This window is currently a styled placeholder.",
            text_color="gray"
        )
        self.note_label.pack()