import customtkinter as ctk


class CustomDialog(ctk.CTkToplevel):
    def __init__(
        self,
        parent,
        title: str,
        message: str,
        dialog_type: str = "info",   # info, warning, error, question
        ok_text: str = "OK",
        cancel_text: str = "Cancel",
    ):
        super().__init__(parent)

        self.result = None
        self.title(title)
        self.geometry("460x240")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()
        self.lift()
        self.attributes("-topmost", True)
        self.after(200, lambda: self.attributes("-topmost", False))

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        if dialog_type == "info":
            icon_text = "ℹ"
        elif dialog_type == "warning":
            icon_text = "⚠"
        elif dialog_type == "error":
            icon_text = "✖"
        elif dialog_type == "question":
            icon_text = "?"
        else:
            icon_text = "ℹ"

        self.header_frame = ctk.CTkFrame(self, corner_radius=12)
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        self.icon_label = ctk.CTkLabel(
            self.header_frame,
            text=icon_text,
            font=ctk.CTkFont(size=28, weight="bold"),
            width=40
        )
        self.icon_label.pack(side="left", padx=(15, 10), pady=12)

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text=title,
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.title_label.pack(side="left", pady=12)

        self.message_label = ctk.CTkLabel(
            self,
            text=message,
            font=ctk.CTkFont(size=16),
            wraplength=380,
            justify="center"
        )
        self.message_label.grid(row=1, column=0, padx=30, pady=(10, 10), sticky="nsew")

        self.buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons_frame.grid(row=2, column=0, pady=(0, 20))

        if dialog_type == "question":
            self.yes_button = ctk.CTkButton(
                self.buttons_frame,
                text="Yes",
                width=120,
                command=self._on_yes
            )
            self.yes_button.pack(side="left", padx=10)

            self.no_button = ctk.CTkButton(
                self.buttons_frame,
                text="No",
                width=120,
                command=self._on_no
            )
            self.no_button.pack(side="left", padx=10)
        else:
            self.ok_button = ctk.CTkButton(
                self.buttons_frame,
                text=ok_text,
                width=140,
                command=self._on_ok
            )
            self.ok_button.pack(padx=10)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.update_idletasks()

        x = parent.winfo_x() + (parent.winfo_width() // 2) - (460 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (240 // 2)
        self.geometry(f"460x240+{x}+{y}")

    def _on_ok(self):
        self.result = True
        self.destroy()

    def _on_yes(self):
        self.result = True
        self.destroy()

    def _on_no(self):
        self.result = False
        self.destroy()

    def _on_close(self):
        self.result = False
        self.destroy()