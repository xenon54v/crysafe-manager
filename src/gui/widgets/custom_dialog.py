import customtkinter as ctk


class CustomDialog(ctk.CTkToplevel):
    def __init__(
        self,
        parent,
        title: str,
        message: str,
        dialog_type: str = "info",
        ok_text: str = "OK",
        cancel_text: str = "Cancel",
    ):
        super().__init__(parent)

        self.parent = parent
        self.result = None

        self.title(title)
        self.geometry("560x420")
        self.minsize(520, 360)
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._create_header(title, dialog_type)
        self._create_message_area(message)
        self._create_buttons(dialog_type, ok_text, cancel_text)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.bind("<Escape>", lambda event: self._on_close())
        self.bind("<Return>", lambda event: self._on_ok())

        self._center_window()

        self.lift()
        self.focus_force()

    def _create_header(self, title: str, dialog_type: str):
        self.header_frame = ctk.CTkFrame(
            self,
            corner_radius=14
        )
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=22, pady=(22, 12))
        self.header_frame.grid_columnconfigure(1, weight=1)

        icon_text = self._get_icon(dialog_type)

        self.icon_label = ctk.CTkLabel(
            self.header_frame,
            text=icon_text,
            font=ctk.CTkFont(size=30, weight="bold"),
            width=48
        )
        self.icon_label.grid(row=0, column=0, padx=(18, 12), pady=18)

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text=title,
            font=ctk.CTkFont(size=24, weight="bold"),
            anchor="w"
        )
        self.title_label.grid(row=0, column=1, sticky="ew", pady=18)

    def _create_message_area(self, message: str):
        self.message_frame = ctk.CTkScrollableFrame(
            self,
            corner_radius=14
        )
        self.message_frame.grid(row=1, column=0, sticky="nsew", padx=22, pady=(0, 12))
        self.message_frame.grid_columnconfigure(0, weight=1)

        self.message_label = ctk.CTkLabel(
            self.message_frame,
            text=message,
            font=ctk.CTkFont(size=15),
            wraplength=470,
            justify="left",
            anchor="w"
        )
        self.message_label.grid(row=0, column=0, sticky="ew", padx=14, pady=14)

    def _create_buttons(self, dialog_type: str, ok_text: str, cancel_text: str):
        self.buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons_frame.grid(row=2, column=0, pady=(0, 22))

        if dialog_type == "question":
            self.yes_button = ctk.CTkButton(
                self.buttons_frame,
                text="Yes",
                width=130,
                height=38,
                command=self._on_yes
            )
            self.yes_button.pack(side="left", padx=8)

            self.no_button = ctk.CTkButton(
                self.buttons_frame,
                text="No",
                width=130,
                height=38,
                command=self._on_no
            )
            self.no_button.pack(side="left", padx=8)
        else:
            self.ok_button = ctk.CTkButton(
                self.buttons_frame,
                text=ok_text,
                width=160,
                height=38,
                command=self._on_ok
            )
            self.ok_button.pack(padx=8)

    def _get_icon(self, dialog_type: str) -> str:
        if dialog_type == "info":
            return "ⓘ"
        if dialog_type == "warning":
            return "⚠"
        if dialog_type == "error":
            return "✕"
        if dialog_type == "question":
            return "?"
        return "ⓘ"

    def _center_window(self):
        self.update_idletasks()

        width = 560
        height = 420

        parent_x = self.parent.winfo_x()
        parent_y = self.parent.winfo_y()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()

        x = parent_x + (parent_width // 2) - (width // 2)
        y = parent_y + (parent_height // 2) - (height // 2)

        self.geometry(f"{width}x{height}+{x}+{y}")

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