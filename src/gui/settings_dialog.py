import customtkinter as ctk

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"

class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, master=None):
        super().__init__(master)

        self.result = None

        self.title("Settings")
        self.geometry("420x260")
        self.resizable(False, False)

        self.transient(master)
        self.grab_set()

        self._create_widgets()

    def _create_widgets(self):
        title_label = ctk.CTkLabel(
            self,
            text="Settings",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=(25, 20))

        change_password_button = ctk.CTkButton(
            self,
            text="Change master password",
            command=self._choose_change_password,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        change_password_button.pack(fill="x", padx=35, pady=10)

        close_button = ctk.CTkButton(
            self,
            text="Close",
            command=self.destroy,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        close_button.pack(fill="x", padx=35, pady=10)

    def _choose_change_password(self):
        self.result = "change_master_password"
        self.destroy()