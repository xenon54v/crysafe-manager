import customtkinter as ctk
from tkinter import messagebox

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"

class ChangePasswordDialog(ctk.CTkToplevel):
    def __init__(self, master=None):
        super().__init__(master)

        self.result = None

        self.title("Change master password")
        self.geometry("420x360")
        self.resizable(False, False)

        self.transient(master)
        self.grab_set()

        self._create_widgets()

    def _create_widgets(self):
        self.title_label = ctk.CTkLabel(
            self,
            text="Change master password",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.title_label.pack(pady=(20, 15))

        self.old_password_entry = ctk.CTkEntry(
            self,
            placeholder_text="Current password",
            show="*"
        )
        self.old_password_entry.pack(fill="x", padx=30, pady=8)

        self.new_password_entry = ctk.CTkEntry(
            self,
            placeholder_text="New password",
            show="*"
        )
        self.new_password_entry.pack(fill="x", padx=30, pady=8)

        self.confirm_password_entry = ctk.CTkEntry(
            self,
            placeholder_text="Confirm new password",
            show="*"
        )
        self.confirm_password_entry.pack(fill="x", padx=30, pady=8)

        self.change_button = ctk.CTkButton(
            self,
            text="Change password",
            command=self._change_password,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.change_button.pack(fill="x", padx=30, pady=(20, 8))

        self.cancel_button = ctk.CTkButton(
            self,
            text="Cancel",
            command=self.destroy,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.cancel_button.pack(fill="x", padx=30, pady=8)

    def _change_password(self):
        old_password = self.old_password_entry.get()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not old_password or not new_password:
            messagebox.showwarning(
                "Change password",
                "Fill all password fields."
            )
            return

        if new_password != confirm_password:
            messagebox.showerror(
                "Change password",
                "New passwords do not match."
            )
            return

        self.result = {
            "old_password": old_password,
            "new_password": new_password,
        }

        self.destroy()