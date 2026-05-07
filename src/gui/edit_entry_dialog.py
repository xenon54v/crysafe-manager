import customtkinter as ctk

PINK = "#d98ca3"
PINK_HOVER = "#c97c93"

class EditEntryDialog(ctk.CTkToplevel):
    def __init__(self, master=None, entry=None):
        super().__init__(master)

        self.result = None
        self.entry = entry

        self.title("Edit Entry")
        self.geometry("420x520")
        self.resizable(False, False)

        self.transient(master)
        self.grab_set()

        self._create_widgets()
        self._fill_fields()

    def _create_widgets(self):
        self.title_label = ctk.CTkLabel(
            self,
            text="Edit password entry",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.title_label.pack(pady=(20, 10))

        self.title_entry = ctk.CTkEntry(self, placeholder_text="Title")
        self.title_entry.pack(fill="x", padx=30, pady=8)

        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username")
        self.username_entry.pack(fill="x", padx=30, pady=8)

        self.password_entry = ctk.CTkEntry(
            self,
            placeholder_text="New password",
            show="*"
        )
        self.password_entry.pack(fill="x", padx=30, pady=8)

        self.url_entry = ctk.CTkEntry(self, placeholder_text="URL")
        self.url_entry.pack(fill="x", padx=30, pady=8)

        self.notes_entry = ctk.CTkEntry(self, placeholder_text="Notes")
        self.notes_entry.pack(fill="x", padx=30, pady=8)

        self.tags_entry = ctk.CTkEntry(self, placeholder_text="Tags")
        self.tags_entry.pack(fill="x", padx=30, pady=8)

        self.save_button = ctk.CTkButton(
            self,
            text="Save changes",
            command=self._save,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.save_button.pack(fill="x", padx=30, pady=(20, 8))

        self.cancel_button = ctk.CTkButton(
            self,
            text="Cancel",
            command=self.destroy,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.cancel_button.pack(fill="x", padx=30, pady=8)

    def _fill_fields(self):
        if self.entry is None:
            return

        self.title_entry.insert(0, self.entry[1])
        self.username_entry.insert(0, self.entry[2])
        self.url_entry.insert(0, self.entry[4])
        self.notes_entry.insert(0, self.entry[5])
        self.tags_entry.insert(0, self.entry[6])

    def _save(self):
        self.result = {
            "title": self.title_entry.get(),
            "username": self.username_entry.get(),
            "password": self.password_entry.get(),
            "url": self.url_entry.get(),
            "notes": self.notes_entry.get(),
            "tags": self.tags_entry.get(),
        }

        self.destroy()