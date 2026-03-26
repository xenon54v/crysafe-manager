import customtkinter as ctk


PINK = "#d98ca3"
PINK_HOVER = "#c97c93"


class PasswordEntry(ctk.CTkFrame):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, fg_color="transparent")

        self.grid_columnconfigure(0, weight=1)

        self._shown = False
        self._var = ctk.StringVar()

        self.entry = ctk.CTkEntry(self, textvariable=self._var, show="*", **kwargs)
        self.entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.button = ctk.CTkButton(
            self,
            text="Show",
            width=70,
            command=self.toggle,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.button.grid(row=0, column=1)

    def toggle(self):
        self._shown = not self._shown
        if self._shown:
            self.entry.configure(show="")
            self.button.configure(text="Hide")
        else:
            self.entry.configure(show="*")
            self.button.configure(text="Show")

    def get(self):
        return self._var.get()

    def set(self, value: str):
        self._var.set(value)

    def focus(self):
        self.entry.focus_set()