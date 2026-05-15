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
            text_color="white",
        )
        self.button.grid(row=0, column=1)

        self._bind_clipboard_protection()

    def _bind_clipboard_protection(self) -> None:
        sequences = (
            "<Control-c>", "<Control-C>",
            "<Control-x>", "<Control-X>",
            "<Control-v>", "<Control-V>",
            "<Control-Insert>",
            "<Shift-Insert>",
            "<<Copy>>",
            "<<Cut>>",
            "<<Paste>>",
            "<Button-3>",
        )

        for sequence in sequences:
            self.bind(sequence, self._block_clipboard)
            self.entry.bind(sequence, self._block_clipboard)

        self.entry.bind("<FocusIn>", self._enable_global_block)
        self.entry.bind("<FocusOut>", self._disable_global_block)

    def _enable_global_block(self, event=None):
        root = self.winfo_toplevel()

        for sequence in (
            "<Control-c>", "<Control-C>",
            "<Control-x>", "<Control-X>",
            "<Control-v>", "<Control-V>",
            "<<Copy>>",
            "<<Cut>>",
            "<<Paste>>",
        ):
            root.bind_all(sequence, self._block_clipboard)

    def _disable_global_block(self, event=None):
        root = self.winfo_toplevel()

        for sequence in (
            "<Control-c>", "<Control-C>",
            "<Control-x>", "<Control-X>",
            "<Control-v>", "<Control-V>",
            "<<Copy>>",
            "<<Cut>>",
            "<<Paste>>",
        ):
            root.unbind_all(sequence)

    def _block_clipboard(self, event=None):
        try:
            self.clipboard_clear()
        except Exception:
            pass

        return "break"

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