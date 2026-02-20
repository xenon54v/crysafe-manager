import tkinter as tk


class PasswordEntry(tk.Frame):
    """
    Masked password input with show/hide toggle.
    """

    def __init__(self, master=None, **kwargs):
        super().__init__(master)

        self._var = tk.StringVar()
        self._shown = False

        self.entry = tk.Entry(self, textvariable=self._var, show="*", **kwargs)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.btn = tk.Button(self, text="Show", width=6, command=self.toggle)
        self.btn.pack(side=tk.RIGHT)

    def toggle(self):
        self._shown = not self._shown
        if self._shown:
            self.entry.config(show="")
            self.btn.config(text="Hide")
        else:
            self.entry.config(show="*")
            self.btn.config(text="Show")

    def get(self) -> str:
        return self._var.get()

    def set(self, value: str) -> None:
        self._var.set(value)

    def focus(self):
        self.entry.focus_set()
