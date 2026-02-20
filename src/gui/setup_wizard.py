import tkinter as tk
from tkinter import filedialog, messagebox
from dataclasses import dataclass
from pathlib import Path

from src.gui.widgets.password_entry import PasswordEntry


@dataclass(frozen=True)
class SetupResult:
    master_password: str
    db_path: Path
    enc_scheme: str


class SetupWizard(tk.Toplevel):
    """
    First-run setup wizard (GUI-3).
    Step 1: master password creation + confirmation
    Step 2: database location selection
    Step 3: encryption settings placeholder
    """

    def __init__(self, master=None):
        super().__init__(master)
        self.title("First-run Setup (Sprint 1)")
        self.geometry("500x260")
        self.resizable(False, False)

        self._step = 1
        self._result = None

        self._content = tk.Frame(self)
        self._content.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        self._nav = tk.Frame(self)
        self._nav.pack(fill=tk.X, padx=12, pady=(0, 12))

        self.btn_back = tk.Button(self._nav, text="Back", width=10, command=self._back, state=tk.DISABLED)
        self.btn_back.pack(side=tk.LEFT)

        self.btn_next = tk.Button(self._nav, text="Next", width=10, command=self._next)
        self.btn_next.pack(side=tk.RIGHT)

        self.btn_cancel = tk.Button(self._nav, text="Cancel", width=10, command=self._cancel)
        self.btn_cancel.pack(side=tk.RIGHT, padx=(0, 8))

        self._render_step()

        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    @property
    def result(self):
        return self._result

    # ---------------- Steps ----------------

    def _render_step(self):
        for w in self._content.winfo_children():
            w.destroy()

        if self._step == 1:
            self._render_password_step()
        elif self._step == 2:
            self._render_db_step()
        elif self._step == 3:
            self._render_enc_step()

        self.btn_back.config(state=(tk.NORMAL if self._step > 1 else tk.DISABLED))
        self.btn_next.config(text=("Finish" if self._step == 3 else "Next"))

    def _render_password_step(self):
        tk.Label(self._content, text="Create Master Password", font=("Segoe UI", 12, "bold")).pack(anchor="w")

        tk.Label(self._content, text="Master password:").pack(anchor="w", pady=(12, 0))
        self.pw1 = PasswordEntry(self._content)
        self.pw1.pack(fill=tk.X)

        tk.Label(self._content, text="Confirm password:").pack(anchor="w", pady=(10, 0))
        self.pw2 = PasswordEntry(self._content)
        self.pw2.pack(fill=tk.X)

        self.pw1.focus()

    def _render_db_step(self):
        tk.Label(self._content, text="Select Database Location", font=("Segoe UI", 12, "bold")).pack(anchor="w")

        tk.Label(self._content, text="Database file path:").pack(anchor="w", pady=(12, 0))
        self.db_var = tk.StringVar(value=str(Path("data") / "cryptosafe_dev.db"))

        row = tk.Frame(self._content)
        row.pack(fill=tk.X, pady=(6, 0))

        tk.Entry(row, textvariable=self.db_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(row, text="Browse...", command=self._browse_db).pack(side=tk.RIGHT, padx=(8, 0))

        tk.Label(self._content, text="(Sprint 1: DB will be created automatically later.)", fg="gray").pack(anchor="w", pady=(10, 0))

    def _render_enc_step(self):
        tk.Label(self._content, text="Encryption Settings (Placeholder)", font=("Segoe UI", 12, "bold")).pack(anchor="w")

        tk.Label(self._content, text="Encryption scheme:").pack(anchor="w", pady=(12, 0))
        self.enc_var = tk.StringVar(value="XOR_PLACEHOLDER")

        options = ["XOR_PLACEHOLDER"]  # Sprint 3 will add AES-GCM etc.
        tk.OptionMenu(self._content, self.enc_var, *options).pack(anchor="w")

        tk.Label(self._content, text="KDF params: (Sprint 2 placeholder)", fg="gray").pack(anchor="w", pady=(12, 0))
        tk.Label(self._content, text="PBKDF2/scrypt/argon2 settings will appear in Sprint 2.", fg="gray").pack(anchor="w")

    def get_partial_state(self) -> dict:
        state = {}

        # step 1 values
        if hasattr(self, "pw1"):
            state["pw_len"] = len(self.pw1.get())

        # step 2 values
        if hasattr(self, "db_var"):
            state["db_path"] = self.db_var.get()

        # step 3 values
        if hasattr(self, "enc_var"):
            state["enc_scheme"] = self.enc_var.get()

        return state

    # ---------------- Navigation ----------------

    def _next(self):
        if self._step == 1:
            if not self._validate_password_step():
                return
        elif self._step == 2:
            if not self._validate_db_step():
                return
        elif self._step == 3:
            if not self._finish():
                return

        if self._step < 3:
            self._step += 1
            self._render_step()

    def _back(self):
        if self._step > 1:
            self._step -= 1
            self._render_step()

    def _cancel(self):
        self._result = None
        self.destroy()

    # ---------------- Validators ----------------

    def _validate_password_step(self) -> bool:
        p1 = self.pw1.get()
        p2 = self.pw2.get()

        if len(p1) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters (Sprint 1 basic rule).")
            return False
        if p1 != p2:
            messagebox.showerror("Error", "Passwords do not match.")
            return False
        return True

    def _validate_db_step(self) -> bool:
        path = self.db_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Please select a database file path.")
            return False
        return True

    def _browse_db(self):
        filename = filedialog.asksaveasfilename(
            title="Choose database file",
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")]
        )
        if filename:
            self.db_var.set(filename)

    def _finish(self) -> bool:
        master_password = self.pw1.get()
        db_path = Path(self.db_var.get().strip())
        enc_scheme = self.enc_var.get()

        self._result = SetupResult(
            master_password=master_password,
            db_path=db_path,
            enc_scheme=enc_scheme
        )
        self.destroy()
        return True
