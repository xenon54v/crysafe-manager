from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox
from src.core.config import ConfigManager
from src.core.crypto.key_derivation import validate_password, get_password_rule_status
import customtkinter as ctk

from src.gui.widgets.password_entry import PasswordEntry


PINK = "#d98ca3"
PINK_HOVER = "#c97c93"


@dataclass(frozen=True)
class SetupResult:
    master_password: str
    db_path: Path
    enc_scheme: str

@dataclass(frozen=True)
class LoginResult:
    master_password: str

class SetupWizard(ctk.CTkToplevel):
    def __init__(self, master=None):
        super().__init__(master)

        self.title("First-run Setup")
        self.geometry("620x760")
        self.resizable(False, False)

        self._step = 1
        self._result = None

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.content = ctk.CTkFrame(self)
        self.content.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

        self.nav = ctk.CTkFrame(self, fg_color="transparent")
        self.nav.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        self.nav.grid_columnconfigure(1, weight=1)

        self.back_button = ctk.CTkButton(
            self.nav,
            text="Back",
            width=100,
            command=self._back,
            state="disabled",
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.back_button.grid(row=0, column=0, padx=(0, 10))

        self.cancel_button = ctk.CTkButton(
            self.nav,
            text="Cancel",
            width=100,
            command=self._cancel,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.cancel_button.grid(row=0, column=2, padx=(0, 10))

        self.next_button = ctk.CTkButton(
            self.nav,
            text="Next",
            width=100,
            command=self._next,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.next_button.grid(row=0, column=3)

        self._render_step()

        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    @property
    def result(self):
        return self._result

    def _clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def _render_step(self):
        self._clear_content()

        if self._step == 1:
            self._render_password_step()
        elif self._step == 2:
            self._render_db_step()
        elif self._step == 3:
            self._render_enc_step()

        self.back_button.configure(state="normal" if self._step > 1 else "disabled")
        self.next_button.configure(text="Finish" if self._step == 3 else "Next")

    def _render_password_step(self):
        ctk.CTkLabel(
            self.content,
            text="Создание мастер-пароля",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(10, 14))

        ctk.CTkLabel(self.content, text="Мастер-пароль").pack(anchor="w", pady=(0, 5))
        self.pw1 = PasswordEntry(self.content)
        self.pw1.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(
            self.content,
            text="Требования к паролю:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(6, 6))

        self.rules_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        self.rules_frame.pack(fill="x", pady=(0, 14))

        self.rule_labels = {}
        for rule_text in get_password_rule_status("").keys():
            label = ctk.CTkLabel(
                self.rules_frame,
                text=f"- {rule_text}",
                text_color="#d96c6c",
                anchor="w",
                font=ctk.CTkFont(size=13)
            )
            label.pack(anchor="w", pady=1)
            self.rule_labels[rule_text] = label

        ctk.CTkLabel(self.content, text="Подтверждение пароля").pack(anchor="w", pady=(0, 5))
        self.pw2 = PasswordEntry(self.content)
        self.pw2.pack(fill="x")

        self._bind_password_tracking()
        self._update_password_rules()

        self.pw1.focus()


    def _bind_password_tracking(self):
        self.pw1.entry.bind("<KeyRelease>", lambda event: self._update_password_rules())

    def _update_password_rules(self):
        password = self.pw1.get()
        rules = get_password_rule_status(password)

        for rule_text, ok in rules.items():
            label = self.rule_labels[rule_text]
            if ok:
                label.configure(text=f"+ {rule_text}", text_color="#7ccf91")
            else:
                label.configure(text=f"- {rule_text}", text_color="#d96c6c")

    def _render_db_step(self):
        ctk.CTkLabel(
            self.content,
            text="Select Database Location",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(10, 20))

        default_db_path = ConfigManager().load().db_path
        self.db_var = ctk.StringVar(value=str(default_db_path))

        ctk.CTkLabel(self.content, text="Database file path").pack(anchor="w", pady=(0, 5))

        row = ctk.CTkFrame(self.content, fg_color="transparent")
        row.pack(fill="x")

        entry = ctk.CTkEntry(row, textvariable=self.db_var)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        browse_btn = ctk.CTkButton(
            row,
            text="Browse...",
            width=110,
            command=self._browse_db,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        browse_btn.pack(side="right")

    def _render_enc_step(self):
        ctk.CTkLabel(
            self.content,
            text="Encryption Settings",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(10, 20))

        ctk.CTkLabel(self.content, text="Encryption scheme").pack(anchor="w", pady=(0, 5))
        self.enc_var = ctk.StringVar(value="XOR_PLACEHOLDER")
        self.enc_menu = ctk.CTkOptionMenu(
            self.content,
            values=["XOR_PLACEHOLDER"],
            variable=self.enc_var,
            fg_color=PINK,
            button_color=PINK,
            button_hover_color=PINK_HOVER,
            text_color="white"
        )
        self.enc_menu.pack(anchor="w")

        ctk.CTkLabel(
            self.content,
            text="Sprint 1 placeholder. AES-GCM will be added later.",
            text_color="gray"
        ).pack(anchor="w", pady=(20, 0))

    def _next(self):
        if self._step == 1 and not self._validate_password_step():
            return
        if self._step == 2 and not self._validate_db_step():
            return
        if self._step == 3:
            self._finish()
            return

        self._step += 1
        self._render_step()

    def _back(self):
        if self._step > 1:
            self._step -= 1
            self._render_step()

    def _cancel(self):
        self._result = None
        self.destroy()

    def _validate_password_step(self):
        p1 = self.pw1.get()
        p2 = self.pw2.get()

        if p1 != p2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return False

        result = validate_password(p1)
        if not result.ok:
            messagebox.showerror("Error", result.message)
            return False

        return True

    def _validate_db_step(self):
        if not self.db_var.get().strip():
            messagebox.showerror("Ошибка", "Выберите путь к БД.")
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

    def _finish(self):
        self._result = SetupResult(
            master_password=self.pw1.get(),
            db_path=Path(self.db_var.get().strip()),
            enc_scheme=self.enc_var.get()
        )
        self.destroy()

class LoginDialog(ctk.CTkToplevel):
    def __init__(self, master=None):
        super().__init__(master)

        self.title("Login")
        self.geometry("420x260")
        self.resizable(False, False)

        self._result = None

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        frame = ctk.CTkFrame(self)
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

        ctk.CTkLabel(
            frame,
            text="Вход в CryptoSafe Manager",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(10, 18))

        ctk.CTkLabel(frame, text="Введите мастер-пароль").pack(anchor="w", pady=(0, 5))

        self.password_entry = PasswordEntry(frame)
        self.password_entry.pack(fill="x", pady=(0, 18))

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", pady=(10, 0))

        self.cancel_button = ctk.CTkButton(
            buttons,
            text="Cancel",
            width=100,
            command=self._cancel,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.cancel_button.pack(side="right", padx=(10, 0))

        self.login_button = ctk.CTkButton(
            buttons,
            text="Login",
            width=100,
            command=self._login,
            fg_color=PINK,
            hover_color=PINK_HOVER,
            text_color="white"
        )
        self.login_button.pack(side="right")

        self.password_entry.entry.bind("<Return>", lambda event: self._login())

        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        self.password_entry.focus()

    @property
    def result(self):
        return self._result

    def _login(self):
        password = self.password_entry.get()

        if not password:
            messagebox.showerror("Ошибка", "Введите мастер-пароль.")
            return

        self._result = LoginResult(master_password=password)
        self.destroy()

    def _cancel(self):
        self._result = None
        self.destroy()