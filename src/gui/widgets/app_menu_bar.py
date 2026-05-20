import tkinter as tk
import customtkinter as ctk


class AppMenuBar(ctk.CTkFrame):
    def __init__(self, parent, actions: dict):
        super().__init__(parent, height=36, corner_radius=0)

        self.parent = parent
        self.actions = actions
        self.dropdown_window = None

        self.grid_columnconfigure(10, weight=1)

        self._create_menu_button(
            text="File",
            column=0,
            items=[
                ("New", self.actions["new"]),
                ("Open", self.actions["open"]),
                ("Backup", self.actions["backup"]),
                ("separator", None),
                ("Logout", self.actions["logout"]),
                ("Exit", self.actions["exit"]),
            ],
            padx=(10, 2),
        )

        self._create_menu_button(
            text="Edit",
            column=1,
            items=[
                ("Add", self.actions["add"]),
                ("Edit", self.actions["edit"]),
                ("Delete", self.actions["delete"]),
            ],
        )

        self._create_menu_button(
            text="View",
            column=2,
            items=[
                ("Logs", self.actions["logs"]),
                ("Settings", self.actions["settings"]),
            ],
        )

        self._create_menu_button(
            text="Help",
            column=3,
            items=[
                ("About", self.actions["about"]),
            ],
        )

    def _create_menu_button(self, text: str, column: int, items: list, padx=2):
        button = ctk.CTkButton(
            self,
            text=text,
            width=70,
            height=28,
            fg_color="transparent",
            hover_color=("gray80", "gray25"),
            text_color=("gray10", "gray90"),
            command=lambda: self._show_dropdown(button, items)
        )
        button.grid(row=0, column=column, padx=padx, pady=4)
        return button

    def _show_dropdown(self, widget, items) -> None:
        self.close_dropdown()

        self.dropdown_window = ctk.CTkToplevel(self.parent)
        self.dropdown_window.overrideredirect(True)
        self.dropdown_window.attributes("-topmost", True)

        frame = ctk.CTkFrame(
            self.dropdown_window,
            corner_radius=10,
            border_width=1
        )
        frame.pack(fill="both", expand=True, padx=2, pady=2)

        row = 0

        for label, command in items:
            if label == "separator":
                separator = ctk.CTkFrame(
                    frame,
                    height=1,
                    fg_color=("gray70", "gray35")
                )
                separator.grid(row=row, column=0, sticky="ew", padx=8, pady=4)
                row += 1
                continue

            item_button = ctk.CTkButton(
                frame,
                text=label,
                width=150,
                height=34,
                anchor="w",
                fg_color="transparent",
                hover_color=("gray80", "gray25"),
                text_color=("gray10", "gray90"),
                command=lambda cmd=command: self._run_command(cmd)
            )
            item_button.grid(row=row, column=0, sticky="ew", padx=6, pady=3)
            row += 1

        x = widget.winfo_rootx()
        y = widget.winfo_rooty() + widget.winfo_height() + 2

        self.dropdown_window.geometry(f"+{x}+{y}")
        self.dropdown_window.focus_force()

        self.dropdown_window.bind("<FocusOut>", lambda event: self.close_dropdown())
        self.dropdown_window.bind("<Escape>", lambda event: self.close_dropdown())

    def _run_command(self, command) -> None:
        self.close_dropdown()

        if command is not None:
            command()

    def close_dropdown(self) -> None:
        if self.dropdown_window is not None:
            try:
                self.dropdown_window.destroy()
            except tk.TclError:
                pass

            self.dropdown_window = None