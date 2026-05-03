from pathlib import Path
import tkinter as tk

from src.database.db import Database
from src.gui.main_window import MainWindow


def main() -> None:
    db_path = Path("data/cryptosafe_dev.db")

    db = Database(db_path)
    db.connect()

    root = tk.Tk()
    app = MainWindow(root, db)
    root.mainloop()

    db.close()


if __name__ == "__main__":
    main()