from pathlib import Path

from src.database.db import Database
from src.gui.main_window import MainWindow

def main() -> None:
    db_path = Path("data/cryptosafe_dev.db")

    db = Database(db_path)
    db.connect()

    app = MainWindow()
    app.mainloop()

    db.close()

if __name__ == "__main__":
    main()