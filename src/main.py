from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from src import __version__
from src.core.config import ConfigManager, Environment


def main() -> None:
    """Start the desktop application and keep startup errors user friendly."""

    if getattr(sys, "frozen", False):
        os.environ.setdefault("CRYPTOSAFE_ENV", Environment.PRODUCTION.value)

    config = ConfigManager().load()
    _configure_logging(config.db_path.parent)

    try:
        from src.gui.main_window import MainWindow

        app = MainWindow()
        app.mainloop()
    except Exception as exc:  # noqa: BLE001 - final boundary for GUI startup
        logging.getLogger(__name__).exception("Application startup failed")
        _show_startup_error(exc, config.db_path.parent)
        raise SystemExit(1) from None


def _configure_logging(data_directory: Path) -> None:
    data_directory.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=data_directory / "cryptosafe.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _show_startup_error(exc: Exception, data_directory: Path) -> None:
    message = (
        "CryptoSafe Manager could not start. "
        f"Check write access to {data_directory} and review cryptosafe.log. "
        f"Error type: {type(exc).__name__}."
    )
    try:
        from tkinter import messagebox

        messagebox.showerror(f"CryptoSafe Manager {__version__}", message)
    except Exception:  # noqa: BLE001 - stderr is the last available channel
        print(message, file=sys.stderr)


if __name__ == "__main__":
    main()
