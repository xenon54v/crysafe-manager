"""Source launcher and non-graphical installation check for CryptoSafe Manager."""

from __future__ import annotations

import argparse
import importlib
import sqlite3
import sys
import tempfile
from pathlib import Path

from src import __version__


REQUIRED_MODULES = (
    "argon2",
    "cryptography",
    "customtkinter",
    "keyring",
    "PIL",
    "pyperclip",
    "qrcode",
    "reportlab",
)


def check_installation() -> tuple[bool, list[str]]:
    """Check imports, SQLite access, and the main application module."""

    problems: list[str] = []
    for module_name in REQUIRED_MODULES:
        try:
            importlib.import_module(module_name)
        except ImportError as exc:
            problems.append(f"Dependency {module_name!r} is unavailable: {exc.name}")

    try:
        importlib.import_module("src.main")
    except ImportError as exc:
        problems.append(f"Application import failed: {exc.name}")

    try:
        with tempfile.TemporaryDirectory(prefix="cryptosafe-check-") as directory:
            connection = sqlite3.connect(Path(directory) / "check.db")
            connection.execute("CREATE TABLE health_check (value INTEGER NOT NULL)")
            connection.execute("INSERT INTO health_check VALUES (1)")
            value = connection.execute("SELECT value FROM health_check").fetchone()
            connection.close()
            if value != (1,):
                problems.append("SQLite health check returned an unexpected result.")
    except (OSError, sqlite3.Error) as exc:
        problems.append(f"SQLite health check failed: {type(exc).__name__}")

    return not problems, problems


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser used by source and packaged launchers."""

    parser = argparse.ArgumentParser(prog="cryptosafe-manager")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify dependencies and local SQLite access without opening the GUI",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"CryptoSafe Manager {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run an installation check or launch the desktop application."""

    arguments = build_parser().parse_args(argv)
    if arguments.check:
        healthy, problems = check_installation()
        if healthy:
            print(f"CryptoSafe Manager {__version__}: installation check passed")
            return 0
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1

    from src.main import main as launch

    launch()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
