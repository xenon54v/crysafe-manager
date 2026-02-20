from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Optional

from .models import CREATE_TABLES_SQL, CREATE_INDEXES_SQL, SCHEMA_VERSION


class Database:
    """
    Thread-safe SQLite helper (DB-3).
    Supports:
      - schema initialization
      - migration-ready structure via PRAGMA user_version
      - basic connection management
      - future backup/restore stubs (DB-4)
    """

    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._connection: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._connection = sqlite3.connect(
            self._db_path,
            check_same_thread=False
        )
        self._connection.execute("PRAGMA foreign_keys = ON;")

        self._initialize_schema()

    def _initialize_schema(self) -> None:
        current_version = self._get_user_version()

        if current_version == 0:
            with self._connection:
                for stmt in CREATE_TABLES_SQL:
                    self._connection.execute(stmt)

                for stmt in CREATE_INDEXES_SQL:
                    self._connection.execute(stmt)

                self._set_user_version(SCHEMA_VERSION)

    def _get_user_version(self) -> int:
        cursor = self._connection.execute("PRAGMA user_version;")
        return cursor.fetchone()[0]

    def _set_user_version(self, version: int) -> None:
        self._connection.execute(f"PRAGMA user_version = {version};")

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cursor = self._connection.execute(query, params)
            self._connection.commit()
            return cursor

    def close(self) -> None:
        if self._connection:
            self._connection.close()

    # -------- Sprint 8 stub --------

    def backup(self) -> None:
        raise NotImplementedError("Backup will be implemented in Sprint 8")

    def restore(self) -> None:
        raise NotImplementedError("Restore will be implemented in Sprint 8")
