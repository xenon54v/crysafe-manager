from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Optional

from .models import CREATE_TABLES_SQL, CREATE_INDEXES_SQL, SCHEMA_VERSION

class Database:

    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._connection: Optional[sqlite3.Connection] = None

    @property
    def path(self) -> Path:
        return self._db_path

    def connect(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        # отладочное соединение отключено

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

        elif current_version < SCHEMA_VERSION:
            self._migrate(current_version)

    def _migrate(self, current_version: int) -> None:
        with self._connection:
            if current_version < 2:
                self._connection.execute("""
                    CREATE TABLE IF NOT EXISTS key_store (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key_type TEXT UNIQUE NOT NULL,
                        salt BLOB NOT NULL,
                        hash TEXT NOT NULL,
                        params TEXT
                    );
                """)

                self._connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_key_store_type ON key_store(key_type);"
                )

                self._set_user_version(2)

    def _get_user_version(self) -> int:
        cursor = self._connection.execute("PRAGMA user_version;")
        return cursor.fetchone()[0]

    def _set_user_version(self, version: int) -> None:
        self._connection.execute(f"PRAGMA user_version = {version};")

    def execute(self, query, params=()):
        # debug sql disabled

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
