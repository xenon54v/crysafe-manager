from __future__ import annotations

import queue
import sqlite3
import threading
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from .models import (
    CREATE_INDEXES_SQL,
    CREATE_TABLES_SQL,
    CREATE_TRIGGERS_SQL,
    SCHEMA_VERSION,
)


class QueryResult:
    """Detached cursor result that remains usable after a pooled connection is released."""

    def __init__(
        self,
        rows: Sequence[sqlite3.Row],
        rowcount: int,
        lastrowid: int | None,
    ) -> None:
        self._rows = list(rows)
        self._offset = 0
        self.rowcount = rowcount
        self.lastrowid = lastrowid

    def fetchone(self):
        if self._offset >= len(self._rows):
            return None
        row = self._rows[self._offset]
        self._offset += 1
        return row

    def fetchall(self):
        rows = self._rows[self._offset :]
        self._offset = len(self._rows)
        return rows


class SQLiteConnectionPool:
    def __init__(self, db_path: Path, size: int = 4) -> None:
        if size < 1:
            raise ValueError("Connection pool size must be at least one.")

        self._db_path = db_path
        self._size = 1 if str(db_path) == ":memory:" else size
        self._available: queue.LifoQueue[sqlite3.Connection] = queue.LifoQueue()
        self._connections: list[sqlite3.Connection] = []

        for _ in range(self._size):
            connection = self._create_connection()
            self._connections.append(connection)
            self._available.put(connection)

    @property
    def size(self) -> int:
        return self._size

    @contextmanager
    def acquire(self) -> Iterator[sqlite3.Connection]:
        connection = self._available.get()
        try:
            yield connection
        finally:
            self._available.put(connection)

    def close(self) -> None:
        while not self._available.empty():
            self._available.get_nowait()
        for connection in self._connections:
            connection.close()
        self._connections.clear()

    def _create_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._db_path,
            check_same_thread=False,
            timeout=10.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute("PRAGMA busy_timeout = 5000;")
        if str(self._db_path) != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL;")
            connection.execute("PRAGMA synchronous = NORMAL;")
        return connection


class Database:
    def __init__(self, db_path: Path | str, pool_size: int = 4) -> None:
        self._db_path = Path(db_path)
        self._pool_size = pool_size
        self._pool: SQLiteConnectionPool | None = None
        self._local = threading.local()

    @property
    def path(self) -> Path:
        return self._db_path

    @property
    def connection_pool_size(self) -> int:
        return self._pool.size if self._pool is not None else 0

    def connect(self) -> None:
        if self._pool is not None:
            return

        if str(self._db_path) == ":memory:":
            self._pool = SQLiteConnectionPool(self._db_path, 1)
            with self._pool.acquire() as connection:
                self._initialize_schema(connection)
                self._ensure_default_settings(connection)
            return

        if str(self._db_path) != ":memory:":
            self._db_path.parent.mkdir(parents=True, exist_ok=True)

        bootstrap = sqlite3.connect(self._db_path)
        try:
            bootstrap.execute("PRAGMA foreign_keys = ON;")
            self._initialize_schema(bootstrap)
            self._ensure_default_settings(bootstrap)
            bootstrap.commit()
        finally:
            bootstrap.close()

        self._pool = SQLiteConnectionPool(self._db_path, self._pool_size)

    def execute(self, query: str, params: Sequence = ()) -> QueryResult:
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            return self._execute_on(connection, query, params)

        pool = self._require_pool()
        with pool.acquire() as pooled_connection:
            return self._execute_on(pooled_connection, query, params)

    def executemany(self, query: str, params: Iterable[Sequence]) -> QueryResult:
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            cursor = connection.executemany(query, params)
            return QueryResult((), cursor.rowcount, cursor.lastrowid)

        pool = self._require_pool()
        with pool.acquire() as pooled_connection:
            cursor = pooled_connection.executemany(query, params)
            return QueryResult((), cursor.rowcount, cursor.lastrowid)

    @contextmanager
    def transaction(self, write: bool = True) -> Iterator[Database]:
        existing = getattr(self._local, "connection", None)
        if existing is not None:
            self._local.depth += 1
            try:
                yield self
            finally:
                self._local.depth -= 1
            return

        pool = self._require_pool()
        with pool.acquire() as connection:
            self._local.connection = connection
            self._local.depth = 1
            connection.execute("BEGIN IMMEDIATE;" if write else "BEGIN;")
            try:
                yield self
            except Exception:
                connection.execute("ROLLBACK;")
                raise
            else:
                connection.execute("COMMIT;")
            finally:
                self._local.connection = None
                self._local.depth = 0

    def commit(self) -> None:
        """Compatibility method for older repository code.

        Standalone statements use SQLite autocommit. Explicit transactions are
        committed by the ``transaction`` context manager.
        """

    def rollback(self) -> None:
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            connection.execute("ROLLBACK;")
            self._local.connection = None
            self._local.depth = 0

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    def _execute_on(
        self,
        connection: sqlite3.Connection,
        query: str,
        params: Sequence,
    ) -> QueryResult:
        cursor = connection.execute(query, params)
        rows = cursor.fetchall() if cursor.description is not None else ()
        return QueryResult(rows, cursor.rowcount, cursor.lastrowid)

    def _require_pool(self) -> SQLiteConnectionPool:
        if self._pool is None:
            raise RuntimeError("Database is not connected.")
        return self._pool

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        self._migrate_legacy_vault_table(connection)
        self._migrate_legacy_audit_table(connection)
        self._ensure_key_store_columns(connection)

        for statement in CREATE_TABLES_SQL:
            connection.execute(statement)
        for statement in CREATE_INDEXES_SQL:
            connection.execute(statement)
        for statement in CREATE_TRIGGERS_SQL:
            connection.execute(statement)

        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")

    def _migrate_legacy_vault_table(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vault_entries';"
        ).fetchone()
        if row is None:
            return

        columns = {
            item[1]
            for item in connection.execute(
                "PRAGMA table_info(vault_entries);"
            ).fetchall()
        }
        if "encrypted_data" in columns:
            return

        legacy_name = "legacy_vault_entries"
        suffix = 1
        while (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?;",
                (legacy_name,),
            ).fetchone()
            is not None
        ):
            legacy_name = f"legacy_vault_entries_{suffix}"
            suffix += 1

        if not legacy_name.replace("_", "").isalnum():
            raise RuntimeError("Unable to create a safe legacy table name.")
        connection.execute(f"ALTER TABLE vault_entries RENAME TO {legacy_name};")

    def _ensure_key_store_columns(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'key_store';"
        ).fetchone()
        if row is None:
            return

        columns = {
            item[1]
            for item in connection.execute("PRAGMA table_info(key_store);").fetchall()
        }
        if "version" not in columns:
            connection.execute(
                "ALTER TABLE key_store ADD COLUMN version INTEGER NOT NULL DEFAULT 1;"
            )
        if "created_at" not in columns:
            connection.execute("ALTER TABLE key_store ADD COLUMN created_at TEXT;")
            connection.execute(
                "UPDATE key_store SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;"
            )

    def _migrate_legacy_audit_table(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_log';"
        ).fetchone()
        if row is None:
            return

        columns = {
            item[1]
            for item in connection.execute("PRAGMA table_info(audit_log);").fetchall()
        }
        if "sequence_number" in columns:
            return

        legacy_name = "legacy_audit_log"
        suffix = 1
        while (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?;",
                (legacy_name,),
            ).fetchone()
            is not None
        ):
            legacy_name = f"legacy_audit_log_{suffix}"
            suffix += 1

        if not legacy_name.replace("_", "").isalnum():
            raise RuntimeError("Unable to create a safe legacy audit table name.")
        connection.execute(f"ALTER TABLE audit_log RENAME TO {legacy_name};")

    def _ensure_default_settings(self, connection: sqlite3.Connection) -> None:
        defaults = (
            ("auto_lock_timeout", "300", 0),
            ("password_policy_min_length", "12", 0),
            ("password_policy_require_uppercase", "1", 0),
            ("password_policy_require_lowercase", "1", 0),
            ("password_policy_require_digit", "1", 0),
            ("password_policy_require_special", "1", 0),
            ("kdf_params_version", "1", 0),
        )
        connection.executemany(
            """
            INSERT OR IGNORE INTO settings (setting_key, setting_value, encrypted)
            VALUES (?, ?, ?);
            """,
            defaults,
        )

    def backup(self) -> None:
        raise NotImplementedError("Backup will be implemented in Sprint 8.")

    def restore(self) -> None:
        raise NotImplementedError("Restore will be implemented in Sprint 8.")
