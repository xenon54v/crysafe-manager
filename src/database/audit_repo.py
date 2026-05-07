from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


class AuditRepository:
    def __init__(self, db):
        self.db = db

    def add_log(
        self,
        action: str,
        entry_id: Optional[int] = None,
        details: str = "",
        signature: bytes | None = None,
    ) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()

        self.db.execute(
            """
            INSERT INTO audit_log (action, timestamp, entry_id, details, signature)
            VALUES (?, ?, ?, ?, ?);
            """,
            (action, timestamp, entry_id, details, signature),
        )

    def get_logs(self, limit: int = 100):
        cursor = self.db.execute(
            """
            SELECT id, action, timestamp, entry_id, details
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        return cursor.fetchall()