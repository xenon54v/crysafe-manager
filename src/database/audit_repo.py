from __future__ import annotations

from datetime import datetime, timezone


class AuditRepository:
    def __init__(self, db):
        self.db = db

    def add_log(
        self,
        action: str,
        entry_id: str | int | None = None,
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

    def add_clipboard_log(
        self, action: str, entry_id: str | None, details: str
    ) -> None:
        """Stores clipboard metadata only; clipboard values are never accepted."""
        allowed_actions = {
            "clipboard_copy",
            "clipboard_clear",
            "clipboard_security",
            "clipboard_error",
            "clipboard_preview",
        }
        if action not in allowed_actions:
            raise ValueError("Unsupported clipboard audit action.")
        safe_details = " ".join(str(details).replace("\x00", "").split())[:240]
        self.add_log(action, entry_id, safe_details)

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
