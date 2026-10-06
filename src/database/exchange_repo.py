from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


class ExchangeRepository:
    """Stores non-secret metadata for import, export, sharing, and contacts."""

    def __init__(self, db) -> None:
        self.db = db

    def add_history(
        self,
        *,
        operation_type: str,
        format_name: str,
        encryption_method: str,
        entry_count: int,
        file_size: int,
        checksum: str,
        verification_status: str,
        details: dict[str, Any] | None = None,
    ) -> str:
        operation_id = str(uuid.uuid4())
        self.db.execute(
            """
            INSERT INTO import_export_history (
                operation_id, operation_type, format, encryption_method,
                entry_count, file_size, checksum, verification_status,
                details, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                operation_id,
                operation_type,
                format_name,
                encryption_method,
                max(0, int(entry_count)),
                max(0, int(file_size)),
                checksum,
                verification_status,
                json.dumps(details or {}, ensure_ascii=False, sort_keys=True),
                self._now(),
            ),
        )
        return operation_id

    def add_share(
        self,
        *,
        shared_id: str,
        original_entry_id: str,
        encryption_method: str,
        recipient_info: str,
        permissions: dict[str, Any],
        package_checksum: str,
        shared_at: str,
        expires_at: str,
    ) -> None:
        self.db.execute(
            """
            INSERT INTO shared_entries (
                shared_id, original_entry_id, encryption_method, recipient_info,
                permissions, package_checksum, shared_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                shared_id,
                original_entry_id,
                encryption_method,
                recipient_info,
                json.dumps(permissions, ensure_ascii=False, sort_keys=True),
                package_checksum,
                shared_at,
                expires_at,
            ),
        )

    def set_share_status(self, shared_id: str, status: str) -> bool:
        if status not in {"active", "expired", "revoked", "imported"}:
            raise ValueError("Unsupported share status.")
        result = self.db.execute(
            "UPDATE shared_entries SET status = ? WHERE shared_id = ?;",
            (status, shared_id),
        )
        return result.rowcount == 1

    def list_shares(self, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.execute(
            """
            SELECT * FROM shared_entries
            ORDER BY shared_at DESC LIMIT ?;
            """,
            (max(1, min(limit, 500)),),
        ).fetchall()
        return [dict(row) for row in rows]

    def save_checkpoint(
        self,
        checkpoint_id: str,
        source_checksum: str,
        format_name: str,
        next_index: int,
        imported_count: int,
    ) -> None:
        self.db.execute(
            """
            INSERT INTO import_checkpoints (
                checkpoint_id, source_checksum, format, next_index,
                imported_count, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(checkpoint_id) DO UPDATE SET
                source_checksum = excluded.source_checksum,
                format = excluded.format,
                next_index = excluded.next_index,
                imported_count = excluded.imported_count,
                updated_at = excluded.updated_at;
            """,
            (
                checkpoint_id,
                source_checksum,
                format_name,
                next_index,
                imported_count,
                self._now(),
            ),
        )

    def load_checkpoint(self, checkpoint_id: str):
        return self.db.execute(
            "SELECT * FROM import_checkpoints WHERE checkpoint_id = ?;",
            (checkpoint_id,),
        ).fetchone()

    def clear_checkpoint(self, checkpoint_id: str) -> None:
        self.db.execute(
            "DELETE FROM import_checkpoints WHERE checkpoint_id = ?;",
            (checkpoint_id,),
        )

    def mark_nonce_used(self, nonce: str, purpose: str, expires_at: str) -> bool:
        self.db.execute(
            "DELETE FROM exchange_nonces WHERE expires_at <= ?;", (self._now(),)
        )
        try:
            self.db.execute(
                """
                INSERT INTO exchange_nonces (nonce, purpose, used_at, expires_at)
                VALUES (?, ?, ?, ?);
                """,
                (nonce, purpose, self._now(), expires_at),
            )
        except Exception as exc:
            if "UNIQUE" in str(exc).upper():
                return False
            raise
        return True

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
