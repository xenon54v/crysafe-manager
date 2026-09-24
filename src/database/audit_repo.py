from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .models import ZERO_HASH


class AuditRepository:
    """Compatibility adapter for Sprint 1-4 callers.

    Sprint 5 application code uses the event-driven ``AuditLogger``. Calls made
    before the master key is available are stored as unsigned pending records and
    signed automatically after the next successful unlock.
    """

    def __init__(self, db, secure_logger=None):
        self.db = db
        self.secure_logger = secure_logger

    def add_log(
        self,
        action: str,
        entry_id: str | int | None = None,
        details: str = "",
        signature: bytes | None = None,
    ) -> None:
        if self.secure_logger is not None:
            self.secure_logger.log_event(
                str(action).upper(),
                severity=self._severity_for(action),
                source="legacy_audit_adapter",
                details={"message": self._sanitize_text(details)},
                user_id="local_user",
                entry_id=None if entry_id is None else str(entry_id),
            )
            return

        timestamp = datetime.now(timezone.utc).isoformat()
        safe_details = self._sanitize_text(details)
        event_type = str(action).upper()
        severity = self._severity_for(action)
        with self.db.transaction(write=True):
            last = self.db.execute(
                "SELECT sequence_number, entry_hash FROM audit_log "
                "ORDER BY sequence_number DESC LIMIT 1;"
            ).fetchone()
            sequence = 1 if last is None else int(last["sequence_number"]) + 1
            previous_hash = ZERO_HASH if last is None else str(last["entry_hash"])
            entry = {
                "timestamp": timestamp,
                "event_type": event_type,
                "severity": severity,
                "user_id": "local_user",
                "source": "pre_auth_audit",
                "details": {"message": safe_details},
                "entry_id": None if entry_id is None else str(entry_id),
                "sequence_number": sequence,
                "previous_hash": previous_hash,
            }
            entry_data = json.dumps(
                entry,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            entry_hash = hashlib.sha256(entry_data).hexdigest()
            signature_hex = None if signature is None else signature.hex()
            self.db.execute(
                """
                INSERT INTO audit_log
                (sequence_number, id, action, timestamp, event_type, severity,
                 user_id, source, entry_id, details, previous_hash, entry_data,
                 entry_hash, signature, key_id, algorithm)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?);
                """,
                (
                    sequence,
                    sequence,
                    str(action),
                    timestamp,
                    event_type,
                    severity,
                    "local_user",
                    "pre_auth_audit",
                    None if entry_id is None else str(entry_id),
                    safe_details,
                    previous_hash,
                    entry_data,
                    entry_hash,
                    signature_hex,
                    "LEGACY" if signature is not None else "UNSIGNED",
                ),
            )

    def add_clipboard_log(
        self, action: str, entry_id: str | None, details: str
    ) -> None:
        allowed_actions = {
            "clipboard_copy",
            "clipboard_clear",
            "clipboard_security",
            "clipboard_error",
            "clipboard_preview",
        }
        if action not in allowed_actions:
            raise ValueError("Unsupported clipboard audit action.")
        self.add_log(action, entry_id, details)

    def get_logs(self, limit: int = 100):
        cursor = self.db.execute(
            """
            SELECT sequence_number AS id, action, timestamp, entry_id, details
            FROM audit_log
            ORDER BY sequence_number DESC
            LIMIT ?;
            """,
            (limit,),
        )
        return cursor.fetchall()

    @staticmethod
    def _sanitize_text(details: str) -> str:
        text = " ".join(str(details).replace("\x00", "").split())[:240]
        lowered = text.casefold()
        if any(marker in lowered for marker in ("password=", "secret=", "token=")):
            return "[REDACTED]"
        return text

    @staticmethod
    def _severity_for(action: str) -> str:
        lowered = str(action).casefold()
        if "failed" in lowered or "error" in lowered or "security" in lowered:
            return "WARN"
        return "INFO"
