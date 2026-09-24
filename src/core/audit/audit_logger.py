from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.events import (
    AuthenticationFailed,
    ClipboardCleared,
    ClipboardCopied,
    ConfigurationChanged,
    EntryCreated,
    EntryDeleted,
    EntryUpdated,
    EventBus,
    MasterPasswordChanged,
    SearchPerformed,
    SecurityAlert,
    SystemActivity,
    UserLoggedIn,
    UserLoggedOut,
    VaultAccessed,
)
from src.database.models import ZERO_HASH

from .log_signer import AuditLogSigner
from .log_verifier import (
    AuditLogVerifier,
    VerificationReport,
    build_anchor_payload,
    canonical_json,
)


class AuditError(RuntimeError):
    """Raised when a protected audit operation cannot be completed."""


@dataclass(frozen=True)
class AuditConfig:
    max_entries: int = 10_000
    max_age_days: int = 365
    verification_interval_hours: int = 24
    recent_verification_limit: int = 1_000
    page_size: int = 50
    key_rotation_interval: int = 1_000
    lock_on_tamper: bool = True
    encrypt_exports: bool = True
    scheduled_export: str = "disabled"
    export_retention_days: int = 30

    def __post_init__(self) -> None:
        if self.max_entries < 100:
            raise ValueError("Audit maximum entries must be at least 100.")
        if self.max_age_days < 1:
            raise ValueError("Audit maximum age must be positive.")
        if self.verification_interval_hours < 1:
            raise ValueError("Verification interval must be positive.")
        if self.recent_verification_limit < 1:
            raise ValueError("Recent verification limit must be positive.")
        if not 10 <= self.page_size <= 500:
            raise ValueError("Audit page size must be between 10 and 500.")
        if self.key_rotation_interval < 1:
            raise ValueError("Key rotation interval must be positive.")
        if self.scheduled_export not in {"disabled", "daily", "weekly", "monthly"}:
            raise ValueError("Unsupported scheduled export period.")
        if self.export_retention_days < 1:
            raise ValueError("Export retention must be positive.")


@dataclass(frozen=True)
class AuditQuery:
    event_type: str = ""
    severity: str = ""
    user_id: str = ""
    date_from: str = ""
    date_to: str = ""
    search_text: str = ""
    entry_id: str = ""
    page: int = 1
    page_size: int = 50
    sort_by: str = "sequence_number"
    descending: bool = True


class AuditLogger:
    SEVERITIES: ClassVar[set[str]] = {"INFO", "WARN", "ERROR", "CRITICAL"}
    _QUEUE_STOP = object()

    def __init__(
        self,
        db,
        key_manager,
        config: AuditConfig | None = None,
        *,
        is_authenticated: Callable[[], bool] | None = None,
        on_tamper: Callable[[VerificationReport], None] | None = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager
        self.config = config or AuditConfig()
        self._is_authenticated = is_authenticated or (lambda: True)
        self._on_tamper = on_tamper
        self._write_lock = threading.RLock()
        self._queue: queue.Queue[object] = queue.Queue()
        self._worker_error: Exception | None = None
        self._closed = False

        state = self.db.execute(
            "SELECT signing_generation FROM audit_state WHERE state_id = 1;"
        ).fetchone()
        generation = 0 if state is None else int(state["signing_generation"])
        self.signer = AuditLogSigner(self.key_manager, generation=generation)
        self._register_signer()
        self._ensure_state()
        self._migrate_unsigned_entries()
        self._migrate_legacy_tables()
        if self._count_entries() == 0:
            self.log_event(
                "SYSTEM_GENESIS",
                severity="INFO",
                source="audit_logger",
                details={"message": "Audit log initialized"},
                user_id="system",
            )

        self._worker = threading.Thread(
            target=self._worker_loop,
            name="cryptosafe-audit-writer",
            daemon=True,
        )
        self._worker.start()

    def log_event(
        self,
        event_type: str,
        *,
        severity: str = "INFO",
        source: str,
        details: dict[str, Any] | None = None,
        user_id: str | None = None,
        entry_id: str | None = None,
        timestamp: str | None = None,
    ) -> int:
        if self._closed:
            raise AuditError("Audit logger is closed.")
        return self._write_entry(
            event_type=event_type,
            severity=severity,
            source=source,
            details=details or {},
            user_id=user_id or "anonymous",
            entry_id=entry_id,
            timestamp=timestamp,
        )

    def log_event_async(self, event_type: str, **fields: Any) -> None:
        if self._closed:
            raise AuditError("Audit logger is closed.")
        self._queue.put((event_type, fields))

    def flush(self) -> None:
        self._queue.join()
        if self._worker_error is not None:
            error = self._worker_error
            self._worker_error = None
            raise AuditError("An asynchronous audit write failed.") from error

    def close(self) -> None:
        if self._closed:
            return
        self.flush()
        self._closed = True
        self._queue.put(self._QUEUE_STOP)
        self._queue.join()
        self._worker.join(timeout=2.0)
        self.signer.clear()

    def verify_integrity(
        self,
        *,
        full: bool = True,
        recent_limit: int | None = None,
        notify: bool = True,
    ) -> VerificationReport:
        self._require_access()
        self.flush()
        verifier = AuditLogVerifier(self.db, self.key_manager)
        report = verifier.verify(
            recent_limit=(
                None if full else recent_limit or self.config.recent_verification_limit
            )
        )
        status = "VALID" if report.verified else "TAMPERED"
        self.db.execute(
            """
            UPDATE audit_state
            SET integrity_status = ?, last_verified_at = ?, updated_at = ?
            WHERE state_id = 1;
            """,
            (status, report.finished_at, report.finished_at),
        )
        if not report.verified:
            self.record_incident(
                "AUDIT_TAMPERING_DETECTED",
                report.to_dict(),
                severity="CRITICAL",
            )
            if notify and self._on_tamper is not None:
                self._on_tamper(report)
        return report

    def query_entries(self, query: AuditQuery | None = None) -> dict[str, Any]:
        self._require_access()
        self.flush()
        query = query or AuditQuery(page_size=self.config.page_size)
        if query.page < 1 or not 1 <= query.page_size <= 500:
            raise ValueError("Invalid audit page request.")

        conditions: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("event_type", query.event_type),
            ("severity", query.severity),
            ("user_id", query.user_id),
            ("entry_id", query.entry_id),
        ):
            if value:
                conditions.append(f"{column} = ?")
                params.append(value)
        if query.date_from:
            conditions.append("timestamp >= ?")
            params.append(query.date_from)
        if query.date_to:
            conditions.append("timestamp <= ?")
            params.append(query.date_to)
        if query.search_text:
            conditions.append("details LIKE ? ESCAPE '\\'")
            escaped = (
                query.search_text.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            params.append(f"%{escaped}%")
        where = " WHERE " + " AND ".join(conditions) if conditions else ""

        count = int(
            self.db.execute(
                "SELECT COUNT(*) FROM audit_log" + where + ";", params
            ).fetchone()[0]
        )
        sort_columns = {
            "sequence_number",
            "timestamp",
            "event_type",
            "severity",
            "user_id",
            "source",
        }
        sort_by = query.sort_by if query.sort_by in sort_columns else "sequence_number"
        direction = "DESC" if query.descending else "ASC"
        offset = (query.page - 1) * query.page_size
        rows = self.db.execute(
            "SELECT * FROM audit_log"
            + where
            + f" ORDER BY {sort_by} {direction} LIMIT ? OFFSET ?;",
            [*params, query.page_size, offset],
        ).fetchall()
        entries = [self._row_to_public_dict(row) for row in rows]
        return {
            "entries": entries,
            "total": count,
            "page": query.page,
            "page_size": query.page_size,
            "pages": max(1, (count + query.page_size - 1) // query.page_size),
        }

    def get_statistics(self, days: int = 30) -> dict[str, Any]:
        self._require_access()
        if days not in {7, 30, 90}:
            raise ValueError("Statistics range must be 7, 30, or 90 days.")
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        frequency_rows = self.db.execute(
            """
            SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS count
            FROM audit_log WHERE timestamp >= ?
            GROUP BY day ORDER BY day;
            """,
            (since,),
        ).fetchall()
        event_rows = self.db.execute(
            """
            SELECT event_type, COUNT(*) AS count
            FROM audit_log WHERE timestamp >= ?
            GROUP BY event_type ORDER BY count DESC LIMIT 10;
            """,
            (since,),
        ).fetchall()
        security = self.db.execute(
            """
            SELECT
                SUM(CASE WHEN event_type = 'AUTH_LOGIN_FAILURE' THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity IN ('ERROR', 'CRITICAL') THEN 1 ELSE 0 END)
            FROM audit_log WHERE timestamp >= ?;
            """,
            (since,),
        ).fetchone()
        state = self.db.execute(
            "SELECT integrity_status FROM audit_state WHERE state_id = 1;"
        ).fetchone()
        return {
            "days": days,
            "daily_frequency": [dict(row) for row in frequency_rows],
            "top_events": [dict(row) for row in event_rows],
            "failed_logins": int(security[0] or 0),
            "critical_events": int(security[1] or 0),
            "total_entries": self._count_entries(),
            "integrity_status": "UNKNOWN" if state is None else state[0],
        }

    def record_incident(
        self,
        event_type: str,
        details: dict[str, Any],
        *,
        severity: str = "CRITICAL",
    ) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        safe_details = canonical_json(self._sanitize_details(details))
        encryption_key = self.key_manager.derive_subkey("audit-incident-encryption", 32)
        integrity_key = self.key_manager.derive_subkey("audit-incident-integrity", 32)
        nonce = os.urandom(12)
        encrypted = nonce + AESGCM(encryption_key).encrypt(
            nonce, safe_details, event_type.encode("utf-8")
        )
        checksum = hmac.new(
            integrity_key,
            timestamp.encode("utf-8") + encrypted,
            hashlib.sha256,
        ).hexdigest()
        self.db.execute(
            """
            INSERT INTO audit_incidents
            (timestamp, event_type, severity, details, checksum)
            VALUES (?, ?, ?, ?, ?);
            """,
            (timestamp, event_type, severity, encrypted, checksum),
        )

    def rotate_if_needed(self) -> int | None:
        self.flush()
        state = self.db.execute(
            "SELECT last_archived_sequence FROM audit_state WHERE state_id = 1;"
        ).fetchone()
        last_archived = 0 if state is None else int(state[0])
        total = self._count_entries()
        entry_cutoff = max(0, total - self.config.max_entries)
        age_cutoff = (
            datetime.now(timezone.utc) - timedelta(days=self.config.max_age_days)
        ).isoformat()
        age_row = self.db.execute(
            "SELECT MAX(sequence_number) FROM audit_log WHERE timestamp < ?;",
            (age_cutoff,),
        ).fetchone()
        age_sequence = int(age_row[0] or 0)
        end_sequence = max(entry_cutoff, age_sequence)
        if end_sequence <= last_archived:
            return None

        rows = self.db.execute(
            """
            SELECT sequence_number, entry_data, entry_hash, signature, key_id, algorithm
            FROM audit_log
            WHERE sequence_number > ? AND sequence_number <= ?
            ORDER BY sequence_number;
            """,
            (last_archived, end_sequence),
        ).fetchall()
        if not rows:
            return None
        archive_data = canonical_json(
            {
                "format": "cryptosafe-audit-archive-v1",
                "entries": [
                    {
                        "sequence_number": row["sequence_number"],
                        "entry_data_hex": bytes(row["entry_data"]).hex(),
                        "entry_hash": row["entry_hash"],
                        "signature": row["signature"],
                        "key_id": row["key_id"],
                        "algorithm": row["algorithm"],
                    }
                    for row in rows
                ],
            }
        )
        start_sequence = int(rows[0]["sequence_number"])
        end_sequence = int(rows[-1]["sequence_number"])
        aad = f"audit-archive:{start_sequence}:{end_sequence}".encode("ascii")
        key = self.key_manager.derive_subkey("audit-archive-encryption", 32)
        nonce = hashlib.sha256(aad + self.signer.key_id.encode("ascii")).digest()[:12]
        encrypted = nonce + AESGCM(key).encrypt(nonce, archive_data, aad)
        checksum = hashlib.sha256(encrypted).hexdigest()
        result = self.db.execute(
            """
            INSERT OR IGNORE INTO audit_archives
            (created_at, start_sequence, end_sequence, entry_count,
             encrypted_data, checksum)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                start_sequence,
                end_sequence,
                len(rows),
                encrypted,
                checksum,
            ),
        )
        self.db.execute(
            "UPDATE audit_state SET last_archived_sequence = ?, updated_at = ? "
            "WHERE state_id = 1;",
            (end_sequence, datetime.now(timezone.utc).isoformat()),
        )
        return result.lastrowid

    def report_protection_attempt(self, operation: str) -> None:
        self.record_incident(
            "AUDIT_PROTECTION_ATTEMPT",
            {"operation": operation, "result": "blocked"},
            severity="CRITICAL",
        )
        self.log_event(
            "SECURITY_AUDIT_PROTECTION_ATTEMPT",
            severity="CRITICAL",
            source="audit_logger",
            details={"operation": operation, "result": "blocked"},
            user_id="local_user",
        )

    def rekey_after_master_password_change(self) -> None:
        """Start a new signing generation after the master key changes."""
        self.flush()
        with self._write_lock:
            next_generation = self.signer.generation + 1
            self.signer.clear()
            self.signer = AuditLogSigner(
                self.key_manager,
                generation=next_generation,
            )
            self._register_signer()
            self.db.execute(
                "UPDATE audit_state SET signing_generation = ?, updated_at = ? "
                "WHERE state_id = 1;",
                (next_generation, datetime.now(timezone.utc).isoformat()),
            )

    def _write_entry(
        self,
        *,
        event_type: str,
        severity: str,
        source: str,
        details: dict[str, Any],
        user_id: str,
        entry_id: str | None,
        timestamp: str | None,
    ) -> int:
        event_type = self._clean_identifier(event_type, "event type")
        source = self._clean_identifier(source, "source")
        severity = severity.upper()
        if severity not in self.SEVERITIES:
            raise ValueError("Unsupported audit severity.")
        timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        safe_details = self._sanitize_details(details)
        safe_user = self._sanitize_user(user_id)
        safe_entry_id = None if entry_id is None else str(entry_id)[:128]

        with self._write_lock, self.db.transaction(write=True):
            last = self.db.execute(
                "SELECT sequence_number, entry_hash FROM audit_log "
                "ORDER BY sequence_number DESC LIMIT 1;"
            ).fetchone()
            sequence = 1 if last is None else int(last["sequence_number"]) + 1
            previous_hash = ZERO_HASH if last is None else str(last["entry_hash"])
            self._rotate_signer_for_sequence(sequence)
            entry = {
                "timestamp": timestamp,
                "event_type": event_type,
                "severity": severity,
                "user_id": safe_user,
                "source": source,
                "details": safe_details,
                "entry_id": safe_entry_id,
                "sequence_number": sequence,
                "previous_hash": previous_hash,
            }
            entry_data = canonical_json(entry)
            entry_hash = hashlib.sha256(entry_data).hexdigest()
            signature = self.signer.sign(entry_data).hex()
            self.db.execute(
                """
                INSERT INTO audit_log
                (sequence_number, id, action, timestamp, event_type, severity,
                 user_id, source, entry_id, details, previous_hash, entry_data,
                 entry_hash, signature, key_id, algorithm)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    sequence,
                    sequence,
                    event_type,
                    timestamp,
                    event_type,
                    severity,
                    safe_user,
                    source,
                    safe_entry_id,
                    json.dumps(safe_details, ensure_ascii=False, sort_keys=True),
                    previous_hash,
                    entry_data,
                    entry_hash,
                    signature,
                    self.signer.key_id,
                    self.signer.algorithm,
                ),
            )
            self._update_state(sequence, entry_hash)
        return sequence

    def _worker_loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is self._QUEUE_STOP:
                    return
                event_type, fields = item
                self.log_event(str(event_type), **dict(fields))
            except Exception as exc:  # noqa: BLE001 - worker reports through flush()
                self._worker_error = exc
            finally:
                self._queue.task_done()

    def _register_signer(self) -> None:
        public = self.signer.public_key
        self.db.execute(
            """
            INSERT OR IGNORE INTO audit_keys
            (key_id, algorithm, public_key, generation, created_at)
            VALUES (?, ?, ?, ?, ?);
            """,
            (
                public.key_id,
                public.algorithm,
                public.public_key,
                public.generation,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def _ensure_state(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        anchor = self.signer.sign(
            build_anchor_payload(0, ZERO_HASH, self.signer.key_id)
        ).hex()
        self.db.execute(
            """
            INSERT OR IGNORE INTO audit_state
            (state_id, last_sequence, last_hash, key_id, anchor_signature,
             signing_generation, integrity_status, updated_at)
            VALUES (1, 0, ?, ?, ?, ?, 'UNKNOWN', ?);
            """,
            (ZERO_HASH, self.signer.key_id, anchor, self.signer.generation, now),
        )

    def _update_state(self, sequence: int, entry_hash: str) -> None:
        anchor = self.signer.sign(
            build_anchor_payload(sequence, entry_hash, self.signer.key_id)
        ).hex()
        self.db.execute(
            """
            UPDATE audit_state
            SET last_sequence = ?, last_hash = ?, key_id = ?,
                anchor_signature = ?, signing_generation = ?, updated_at = ?
            WHERE state_id = 1;
            """,
            (
                sequence,
                entry_hash,
                self.signer.key_id,
                anchor,
                self.signer.generation,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def _rotate_signer_for_sequence(self, sequence: int) -> None:
        if sequence <= 1:
            return
        target_generation = (sequence - 1) // self.config.key_rotation_interval
        while self.signer.generation < target_generation:
            self.signer = self.signer.rotate()
            self._register_signer()

    def _migrate_unsigned_entries(self) -> None:
        rows = self.db.execute(
            "SELECT * FROM audit_log WHERE signature IS NULL ORDER BY sequence_number;"
        ).fetchall()
        for row in rows:
            sequence = int(row["sequence_number"])
            previous = self.db.execute(
                "SELECT entry_hash FROM audit_log WHERE sequence_number < ? "
                "ORDER BY sequence_number DESC LIMIT 1;",
                (sequence,),
            ).fetchone()
            previous_hash = ZERO_HASH if previous is None else str(previous[0])
            try:
                details = json.loads(row["details"] or "{}")
            except (TypeError, json.JSONDecodeError):
                details = {"message": str(row["details"] or "")}
            self._rotate_signer_for_sequence(sequence)
            entry = {
                "timestamp": str(row["timestamp"]),
                "event_type": str(row["event_type"]),
                "severity": str(row["severity"]),
                "user_id": str(row["user_id"]),
                "source": str(row["source"]),
                "details": self._sanitize_details(details),
                "entry_id": row["entry_id"],
                "sequence_number": sequence,
                "previous_hash": previous_hash,
            }
            data = canonical_json(entry)
            entry_hash = hashlib.sha256(data).hexdigest()
            signature = self.signer.sign(data).hex()
            self.db.execute(
                """
                UPDATE audit_log
                SET id = ?, action = ?, previous_hash = ?, entry_data = ?,
                    entry_hash = ?, signature = ?, key_id = ?, algorithm = ?,
                    details = ?
                WHERE sequence_number = ? AND signature IS NULL;
                """,
                (
                    sequence,
                    entry["event_type"],
                    previous_hash,
                    data,
                    entry_hash,
                    signature,
                    self.signer.key_id,
                    self.signer.algorithm,
                    json.dumps(entry["details"], ensure_ascii=False, sort_keys=True),
                    sequence,
                ),
            )
            self._update_state(sequence, entry_hash)

    def _migrate_legacy_tables(self) -> None:
        tables = self.db.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name LIKE 'legacy_audit_log%'
            ORDER BY name;
            """
        ).fetchall()
        for table_row in tables:
            table = str(table_row["name"])
            if not table.replace("_", "").isalnum():
                continue
            rows = self.db.execute(
                f"SELECT id, action, timestamp, entry_id, details FROM {table} ORDER BY id;"
            ).fetchall()
            for row in rows:
                self.log_event(
                    str(row["action"]),
                    severity=(
                        "WARN" if str(row["action"]) == "failed_login" else "INFO"
                    ),
                    source="legacy_audit_migration",
                    details={"legacy_details": str(row["details"] or "")},
                    user_id="local_user",
                    entry_id=(
                        None if row["entry_id"] is None else str(row["entry_id"])
                    ),
                    timestamp=str(row["timestamp"]),
                )
            migrated = f"migrated_{table}"
            if migrated.replace("_", "").isalnum():
                self.db.execute(f"ALTER TABLE {table} RENAME TO {migrated};")

    def _row_to_public_dict(self, row) -> dict[str, Any]:
        try:
            entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
            entry = {
                "timestamp": row["timestamp"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "user_id": row["user_id"],
                "source": row["source"],
                "entry_id": row["entry_id"],
                "details": {"error": "Unreadable signed entry"},
            }
        entry.update(
            {
                "sequence_number": int(row["sequence_number"]),
                "entry_hash": row["entry_hash"],
                "signature": row["signature"],
                "key_id": row["key_id"],
                "algorithm": row["algorithm"],
            }
        )
        return entry

    def _count_entries(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM audit_log;").fetchone()[0])

    def _require_access(self) -> None:
        if not self._is_authenticated():
            raise PermissionError("Authentication is required to read audit logs.")

    @staticmethod
    def _clean_identifier(value: str, label: str) -> str:
        cleaned = "_".join(str(value).strip().split())[:96]
        if not cleaned or not re.fullmatch(r"[A-Za-z0-9_.:-]+", cleaned):
            raise ValueError(f"Invalid audit {label}.")
        return cleaned.upper() if label == "event type" else cleaned

    @classmethod
    def _sanitize_details(cls, value: Any, depth: int = 0) -> Any:
        if depth > 8:
            return "[TRUNCATED]"
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, item in list(value.items())[:100]:
                clean_key = str(key)[:80]
                normalized = clean_key.casefold()
                if any(
                    marker in normalized
                    for marker in (
                        "password",
                        "passphrase",
                        "private_key",
                        "master_key",
                        "encryption_key",
                        "secret",
                        "token",
                        "clipboard_value",
                    )
                ):
                    result[clean_key] = "[REDACTED]"
                elif normalized in {"query", "search_query"}:
                    result[f"{clean_key}_hash"] = cls._hash_placeholder(item)
                elif normalized in {
                    "email",
                    "ip",
                    "ip_address",
                    "source_address",
                    "username",
                    "personal_data",
                }:
                    result[clean_key] = cls._hash_placeholder(item)
                else:
                    result[clean_key] = cls._sanitize_details(item, depth + 1)
            return result
        if isinstance(value, (list, tuple, set)):
            return [
                cls._sanitize_details(item, depth + 1) for item in list(value)[:100]
            ]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        text = " ".join(str(value).replace("\x00", "").split())[:2_000]
        text = re.sub(
            r"(?i)(password|passphrase|secret|token)\s*[:=]\s*\S+",
            r"\1=[REDACTED]",
            text,
        )
        return text

    @staticmethod
    def _hash_placeholder(value: Any) -> str:
        digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]
        return f"sha256:{digest}"

    @classmethod
    def _sanitize_user(cls, user_id: str) -> str:
        text = str(user_id).strip()[:128] or "anonymous"
        return cls._hash_placeholder(text) if "@" in text else text


class AuditEventBridge:
    """Converts domain events to structured audit records."""

    EVENT_TYPES = (
        EntryCreated,
        EntryUpdated,
        EntryDeleted,
        UserLoggedIn,
        UserLoggedOut,
        ClipboardCopied,
        ClipboardCleared,
        SearchPerformed,
        AuthenticationFailed,
        MasterPasswordChanged,
        VaultAccessed,
        SystemActivity,
        ConfigurationChanged,
        SecurityAlert,
    )

    def __init__(self, event_bus: EventBus, logger: AuditLogger) -> None:
        self.event_bus = event_bus
        self.logger = logger
        for event_type in self.EVENT_TYPES:
            self.event_bus.subscribe(event_type, self.handle)

    def close(self) -> None:
        for event_type in self.EVENT_TYPES:
            self.event_bus.unsubscribe(event_type, self.handle)

    def handle(self, event) -> None:
        data = self._convert(event)
        if data["severity"] in {"WARN", "ERROR", "CRITICAL"}:
            self.logger.log_event(**data)
        else:
            event_type = data.pop("event_type")
            self.logger.log_event_async(event_type, **data)

    def _convert(self, event) -> dict[str, Any]:
        common = {
            "severity": "INFO",
            "source": "event_bus",
            "details": {},
            "user_id": "local_user",
            "entry_id": getattr(event, "entry_id", None),
            "timestamp": event.timestamp.isoformat(),
        }
        if isinstance(event, EntryCreated):
            return {"event_type": "VAULT_ENTRY_CREATE", **common}
        if isinstance(event, EntryUpdated):
            return {"event_type": "VAULT_ENTRY_UPDATE", **common}
        if isinstance(event, EntryDeleted):
            return {"event_type": "VAULT_ENTRY_DELETE", **common}
        if isinstance(event, VaultAccessed):
            common["details"] = {"operation": event.operation}
            return {"event_type": "VAULT_ENTRY_READ", **common}
        if isinstance(event, UserLoggedIn):
            common["user_id"] = event.user
            return {"event_type": "AUTH_LOGIN_SUCCESS", **common}
        if isinstance(event, UserLoggedOut):
            common["user_id"] = event.user
            return {"event_type": "AUTH_LOGOUT", **common}
        if isinstance(event, AuthenticationFailed):
            common.update(
                severity="WARN",
                user_id=event.user,
                details={
                    "attempt_count": event.attempt_count,
                    "source_address": event.source_address,
                },
            )
            return {"event_type": "AUTH_LOGIN_FAILURE", **common}
        if isinstance(event, MasterPasswordChanged):
            common["user_id"] = event.user
            return {"event_type": "AUTH_PASSWORD_CHANGE", **common}
        if isinstance(event, ClipboardCopied):
            common["details"] = {"field": event.field}
            return {"event_type": "CLIPBOARD_COPY", **common}
        if isinstance(event, ClipboardCleared):
            common["details"] = {"reason": event.reason}
            return {"event_type": "CLIPBOARD_CLEAR", **common}
        if isinstance(event, SearchPerformed):
            common["details"] = {
                "query": event.query,
                "query_length": len(event.query),
                "result_count": event.result_count,
            }
            return {"event_type": "VAULT_SEARCH", **common}
        if isinstance(event, ConfigurationChanged):
            common["details"] = {"setting_name": event.setting_name}
            return {"event_type": "CONFIGURATION_CHANGE", **common}
        if isinstance(event, SystemActivity):
            common["severity"] = event.severity
            common["details"] = event.details or {}
            common["source"] = "system"
            return {"event_type": event.event_type, **common}
        if isinstance(event, SecurityAlert):
            common["severity"] = event.severity
            common["source"] = event.source
            common["details"] = event.details or {}
            return {"event_type": event.event_type, **common}
        raise TypeError(f"Unsupported audit event: {type(event).__name__}")
