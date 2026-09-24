from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .audit_logger import AuditQuery
from .log_verifier import AuditLogVerifier, VerificationReport


class AuditExportError(RuntimeError):
    """Raised when an audit export cannot be produced or opened."""


class AuditLogExporter:
    ENCRYPTED_HEADER = b"CSAUDIT1"

    def __init__(self, logger, key_manager) -> None:
        self.logger = logger
        self.key_manager = key_manager

    def export(
        self,
        destination: Path | str,
        export_format: str,
        *,
        query: AuditQuery | None = None,
        exporter: str = "local_user",
        encrypt: bool | None = None,
        master_password_confirmed: bool = False,
    ) -> Path:
        if not master_password_confirmed:
            raise PermissionError(
                "Master password confirmation is required for export."
            )
        self.logger._require_access()
        self.logger.flush()
        export_format = export_format.casefold()
        if export_format not in {"json", "csv", "pdf"}:
            raise ValueError("Audit export format must be JSON, CSV, or PDF.")

        rows = self._select_rows(query)
        metadata = self._metadata(exporter, rows, query)
        if export_format == "json":
            payload = self._signed_json_bytes(metadata, rows)
        elif export_format == "csv":
            payload = self._csv_bytes(metadata, rows)
        else:
            payload = self._pdf_bytes(metadata, rows)

        should_encrypt = (
            self.logger.config.encrypt_exports if encrypt is None else encrypt
        )
        if should_encrypt:
            payload = self.encrypt_payload(payload, export_format)

        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        self.logger.log_event(
            "AUDIT_EXPORT",
            severity="INFO",
            source="audit_exporter",
            details={
                "format": export_format,
                "encrypted": should_encrypt,
                "entry_count": len(rows),
                "range_start": metadata["range"]["start"],
                "range_end": metadata["range"]["end"],
            },
            user_id=exporter,
        )
        return path

    def export_verification_report(
        self,
        report: VerificationReport,
        destination: Path | str,
        *,
        master_password_confirmed: bool = False,
    ) -> Path:
        if not master_password_confirmed:
            raise PermissionError(
                "Master password confirmation is required for export."
            )
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix.casefold() == ".pdf":
            metadata = {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "exporter": "local_user",
                "range": {"start": None, "end": None},
                "entry_count": report.total_entries,
                "report": report.to_dict(),
            }
            path.write_bytes(self._verification_pdf_bytes(metadata, report))
        else:
            path.write_text(
                json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        self.logger.log_event(
            "AUDIT_VERIFICATION_REPORT_EXPORT",
            severity="INFO",
            source="audit_exporter",
            details={"verified": report.verified, "format": path.suffix.casefold()},
            user_id="local_user",
        )
        return path

    def encrypt_payload(self, payload: bytes, export_format: str) -> bytes:
        key = self.key_manager.derive_subkey("audit-export-encryption", 32)
        nonce = os.urandom(12)
        aad = f"cryptosafe-audit-export:{export_format}:v1".encode("ascii")
        ciphertext = AESGCM(key).encrypt(nonce, payload, aad)
        format_name = export_format.encode("ascii")
        return (
            self.ENCRYPTED_HEADER
            + bytes([len(format_name)])
            + format_name
            + nonce
            + ciphertext
        )

    def decrypt_payload(self, payload: bytes) -> tuple[str, bytes]:
        if not payload.startswith(self.ENCRYPTED_HEADER):
            raise AuditExportError("The export is not a CryptoSafe encrypted file.")
        offset = len(self.ENCRYPTED_HEADER)
        format_length = payload[offset]
        offset += 1
        export_format = payload[offset : offset + format_length].decode("ascii")
        offset += format_length
        nonce = payload[offset : offset + 12]
        ciphertext = payload[offset + 12 :]
        key = self.key_manager.derive_subkey("audit-export-encryption", 32)
        aad = f"cryptosafe-audit-export:{export_format}:v1".encode("ascii")
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise AuditExportError("Export authentication failed.") from exc
        return export_format, plaintext

    @staticmethod
    def verify_signed_json(payload: bytes | str) -> VerificationReport:
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        try:
            bundle = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditExportError("Signed JSON export is invalid.") from exc
        return AuditLogVerifier.verify_signed_export(bundle)

    def _select_rows(self, query: AuditQuery | None):
        query = query or AuditQuery(page_size=500)
        conditions: list[str] = ["signature IS NOT NULL"]
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
            conditions.append("details LIKE ?")
            params.append(f"%{query.search_text}%")
        return self.logger.db.execute(
            "SELECT * FROM audit_log WHERE "
            + " AND ".join(conditions)
            + " ORDER BY sequence_number ASC;",
            params,
        ).fetchall()

    def _signed_json_bytes(self, metadata, rows) -> bytes:
        key_ids = sorted({str(row["key_id"]) for row in rows})
        if key_ids:
            placeholders = ",".join("?" for _ in key_ids)
            key_rows = self.logger.db.execute(
                "SELECT * FROM audit_keys WHERE key_id IN ("
                + placeholders
                + ") ORDER BY generation;",
                key_ids,
            ).fetchall()
        else:
            key_rows = []
        bundle = {
            "format": "cryptosafe-signed-audit-v1",
            "metadata": metadata,
            "public_keys": [
                {
                    "key_id": row["key_id"],
                    "algorithm": row["algorithm"],
                    "generation": row["generation"],
                    "public_key": bytes(row["public_key"]).hex(),
                    "created_at": row["created_at"],
                }
                for row in key_rows
            ],
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
        return json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2).encode(
            "utf-8"
        )

    @staticmethod
    def _csv_bytes(metadata, rows) -> bytes:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(["CryptoSafe Audit Export", metadata["exported_at"]])
        writer.writerow(
            [
                "sequence_number",
                "timestamp",
                "event_type",
                "severity",
                "user_id",
                "source",
                "entry_id",
                "details",
                "entry_hash",
                "signature",
                "key_id",
            ]
        )
        for row in rows:
            entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
            writer.writerow(
                [
                    row["sequence_number"],
                    entry["timestamp"],
                    entry["event_type"],
                    entry["severity"],
                    entry["user_id"],
                    entry["source"],
                    entry["entry_id"],
                    json.dumps(entry["details"], ensure_ascii=False, sort_keys=True),
                    row["entry_hash"],
                    row["signature"],
                    row["key_id"],
                ]
            )
        return stream.getvalue().encode("utf-8-sig")

    def _pdf_bytes(self, metadata, rows) -> bytes:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        stream = io.BytesIO()
        doc = SimpleDocTemplate(
            stream,
            pagesize=A4,
            rightMargin=16 * mm,
            leftMargin=16 * mm,
            topMargin=16 * mm,
            bottomMargin=16 * mm,
            title="CryptoSafe Audit Report",
        )
        styles = getSampleStyleSheet()
        title = ParagraphStyle(
            "AuditTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontSize=18,
            leading=22,
            textColor=colors.black,
        )
        story = [
            Paragraph("CryptoSafe Audit Report", title),
            Spacer(1, 6 * mm),
            Paragraph(f"Exported at {metadata['exported_at']}", styles["BodyText"]),
            Paragraph(f"Exporter {metadata['exporter']}", styles["BodyText"]),
            Paragraph(f"Entries {metadata['entry_count']}", styles["BodyText"]),
            Spacer(1, 6 * mm),
        ]
        table_data = [["Seq", "Timestamp", "Event", "Severity", "User", "Entry"]]
        for row in rows:
            entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
            table_data.append(
                [
                    str(row["sequence_number"]),
                    str(entry["timestamp"])[:19],
                    str(entry["event_type"]),
                    str(entry["severity"]),
                    str(entry["user_id"]),
                    str(entry["entry_id"] or "-"),
                ]
            )
        table = Table(
            table_data,
            repeatRows=1,
            colWidths=[12 * mm, 34 * mm, 46 * mm, 20 * mm, 30 * mm, 34 * mm],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D9D9D9")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#F1F5F9")],
                    ),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(table)
        if rows:
            story.extend([PageBreak(), Paragraph("Event Details", styles["Heading1"])])
            for row in rows[:200]:
                entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))
                details = json.dumps(
                    entry["details"], ensure_ascii=False, sort_keys=True
                )
                story.append(
                    Paragraph(
                        f"{row['sequence_number']} {entry['event_type']} {details}",
                        styles["BodyText"],
                    )
                )
                story.append(Spacer(1, 2 * mm))
        doc.build(story)
        return stream.getvalue()

    def _verification_pdf_bytes(self, metadata, report: VerificationReport) -> bytes:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

        stream = io.BytesIO()
        doc = SimpleDocTemplate(stream, pagesize=A4, title="Audit Verification Report")
        styles = getSampleStyleSheet()
        status = "VALID" if report.verified else "TAMPERED"
        story = [
            Paragraph("Audit Verification Report", styles["Title"]),
            Spacer(1, 8 * mm),
            Paragraph(f"Status {status}", styles["Heading1"]),
            Paragraph(f"Verified entries {report.valid_entries}", styles["BodyText"]),
            Paragraph(f"Total entries {report.total_entries}", styles["BodyText"]),
            Paragraph(
                f"Duration {report.duration_seconds:.6f} seconds", styles["BodyText"]
            ),
            Paragraph(f"Finished at {report.finished_at}", styles["BodyText"]),
        ]
        if report.invalid_entries:
            story.append(Paragraph("Invalid Entries", styles["Heading2"]))
            for item in report.invalid_entries:
                story.append(
                    Paragraph(json.dumps(item, sort_keys=True), styles["BodyText"])
                )
        if report.chain_breaks:
            story.append(Paragraph("Chain Breaks", styles["Heading2"]))
            for item in report.chain_breaks:
                story.append(
                    Paragraph(json.dumps(item, sort_keys=True), styles["BodyText"])
                )
        doc.build(story)
        return stream.getvalue()

    @staticmethod
    def _metadata(exporter, rows, query) -> dict[str, Any]:
        return {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exporter": exporter,
            "entry_count": len(rows),
            "range": {
                "start": None if not rows else int(rows[0]["sequence_number"]),
                "end": None if not rows else int(rows[-1]["sequence_number"]),
                "date_from": None if query is None else query.date_from or None,
                "date_to": None if query is None else query.date_to or None,
            },
        }


class AuditExportScheduler:
    def __init__(
        self, exporter: AuditLogExporter, export_directory: Path | str
    ) -> None:
        self.exporter = exporter
        self.export_directory = Path(export_directory)

    def run_if_due(self, now: datetime | None = None) -> Path | None:
        period = self.exporter.logger.config.scheduled_export
        if period == "disabled":
            return None
        now = now or datetime.now(timezone.utc)
        last_row = self.exporter.logger.db.execute(
            "SELECT setting_value FROM settings WHERE setting_key = ?;",
            ("audit_last_scheduled_export",),
        ).fetchone()
        if last_row is not None:
            last = datetime.fromisoformat(str(last_row[0]))
            intervals = {
                "daily": timedelta(days=1),
                "weekly": timedelta(days=7),
                "monthly": timedelta(days=30),
            }
            if now - last < intervals[period]:
                return None
        self.export_directory.mkdir(parents=True, exist_ok=True)
        destination = self.export_directory / f"audit-{now:%Y%m%d-%H%M%S}.json.enc"
        path = self.exporter.export(
            destination,
            "json",
            encrypt=True,
            master_password_confirmed=True,
        )
        self.exporter.logger.db.execute(
            """
            INSERT INTO settings (setting_key, setting_value, encrypted)
            VALUES (?, ?, 0)
            ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value;
            """,
            ("audit_last_scheduled_export", now.isoformat()),
        )
        self.delete_expired(now)
        return path

    def delete_expired(self, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(days=self.exporter.logger.config.export_retention_days)
        removed = 0
        if not self.export_directory.exists():
            return removed
        for path in self.export_directory.glob("audit-*.enc"):
            modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            if modified < cutoff:
                path.unlink()
                removed += 1
        return removed
