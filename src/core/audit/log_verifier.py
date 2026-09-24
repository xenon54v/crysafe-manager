from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar

from .log_signer import AuditLogSigner


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_anchor_payload(sequence_number: int, entry_hash: str, key_id: str) -> bytes:
    return canonical_json(
        {
            "entry_hash": entry_hash,
            "key_id": key_id,
            "sequence_number": sequence_number,
        }
    )


@dataclass
class VerificationReport:
    verified: bool = True
    scope: str = "full"
    total_entries: int = 0
    valid_entries: int = 0
    invalid_entries: list[dict[str, Any]] = field(default_factory=list)
    chain_breaks: list[dict[str, Any]] = field(default_factory=list)
    unsigned_entries: list[int] = field(default_factory=list)
    anchor_valid: bool = True
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLogVerifier:
    REQUIRED_ENTRY_FIELDS: ClassVar[set[str]] = {
        "timestamp",
        "event_type",
        "severity",
        "user_id",
        "source",
        "details",
        "entry_id",
        "sequence_number",
        "previous_hash",
    }

    def __init__(self, db, key_manager=None) -> None:
        self.db = db
        self.key_manager = key_manager

    def verify(
        self,
        start_sequence: int | None = None,
        end_sequence: int | None = None,
        recent_limit: int | None = None,
    ) -> VerificationReport:
        started = time.perf_counter()
        started_at = datetime.now(timezone.utc).isoformat()
        scope = "full"

        if recent_limit is not None:
            if recent_limit < 1:
                raise ValueError("Recent verification limit must be positive.")
            newest = self.db.execute(
                "SELECT MAX(sequence_number) FROM audit_log;"
            ).fetchone()[0]
            if newest is not None:
                start_sequence = max(1, int(newest) - recent_limit + 1)
            scope = f"recent:{recent_limit}"
        elif start_sequence is not None or end_sequence is not None:
            scope = "range"

        rows = self._load_rows(start_sequence, end_sequence)
        report = VerificationReport(
            scope=scope,
            total_entries=len(rows),
            started_at=started_at,
        )
        keys = self._load_keys()
        previous_hash, expected_sequence = self._initial_chain_state(start_sequence)

        for row in rows:
            sequence_number = int(row["sequence_number"])
            if expected_sequence is not None and sequence_number != expected_sequence:
                report.chain_breaks.append(
                    {
                        "sequence": sequence_number,
                        "reason": "sequence_gap",
                        "expected": expected_sequence,
                    }
                )
            expected_sequence = sequence_number + 1

            if row["signature"] is None or row["key_id"] is None:
                report.unsigned_entries.append(sequence_number)
                continue

            entry_data = row["entry_data"]
            if isinstance(entry_data, str):
                entry_data = entry_data.encode("utf-8")
            else:
                entry_data = bytes(entry_data)

            entry_hash = hashlib.sha256(entry_data).hexdigest()
            if entry_hash != row["entry_hash"]:
                report.invalid_entries.append(
                    {"sequence": sequence_number, "reason": "hash_mismatch"}
                )
                previous_hash = str(row["entry_hash"])
                continue

            try:
                entry = json.loads(entry_data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                report.invalid_entries.append(
                    {"sequence": sequence_number, "reason": "invalid_json"}
                )
                previous_hash = str(row["entry_hash"])
                continue

            if not self.REQUIRED_ENTRY_FIELDS.issubset(entry):
                report.invalid_entries.append(
                    {"sequence": sequence_number, "reason": "missing_fields"}
                )
            elif not self._columns_match_entry(row, entry):
                report.invalid_entries.append(
                    {"sequence": sequence_number, "reason": "column_mismatch"}
                )

            if (
                previous_hash is not None
                and entry.get("previous_hash") != previous_hash
            ):
                report.chain_breaks.append(
                    {
                        "sequence": sequence_number,
                        "reason": "previous_hash_mismatch",
                        "expected": previous_hash,
                        "actual": entry.get("previous_hash"),
                    }
                )

            public_key = keys.get(str(row["key_id"]))
            if public_key is None:
                report.invalid_entries.append(
                    {"sequence": sequence_number, "reason": "unknown_signing_key"}
                )
            elif not self._verify_signature(row, public_key, entry_data):
                report.invalid_entries.append(
                    {"sequence": sequence_number, "reason": "invalid_signature"}
                )
            else:
                report.valid_entries += 1

            previous_hash = str(row["entry_hash"])

        if scope == "full":
            report.anchor_valid = self._verify_anchor(rows, keys)

        report.verified = not (
            report.invalid_entries
            or report.chain_breaks
            or report.unsigned_entries
            or not report.anchor_valid
        )
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.duration_seconds = time.perf_counter() - started
        return report

    @classmethod
    def verify_signed_export(cls, bundle: dict[str, Any]) -> VerificationReport:
        started = time.perf_counter()
        report = VerificationReport(
            scope="signed_export",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        entries = list(bundle.get("entries", []))
        keys = {
            str(item["key_id"]): bytes.fromhex(str(item["public_key"]))
            for item in bundle.get("public_keys", [])
            if item.get("algorithm") == AuditLogSigner.ED25519
        }
        report.total_entries = len(entries)
        previous_hash: str | None = None
        expected_sequence: int | None = None

        for item in entries:
            sequence = int(item["sequence_number"])
            if expected_sequence is not None and sequence != expected_sequence:
                report.chain_breaks.append(
                    {
                        "sequence": sequence,
                        "reason": "sequence_gap",
                        "expected": expected_sequence,
                    }
                )
            expected_sequence = sequence + 1
            entry_data = bytes.fromhex(str(item["entry_data_hex"]))
            computed_hash = hashlib.sha256(entry_data).hexdigest()
            if computed_hash != item.get("entry_hash"):
                report.invalid_entries.append(
                    {"sequence": sequence, "reason": "hash_mismatch"}
                )
                continue
            entry = json.loads(entry_data.decode("utf-8"))
            if (
                previous_hash is not None
                and entry.get("previous_hash") != previous_hash
            ):
                report.chain_breaks.append(
                    {"sequence": sequence, "reason": "previous_hash_mismatch"}
                )
            public_key = keys.get(str(item.get("key_id")))
            signature = bytes.fromhex(str(item.get("signature", "")))
            if public_key is None or not AuditLogSigner.verify_ed25519(
                public_key, entry_data, signature
            ):
                report.invalid_entries.append(
                    {"sequence": sequence, "reason": "invalid_signature"}
                )
            else:
                report.valid_entries += 1
            previous_hash = str(item["entry_hash"])

        report.verified = not report.invalid_entries and not report.chain_breaks
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.duration_seconds = time.perf_counter() - started
        return report

    def _load_rows(self, start_sequence, end_sequence):
        conditions = []
        params: list[int] = []
        if start_sequence is not None:
            conditions.append("sequence_number >= ?")
            params.append(int(start_sequence))
        if end_sequence is not None:
            conditions.append("sequence_number <= ?")
            params.append(int(end_sequence))
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        return self.db.execute(
            "SELECT * FROM audit_log" + where + " ORDER BY sequence_number ASC;",
            params,
        ).fetchall()

    def _load_keys(self) -> dict[str, dict[str, Any]]:
        rows = self.db.execute(
            "SELECT key_id, algorithm, public_key, generation FROM audit_keys;"
        ).fetchall()
        return {
            str(row["key_id"]): {
                "algorithm": str(row["algorithm"]),
                "public_key": bytes(row["public_key"]),
                "generation": int(row["generation"]),
            }
            for row in rows
        }

    def _initial_chain_state(
        self, start_sequence: int | None
    ) -> tuple[str | None, int | None]:
        if start_sequence is None or start_sequence <= 1:
            return None, None
        row = self.db.execute(
            "SELECT entry_hash FROM audit_log WHERE sequence_number < ? "
            "ORDER BY sequence_number DESC LIMIT 1;",
            (start_sequence,),
        ).fetchone()
        return (None if row is None else str(row["entry_hash"]), start_sequence)

    def _verify_signature(self, row, key, entry_data: bytes) -> bool:
        try:
            signature = bytes.fromhex(str(row["signature"]))
        except ValueError:
            return False
        if key["algorithm"] == AuditLogSigner.ED25519:
            return AuditLogSigner.verify_ed25519(
                key["public_key"], entry_data, signature
            )
        if key["algorithm"] != AuditLogSigner.HMAC_SHA256 or self.key_manager is None:
            return False
        signer = AuditLogSigner(
            self.key_manager,
            generation=key["generation"],
            prefer_ed25519=False,
        )
        try:
            return signer.verify(entry_data, signature)
        finally:
            signer.clear()

    @staticmethod
    def _columns_match_entry(row, entry: dict[str, Any]) -> bool:
        return (
            int(entry["sequence_number"]) == int(row["sequence_number"])
            and entry["timestamp"] == row["timestamp"]
            and entry["event_type"] == row["event_type"]
            and entry["severity"] == row["severity"]
            and entry["user_id"] == row["user_id"]
            and entry["source"] == row["source"]
            and entry["entry_id"] == row["entry_id"]
            and entry["previous_hash"] == row["previous_hash"]
        )

    def _verify_anchor(self, rows, keys) -> bool:
        state = self.db.execute(
            "SELECT * FROM audit_state WHERE state_id = 1;"
        ).fetchone()
        if not rows:
            return state is not None and int(state["last_sequence"]) == 0
        if state is None:
            return False
        last = rows[-1]
        if (
            int(state["last_sequence"]) != int(last["sequence_number"])
            or state["last_hash"] != last["entry_hash"]
            or state["anchor_signature"] is None
            or state["key_id"] is None
        ):
            return False
        key = keys.get(str(state["key_id"]))
        if key is None or key["algorithm"] != AuditLogSigner.ED25519:
            return False
        payload = build_anchor_payload(
            int(state["last_sequence"]),
            str(state["last_hash"]),
            str(state["key_id"]),
        )
        try:
            signature = bytes.fromhex(str(state["anchor_signature"]))
        except ValueError:
            return False
        return AuditLogSigner.verify_ed25519(key["public_key"], payload, signature)
