from __future__ import annotations

import json
import time
import tracemalloc

import pytest

from src.core.audit import AuditLogExporter, AuditQuery


def _create_events(logger, count: int) -> None:
    for index in range(count):
        logger.log_event(
            "LOAD_EVENT" if index % 2 else "AUTH_LOGIN_FAILURE",
            severity="WARN" if index % 2 == 0 else "INFO",
            source="performance_test",
            details={"index": index, "result": "blocked"},
            user_id="local_user",
        )


def test_signed_json_export_can_be_verified_independently(secure_audit, tmp_path):
    _db, key_manager, logger = secure_audit
    _create_events(logger, 20)
    exporter = AuditLogExporter(logger, key_manager)
    path = exporter.export(
        tmp_path / "audit.json",
        "json",
        encrypt=False,
        master_password_confirmed=True,
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    report = AuditLogExporter.verify_signed_json(path.read_bytes())

    assert payload["format"] == "cryptosafe-signed-audit-v1"
    assert payload["metadata"]["exporter"] == "local_user"
    assert payload["public_keys"]
    assert all(item["signature"] for item in payload["entries"])
    assert report.verified


def test_encrypted_export_round_trip(secure_audit, tmp_path):
    _db, key_manager, logger = secure_audit
    _create_events(logger, 5)
    exporter = AuditLogExporter(logger, key_manager)
    path = exporter.export(
        tmp_path / "audit.json.enc",
        "json",
        encrypt=True,
        master_password_confirmed=True,
    )
    export_format, plaintext = exporter.decrypt_payload(path.read_bytes())

    assert export_format == "json"
    assert path.read_bytes().startswith(AuditLogExporter.ENCRYPTED_HEADER)
    assert AuditLogExporter.verify_signed_json(plaintext).verified


def test_export_requires_master_password_confirmation(secure_audit, tmp_path):
    _db, key_manager, logger = secure_audit
    exporter = AuditLogExporter(logger, key_manager)

    with pytest.raises(PermissionError, match="confirmation"):
        exporter.export(tmp_path / "blocked.json", "json")


def test_csv_export_contains_sanitized_records(secure_audit, tmp_path):
    _db, key_manager, logger = secure_audit
    logger.log_event(
        "CSV_EVENT",
        source="unit_test",
        details={"password": "hidden", "result": "ok"},
    )
    path = AuditLogExporter(logger, key_manager).export(
        tmp_path / "audit.csv",
        "csv",
        encrypt=False,
        master_password_confirmed=True,
    )
    content = path.read_text(encoding="utf-8-sig")

    assert "sequence_number" in content
    assert "CSV_EVENT" in content
    assert "hidden" not in content
    assert "[REDACTED]" in content


def test_pdf_export_is_human_readable(secure_audit, tmp_path):
    pytest.importorskip("reportlab")
    _db, key_manager, logger = secure_audit
    _create_events(logger, 8)
    path = AuditLogExporter(logger, key_manager).export(
        tmp_path / "audit.pdf",
        "pdf",
        encrypt=False,
        master_password_confirmed=True,
    )

    assert path.read_bytes().startswith(b"%PDF")
    assert path.stat().st_size > 1_000


def test_ten_thousand_events_meet_logging_query_and_memory_limits(secure_audit):
    _db, _key_manager, logger = secure_audit
    started = time.perf_counter()
    _create_events(logger, 10_000)
    logging_elapsed = time.perf_counter() - started

    tracemalloc.start()
    query_started = time.perf_counter()
    result = logger.query_entries(
        AuditQuery(event_type="LOAD_EVENT", page=1, page_size=50)
    )
    query_elapsed = time.perf_counter() - query_started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    verification_started = time.perf_counter()
    report = logger.verify_integrity(full=False, recent_limit=1_000)
    verification_elapsed = time.perf_counter() - verification_started

    assert logging_elapsed / 10_000 < 0.010
    assert query_elapsed < 0.500
    assert verification_elapsed < 1.0
    assert peak < 50 * 1024 * 1024
    assert result["total"] == 5_000
    assert len(result["entries"]) == 50
    assert report.verified
