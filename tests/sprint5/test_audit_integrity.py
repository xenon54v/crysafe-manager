from __future__ import annotations

import json
import sqlite3
import time

import pytest

from src.core.audit import AuditLogSigner


def test_signed_entry_contains_required_fields_and_redacts_secrets(secure_audit):
    db, _key_manager, logger = secure_audit
    secret = "NeverPersistThisPassword"
    logger.log_event(
        "SECURITY_TEST",
        severity="WARN",
        source="unit_test",
        user_id="student@example.com",
        entry_id="entry-17",
        details={
            "password": secret,
            "api_token": "token-value",
            "email": "student@example.com",
            "query": "private search text",
            "result": "blocked",
        },
    )

    row = db.execute(
        "SELECT * FROM audit_log WHERE event_type = ?;", ("SECURITY_TEST",)
    ).fetchone()
    entry = json.loads(bytes(row["entry_data"]).decode("utf-8"))

    assert {
        "timestamp",
        "event_type",
        "severity",
        "user_id",
        "source",
        "details",
        "entry_id",
        "sequence_number",
        "previous_hash",
    }.issubset(entry)
    assert entry["details"]["password"] == "[REDACTED]"
    assert entry["details"]["api_token"] == "[REDACTED]"
    assert entry["details"]["email"].startswith("sha256:")
    assert entry["details"]["query_hash"].startswith("sha256:")
    assert secret.encode() not in db.path.read_bytes()


def test_signing_key_is_separated_and_only_public_key_is_persisted(secure_audit):
    db, key_manager, logger = secure_audit
    encryption_key = key_manager.get_active_key()
    signing_seed = key_manager.derive_subkey("audit-signing:generation:0", 32)
    row = db.execute("SELECT public_key FROM audit_keys;").fetchone()

    assert signing_seed != encryption_key
    assert bytes(row["public_key"]) != signing_seed
    assert encryption_key not in db.path.read_bytes()
    assert signing_seed not in db.path.read_bytes()
    assert logger.signer.algorithm == "Ed25519"


def test_hash_chain_and_all_signatures_verify(secure_audit):
    _db, _key_manager, logger = secure_audit
    for index in range(25):
        logger.log_event("CHAIN_EVENT", source="unit_test", details={"index": index})

    report = logger.verify_integrity()

    assert report.verified
    assert report.valid_entries == report.total_entries == 26
    assert report.anchor_valid


def test_append_only_triggers_block_update_and_delete(secure_audit):
    db, _key_manager, logger = secure_audit
    logger.log_event("IMMUTABLE_EVENT", source="unit_test")

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute(
            "UPDATE audit_log SET details = ? WHERE event_type = ?;",
            ("changed", "IMMUTABLE_EVENT"),
        )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("DELETE FROM audit_log WHERE event_type = ?;", ("IMMUTABLE_EVENT",))


def test_tampered_entry_is_detected(secure_audit):
    db, _key_manager, logger = secure_audit
    logger.log_event("TAMPER_TARGET", source="unit_test", details={"value": 1})
    db.execute("DROP TRIGGER audit_log_prevent_signed_update;")
    db.execute(
        "UPDATE audit_log SET entry_data = ? WHERE event_type = ?;",
        (b'{"tampered":true}', "TAMPER_TARGET"),
    )

    report = logger.verify_integrity(notify=False)

    assert not report.verified
    assert any(item["reason"] == "hash_mismatch" for item in report.invalid_entries)
    assert db.execute("SELECT COUNT(*) FROM audit_incidents;").fetchone()[0] == 1


def test_tail_truncation_is_detected_by_signed_head_anchor(secure_audit):
    db, _key_manager, logger = secure_audit
    logger.log_event("TAIL_ONE", source="unit_test")
    logger.log_event("TAIL_TWO", source="unit_test")
    db.execute("DROP TRIGGER audit_log_prevent_delete;")
    db.execute(
        "DELETE FROM audit_log WHERE sequence_number = "
        "(SELECT MAX(sequence_number) FROM audit_log);"
    )

    report = logger.verify_integrity(notify=False)

    assert not report.verified
    assert not report.anchor_valid


def test_one_thousand_signatures_verify_in_under_one_second(secure_audit):
    _db, _key_manager, logger = secure_audit
    for index in range(1_000):
        logger.log_event("PERFORMANCE_EVENT", source="unit_test", details={"i": index})

    started = time.perf_counter()
    report = logger.verify_integrity(full=False, recent_limit=1_000)
    elapsed = time.perf_counter() - started

    assert report.verified
    assert report.total_entries == 1_000
    assert elapsed < 1.0


def test_hmac_fallback_signs_and_verifies(secure_audit):
    _db, key_manager, _logger = secure_audit
    signer = AuditLogSigner(key_manager, prefer_ed25519=False)
    data = b"fallback audit record"
    signature = signer.sign(data)

    assert signer.algorithm == "HMAC-SHA256"
    assert signer.verify(data, signature)
    assert not signer.verify(data + b"!", signature)
    signer.clear()
