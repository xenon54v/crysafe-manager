from __future__ import annotations

import json

import pytest

from src.core.audit import AuditLogger
from src.core.import_export import (
    ExportOptions,
    ImportOptions,
    KeyExchangeService,
    SharePermissions,
    SharingService,
    VaultExporter,
    VaultImporter,
)
from src.core.import_export.errors import SharingError
from src.gui.exchange_dialogs import (
    ContactsDialog,
    ExportDialog,
    ImportDialog,
    ReceiveShareDialog,
    SharingDialog,
)
from src.gui.qr_viewer import QRCodeViewer

from .conftest import MASTER_PASSWORD


def test_exchange_operations_are_written_to_signed_audit(populated_vault):
    db, key_manager, entries, created = populated_vault
    logger = AuditLogger(db, key_manager)
    try:
        exporter = VaultExporter(entries, key_manager, audit_logger=logger)
        artifact = exporter.export(
            ExportOptions(),
            master_password=MASTER_PASSWORD,
            export_password="Audit Export Password!5",
        )
        VaultImporter(entries, audit_logger=logger).import_data(
            artifact.data,
            ImportOptions(mode="dry_run"),
            password="Audit Export Password!5",
        )
        SharingService(entries, audit_logger=logger).share_entry(
            created["id"],
            "audited-recipient",
            method="password",
            password="Audit Share Password!5",
            permissions=SharePermissions(expires_in_days=1),
        )
        event_types = {
            row[0] for row in db.execute("SELECT event_type FROM audit_log;").fetchall()
        }
        assert {
            "VAULT_EXPORT_COMPLETED",
            "VAULT_IMPORT_DRY_RUN",
            "ENTRY_SHARED",
        } <= event_types
        assert logger.verify_integrity().verified
    finally:
        logger.close()


def test_public_key_share_includes_sender_key_for_reply(populated_vault):
    _db, _key_manager, entries, created = populated_vault
    exchange = KeyExchangeService()
    recipient = exchange.generate_key_pair("RSA-2048")
    sender = exchange.generate_key_pair("ECC-P256")
    artifact = SharingService(entries).share_entry(
        created["id"],
        "recipient",
        method="rsa",
        recipient_public_key=recipient.public_key,
        sender_public_key=sender.public_key,
    )
    assert b'"sender_public_key"' in artifact.package
    tampered = json.loads(artifact.package)
    tampered["sender_public_key"] = "QUJDRA=="
    with pytest.raises(SharingError, match="signature"):
        SharingService(entries).receive_share(
            json.dumps(tampered).encode(), private_key=recipient.private_key
        )


def test_gui_workflow_classes_are_available():
    assert all(
        widget is not None
        for widget in (
            ExportDialog,
            ImportDialog,
            SharingDialog,
            ReceiveShareDialog,
            ContactsDialog,
            QRCodeViewer,
        )
    )
