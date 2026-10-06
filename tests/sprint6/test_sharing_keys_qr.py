from __future__ import annotations

import json
import time

import pytest

from src.core.import_export import (
    KeyExchangeService,
    QRCodeService,
    SharePermissions,
    SharingService,
)
from src.core.import_export.errors import QRCodeError, SharingError
from src.core.vault.entry_manager import EntryManagerError


@pytest.mark.parametrize("algorithm,method", [("RSA-2048", "rsa"), ("ECC-P256", "ecc")])
def test_public_key_sharing_and_tamper_detection(populated_vault, algorithm, method):
    _db, _key_manager, entries, created = populated_vault
    key_pair = KeyExchangeService().generate_key_pair(algorithm)
    service = SharingService(entries)
    artifact = service.share_entry(
        created["id"],
        "recipient@example.com",
        method=method,
        recipient_public_key=key_pair.public_key,
        permissions=SharePermissions(edit=True, expires_in_days=3),
    )
    assert b"EntryPassword!42" not in artifact.package
    received = service.receive_share(artifact.package, private_key=key_pair.private_key)
    assert received.entry["password"] == "EntryPassword!42"
    assert received.permissions["edit"] is True

    second = service.share_entry(
        created["id"],
        "recipient@example.com",
        method=method,
        recipient_public_key=key_pair.public_key,
    )
    package = json.loads(second.package)
    package["data"] = package["data"][:-2] + "AA"
    with pytest.raises(SharingError, match="checksum|signature|decryption"):
        service.receive_share(
            json.dumps(package).encode(), private_key=key_pair.private_key
        )


def test_password_share_link_replay_and_read_only(populated_vault):
    _db, _key_manager, entries, created = populated_vault
    service = SharingService(entries)
    artifact = service.share_entry(
        created["id"],
        "Bob",
        method="password",
        password="One-time Share Password!4",
        delivery_method="link",
        permissions=SharePermissions(edit=False),
    )
    assert artifact.delivery_data.startswith(b"cryptosafe://share/")
    received = service.receive_share(
        artifact.delivery_data,
        password="One-time Share Password!4",
        save_to_vault=True,
    )
    assert received.saved_entry_id is not None
    with pytest.raises(EntryManagerError, match="read-only"):
        entries.update_entry(received.saved_entry_id, {"notes": "changed"})
    with pytest.raises(SharingError, match="already been used"):
        service.receive_share(
            artifact.delivery_data, password="One-time Share Password!4"
        )


def test_share_contains_only_selected_fields(populated_vault):
    _db, _key_manager, entries, created = populated_vault
    permissions = SharePermissions(fields=frozenset({"title", "password", "username"}))
    service = SharingService(entries)
    artifact = service.share_entry(
        created["id"],
        "Bob",
        method="password",
        password="Fields Password!4",
        permissions=permissions,
    )
    received = service.receive_share(artifact.package, password="Fields Password!4")
    assert received.entry["notes"] == ""
    assert received.entry["totp_secret"] == ""


def test_contact_fingerprint_verification_rotation_and_revocation(vault):
    db, _key_manager, _entries = vault
    service = KeyExchangeService(db)
    first = service.generate_key_pair("RSA-2048")
    contact_id = service.add_contact("Alice", "alice@example.com", first.public_key)
    assert service.verify_contact_fingerprint(contact_id, first.fingerprint)
    second = service.generate_key_pair("ECC-P256")
    new_fingerprint = service.rotate_contact_key(contact_id, second.public_key)
    assert new_fingerprint == second.fingerprint
    assert service.list_contacts()[0]["verified"] == 0
    old = db.execute(
        "SELECT revoked_at FROM contact_keys WHERE fingerprint = ?;",
        (first.fingerprint,),
    ).fetchone()
    assert old[0] is not None
    service.revoke_contact_key(contact_id)
    assert service.list_contacts() == []
    with pytest.raises(ValueError, match="revoked"):
        service.get_contact_public_key(contact_id)


def test_qr_public_key_chunking_image_scan_and_replay(vault, tmp_path):
    db, _key_manager, _entries = vault
    key_pair = KeyExchangeService().generate_key_pair("ECC-P256")
    service = QRCodeService(db)
    envelope = service.create_payload("public_key", key_pair.public_key)
    chunks = service.encode_chunks(envelope, chunk_size=256)
    assert len(chunks) > 1
    images = service.generate_qr_codes(envelope, chunk_size=1800)
    path = tmp_path / "key.png"
    path.write_bytes(images[0])
    scanned = service.scan_image(path)
    payload = service.decode_chunks([scanned])
    assert payload.payload_type == "public_key"
    assert payload.data == key_pair.public_key
    with pytest.raises(QRCodeError, match="already been used"):
        service.decode_chunks([scanned])


def test_qr_rejects_plaintext_entry_and_detects_chunk_tampering():
    service = QRCodeService()
    with pytest.raises(QRCodeError, match="only encrypted"):
        service.create_payload("encrypted_entry", b'{"entry":{"password":"plain"}}')
    key_pair = KeyExchangeService().generate_key_pair()
    envelope = service.create_payload("public_key", key_pair.public_key)
    chunk = json.loads(service.encode_chunks(envelope)[0])
    chunk["data"] = "A" + chunk["data"][1:]
    with pytest.raises(QRCodeError, match="checksum"):
        service.decode_chunks([json.dumps(chunk)])


def test_qr_generation_and_image_scan_for_one_kilobyte_meet_target(tmp_path):
    service = QRCodeService()
    encrypted_package = json.dumps(
        {
            "encryption": {"algorithm": "AES-256-GCM"},
            "data": "A" * 1024,
        }
    ).encode()
    envelope = service.create_payload("encrypted_entry", encrypted_package)
    started = time.perf_counter()
    images = service.generate_qr_codes(envelope)
    elapsed = time.perf_counter() - started
    assert images and all(image.startswith(b"\x89PNG") for image in images)
    assert elapsed < 0.1
    image_path = tmp_path / "one-kilobyte.png"
    image_path.write_bytes(images[0])
    scanned = service.scan_image(image_path)
    decoded = service.decode_chunks([scanned])
    assert decoded.data == encrypted_package


def test_share_history_and_revocation(populated_vault):
    _db, _key_manager, entries, created = populated_vault
    service = SharingService(entries)
    artifact = service.share_entry(
        created["id"],
        "Bob",
        method="password",
        password="History Password!4",
    )
    assert service.share_history()[0]["shared_id"] == artifact.shared_id
    assert service.revoke_share(artifact.shared_id)
    assert service.share_history()[0]["status"] == "revoked"
