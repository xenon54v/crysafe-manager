from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from src.database.exchange_repo import ExchangeRepository

from .crypto import (
    canonical_json,
    decrypt_payload_with_password,
    decrypt_payload_with_private_key,
    encrypt_payload_with_password,
    encrypt_payload_with_public_key,
)
from .errors import ImportValidationError, SharingError


@dataclass(frozen=True)
class SharePermissions:
    """Store share permissions values."""

    read: bool = True
    edit: bool = False
    expires_in_days: int = 7
    fields: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"title", "username", "password", "url", "notes", "category", "tags"}
        )
    )

    def __post_init__(self) -> None:
        if not self.read:
            raise ValueError("A shared entry must grant read access.")
        if not 1 <= self.expires_in_days <= 30:
            raise ValueError("Share expiration must be between 1 and 30 days.")
        allowed = {
            "title",
            "username",
            "password",
            "url",
            "notes",
            "category",
            "tags",
            "totp_secret",
        }
        if not self.fields <= allowed or not {"title", "password"} <= self.fields:
            raise ValueError("Share fields must include title and password.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "read": self.read,
            "edit": self.edit,
            "expires_in_days": self.expires_in_days,
            "fields": sorted(self.fields),
        }


@dataclass(frozen=True)
class ShareArtifact:
    """Store share artifact values."""

    shared_id: str
    package: bytes
    delivery_data: bytes
    delivery_method: str
    encryption_method: str
    expires_at: str
    checksum: str


@dataclass(frozen=True)
class ReceivedShare:
    """Represent received share behavior."""

    shared_id: str
    entry: dict[str, Any]
    permissions: dict[str, Any]
    sharer: str
    recipient: str
    expires_at: str
    saved_entry_id: str | None = None


class SharingService:
    """Creates single-entry packages that never reuse the vault encryption key."""

    def __init__(self, entry_manager, *, db=None, audit_logger=None) -> None:
        self.entry_manager = entry_manager
        self.db = db or entry_manager.db
        self.audit_logger = audit_logger
        self.repository = ExchangeRepository(self.db)

    def share_entry(
        self,
        entry_id: str,
        recipient: str,
        *,
        method: str,
        permissions: SharePermissions | None = None,
        sharer: str = "local_user",
        password: str | None = None,
        recipient_public_key: bytes | None = None,
        sender_public_key: bytes | None = None,
        delivery_method: str = "file",
    ) -> ShareArtifact:
        permissions = permissions or SharePermissions()
        if method not in {"password", "rsa", "ecc"}:
            raise SharingError("Sharing method must be password, rsa, or ecc.")
        if delivery_method not in {"file", "qr", "link"}:
            raise SharingError("Delivery method must be file, qr, or link.")
        recipient = recipient.strip()
        if not recipient:
            raise SharingError("Recipient information is required.")
        entry = self.entry_manager.get_entry(entry_id)
        if entry is None:
            raise SharingError("The selected entry was not found.")

        shared_id = str(uuid.uuid4())
        created = datetime.now(timezone.utc)
        expires = created + timedelta(days=permissions.expires_in_days)
        nonce = secrets.token_urlsafe(18)
        header = {
            "version": "1.0",
            "cryptosafe_share": True,
            "shared_id": shared_id,
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
            "sharer": sharer,
            "recipient": recipient,
            "permissions": permissions.to_dict(),
            "nonce": nonce,
            "sender_public_key": (
                base64.b64encode(sender_public_key).decode("ascii")
                if sender_public_key is not None
                else None
            ),
        }
        selected_entry = {
            key: value for key, value in entry.items() if key in permissions.fields
        }
        plaintext = canonical_json({"entry": selected_entry})
        associated_data = canonical_json(header)
        try:
            if method == "password":
                if not password:
                    raise SharingError("A share password is required.")
                encrypted = encrypt_payload_with_password(
                    plaintext,
                    password,
                    key_size=32,
                    associated_data=associated_data,
                )
            else:
                if recipient_public_key is None:
                    raise SharingError("The recipient public key is required.")
                encrypted = encrypt_payload_with_public_key(
                    plaintext,
                    recipient_public_key,
                    associated_data=associated_data,
                    sender_public_key=None,
                )
                algorithm = str(encrypted["encryption"]["algorithm"])
                if method == "rsa" and not algorithm.startswith("RSA-"):
                    raise SharingError("An RSA public key is required for RSA sharing.")
                if method == "ecc" and not algorithm.startswith("ECDH-"):
                    raise SharingError(
                        "A P-256 public key is required for ECC sharing."
                    )
            package_dict = {**header, **encrypted}
            package = json.dumps(
                package_dict, ensure_ascii=False, sort_keys=True, indent=2
            ).encode("utf-8")
            checksum = hashlib.sha256(package).hexdigest()
            encryption_method = str(encrypted["encryption"]["algorithm"])
            delivery_data = (
                self._make_link(package) if delivery_method == "link" else package
            )
            self.repository.add_share(
                shared_id=shared_id,
                original_entry_id=entry_id,
                encryption_method=encryption_method,
                recipient_info=recipient,
                permissions=permissions.to_dict(),
                package_checksum=checksum,
                shared_at=created.isoformat(),
                expires_at=expires.isoformat(),
            )
            self._audit(
                "ENTRY_SHARED",
                "INFO",
                {
                    "entry_id": entry_id,
                    "shared_id": shared_id,
                    "recipient": recipient,
                    "encryption_method": encryption_method,
                    "delivery_method": delivery_method,
                    "expires_at": expires.isoformat(),
                },
                entry_id=entry_id,
            )
            return ShareArtifact(
                shared_id=shared_id,
                package=package,
                delivery_data=delivery_data,
                delivery_method=delivery_method,
                encryption_method=encryption_method,
                expires_at=expires.isoformat(),
                checksum=checksum,
            )
        except SharingError:
            raise
        except Exception as exc:
            self._audit(
                "ENTRY_SHARE_FAILED",
                "ERROR",
                {"entry_id": entry_id, "error_type": type(exc).__name__},
                entry_id=entry_id,
            )
            raise SharingError("The share package could not be created.") from exc
        finally:
            selected_entry.clear()
            entry.clear()

    def receive_share(
        self,
        package_or_link: bytes | str,
        *,
        password: str | None = None,
        private_key: bytes | None = None,
        private_key_password: bytes | None = None,
        save_to_vault: bool = False,
    ) -> ReceivedShare:
        package_bytes = self._package_from_delivery(package_or_link)
        try:
            package = json.loads(package_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SharingError("Share package is not valid JSON.") from exc
        if not isinstance(package, dict) or package.get("cryptosafe_share") is not True:
            raise SharingError("Share package marker is missing.")
        header_keys = {
            "version",
            "cryptosafe_share",
            "shared_id",
            "created_at",
            "expires_at",
            "sharer",
            "recipient",
            "permissions",
            "nonce",
            "sender_public_key",
        }
        header = {key: package.get(key) for key in header_keys}
        try:
            expires = datetime.fromisoformat(str(package["expires_at"]))
        except (KeyError, ValueError) as exc:
            raise SharingError("Share expiration timestamp is invalid.") from exc
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            self._set_status_if_local(str(package.get("shared_id", "")), "expired")
            raise SharingError("Share package has expired.")
        associated_data = canonical_json(header)
        encryption = package.get("encryption")
        if not isinstance(encryption, dict):
            raise SharingError("Share encryption metadata is missing.")
        algorithm = str(encryption.get("algorithm", ""))
        try:
            if algorithm.startswith("AES-"):
                if not password:
                    raise SharingError("A share password is required.")
                plaintext = decrypt_payload_with_password(
                    package, password, associated_data=associated_data
                )
            else:
                if private_key is None:
                    raise SharingError("The recipient private key is required.")
                plaintext = decrypt_payload_with_private_key(
                    package,
                    private_key,
                    private_key_password=private_key_password,
                    associated_data=associated_data,
                )
        except ImportValidationError as exc:
            self._audit(
                "SHARE_PACKAGE_REJECTED",
                "WARN",
                {"shared_id": package.get("shared_id"), "reason": str(exc)},
            )
            raise SharingError(str(exc)) from exc
        nonce = str(package.get("nonce", ""))
        if not nonce or not self.repository.mark_nonce_used(
            nonce, "share", expires.isoformat()
        ):
            raise SharingError("Share package has already been used.")
        try:
            payload = json.loads(plaintext.decode("utf-8"))
            entry = payload["entry"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise SharingError("Decrypted share data is invalid.") from exc
        if not isinstance(entry, dict):
            raise SharingError("Shared entry is invalid.")
        permissions = package.get("permissions")
        if not isinstance(permissions, dict) or not permissions.get("read"):
            raise SharingError("Share permissions are invalid.")
        entry = self._prepare_received_entry(entry, permissions, package)
        saved_entry_id = None
        if save_to_vault:
            created = self.entry_manager.create_entry(entry)
            saved_entry_id = str(created["id"])
            self._set_status_if_local(str(package["shared_id"]), "imported")
        self._audit(
            "SHARED_ENTRY_RECEIVED",
            "INFO",
            {
                "shared_id": package["shared_id"],
                "sharer": package.get("sharer", ""),
                "saved": save_to_vault,
            },
            entry_id=saved_entry_id,
        )
        return ReceivedShare(
            shared_id=str(package["shared_id"]),
            entry=entry,
            permissions=dict(permissions),
            sharer=str(package.get("sharer", "")),
            recipient=str(package.get("recipient", "")),
            expires_at=expires.isoformat(),
            saved_entry_id=saved_entry_id,
        )

    def revoke_share(self, shared_id: str) -> bool:
        changed = self.repository.set_share_status(shared_id, "revoked")
        if changed:
            self._audit("ENTRY_SHARE_REVOKED", "INFO", {"shared_id": shared_id})
        return changed

    def share_history(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return self.repository.list_shares(limit=limit)

    @staticmethod
    def _prepare_received_entry(
        entry: dict[str, Any],
        permissions: dict[str, Any],
        package: dict[str, Any],
    ) -> dict[str, Any]:
        result = {
            "title": str(entry.get("title", "")),
            "username": str(entry.get("username", "")),
            "password": str(entry.get("password", "")),
            "url": str(entry.get("url", "")),
            "notes": str(entry.get("notes", "")),
            "category": str(entry.get("category", "")),
            "tags": entry.get("tags", []),
            "totp_secret": str(entry.get("totp_secret", "")),
            "version": 1,
            "sharing_metadata": {
                "shared_id": str(package.get("shared_id", "")),
                "sharer": str(package.get("sharer", "")),
                "expires_at": str(package.get("expires_at", "")),
                "read_only": not bool(permissions.get("edit", False)),
            },
        }
        if not result["title"] or not result["password"]:
            raise SharingError("Shared entry is missing required fields.")
        return result

    @staticmethod
    def _make_link(package: bytes) -> bytes:
        token = base64.urlsafe_b64encode(package).rstrip(b"=")
        return b"cryptosafe://share/" + token

    @staticmethod
    def _package_from_delivery(package_or_link: bytes | str) -> bytes:
        raw = (
            package_or_link.encode("utf-8")
            if isinstance(package_or_link, str)
            else bytes(package_or_link)
        )
        prefix = b"cryptosafe://share/"
        if not raw.startswith(prefix):
            return raw
        token = raw[len(prefix) :]
        token += b"=" * (-len(token) % 4)
        try:
            return base64.urlsafe_b64decode(token)
        except (ValueError, TypeError) as exc:
            raise SharingError("Share link is malformed.") from exc

    def _set_status_if_local(self, shared_id: str, status: str) -> None:
        if not shared_id:
            return
        row = self.db.execute(
            "SELECT 1 FROM shared_entries WHERE shared_id = ?;", (shared_id,)
        ).fetchone()
        if row is not None:
            self.repository.set_share_status(shared_id, status)

    def _audit(
        self,
        event: str,
        severity: str,
        details: dict[str, Any],
        *,
        entry_id: str | None = None,
    ) -> None:
        if self.audit_logger is not None:
            self.audit_logger.log_event(
                event,
                severity=severity,
                source="sharing_service",
                details=details,
                user_id="local_user",
                entry_id=entry_id,
            )
