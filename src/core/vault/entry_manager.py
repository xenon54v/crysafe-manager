from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from src.core.events import (
    ClipboardCopied,
    EntryCreated,
    EntryDeleted,
    EntryUpdated,
    EventBus,
    now_utc,
)
from src.core.key_manager import KeyManager
from src.core.vault.encryption_service import AESGCMEncryptionService
from src.core.vault.password_generator import PasswordGenerator
from src.core.vault.url_tools import is_valid_url


class EntryManagerError(Exception):
    """Raised when a vault operation cannot be completed safely."""


class EntryManager:
    """Coordinates encrypted CRUD operations for vault entries."""

    DELETION_RETENTION_DAYS = 30

    def __init__(
        self,
        db,
        key_manager: KeyManager,
        event_bus: EventBus | None = None,
        encryption_service: AESGCMEncryptionService | None = None,
        password_generator: PasswordGenerator | None = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager
        self.event_bus = event_bus
        self.encryption_service = encryption_service or AESGCMEncryptionService()
        self.password_generator = password_generator or PasswordGenerator()

    def create_entry(self, data_dict: dict[str, Any]) -> dict[str, Any]:
        prepared = self._normalize_entry_data(data_dict)
        self._validate_entry_data(prepared)

        entry_id = str(uuid.uuid4())
        created_at = self._utc_now()
        prepared["created_at"] = created_at
        prepared["version"] = int(prepared.get("version", 1))
        encrypted_data = self.encryption_service.encrypt_entry(
            prepared,
            self.key_manager,
            associated_data=entry_id.encode("utf-8"),
        )

        try:
            with self._transaction(write=True):
                self.db.execute(
                    """
                    INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at, tags)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (
                        entry_id,
                        encrypted_data,
                        created_at,
                        created_at,
                        self._serialize_tags(prepared["tags"]),
                    ),
                )
        except Exception as exc:
            raise EntryManagerError("Vault operation could not be completed.") from exc

        self._publish_event(EntryCreated("EntryCreated", now_utc(), entry_id))
        entry = self.get_entry(entry_id)
        if entry is None:
            raise EntryManagerError("Vault operation could not be completed.")
        return entry

    def get_entry(self, entry_id: str) -> dict[str, Any] | None:
        try:
            with self._transaction(write=False):
                return self._get_entry(entry_id)
        except EntryManagerError:
            raise
        except Exception as exc:
            raise EntryManagerError("Vault operation could not be completed.") from exc

    def get_all_entries(self) -> list[dict[str, Any]]:
        try:
            with self._transaction(write=False):
                rows = self.db.execute(
                    """
                    SELECT id, encrypted_data, created_at, updated_at, tags
                    FROM vault_entries
                    ORDER BY updated_at DESC;
                    """
                ).fetchall()
                return [self._row_to_entry(row) for row in rows]
        except Exception as exc:
            raise EntryManagerError("Vault operation could not be completed.") from exc

    def update_entry(
        self,
        entry_id: str,
        data_dict: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            with self._transaction(write=True):
                current = self._get_entry(entry_id)
                if current is None:
                    raise EntryManagerError("Vault operation could not be completed.")

                merged = dict(current)
                merged.update(data_dict)
                prepared = self._normalize_entry_data(merged)
                self._validate_entry_data(prepared)

                updated_at = self._utc_now()
                prepared["created_at"] = current["created_at"]
                encrypted_data = self.encryption_service.encrypt_entry(
                    prepared,
                    self.key_manager,
                    associated_data=entry_id.encode("utf-8"),
                )
                result = self.db.execute(
                    """
                    UPDATE vault_entries
                    SET encrypted_data = ?, updated_at = ?, tags = ?
                    WHERE id = ?;
                    """,
                    (
                        encrypted_data,
                        updated_at,
                        self._serialize_tags(prepared["tags"]),
                        entry_id,
                    ),
                )
                if result.rowcount != 1:
                    raise EntryManagerError("Vault operation could not be completed.")
        except EntryManagerError:
            raise
        except Exception as exc:
            raise EntryManagerError("Vault operation could not be completed.") from exc

        self._publish_event(EntryUpdated("EntryUpdated", now_utc(), entry_id))
        entry = self.get_entry(entry_id)
        if entry is None:
            raise EntryManagerError("Vault operation could not be completed.")
        return entry

    def delete_entry(self, entry_id: str, soft_delete: bool = True) -> bool:
        try:
            with self._transaction(write=True):
                row = self.db.execute(
                    """
                    SELECT id, encrypted_data, created_at, updated_at, tags
                    FROM vault_entries
                    WHERE id = ?;
                    """,
                    (entry_id,),
                ).fetchone()
                if row is None:
                    return False

                if soft_delete:
                    deleted_at = self._utc_now()
                    expires_at = (
                        datetime.now(timezone.utc)
                        + timedelta(days=self.DELETION_RETENTION_DAYS)
                    ).isoformat()
                    self.db.execute(
                        """
                        INSERT INTO deleted_entries (
                            id, encrypted_data, created_at, updated_at,
                            deleted_at, expires_at, tags
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            self._value(row, "id", 0),
                            self._value(row, "encrypted_data", 1),
                            self._value(row, "created_at", 2),
                            self._value(row, "updated_at", 3),
                            deleted_at,
                            expires_at,
                            self._value(row, "tags", 4),
                        ),
                    )

                result = self.db.execute(
                    "DELETE FROM vault_entries WHERE id = ?;",
                    (entry_id,),
                )
                if result.rowcount != 1:
                    raise EntryManagerError("Vault operation could not be completed.")
        except EntryManagerError:
            raise
        except Exception as exc:
            raise EntryManagerError("Vault operation could not be completed.") from exc

        self._publish_event(EntryDeleted("EntryDeleted", now_utc(), entry_id))
        return True

    def purge_expired_deleted_entries(self) -> int:
        try:
            with self._transaction(write=True):
                result = self.db.execute(
                    "DELETE FROM deleted_entries WHERE expires_at <= ?;",
                    (self._utc_now(),),
                )
                return max(0, result.rowcount)
        except Exception as exc:
            raise EntryManagerError("Vault operation could not be completed.") from exc

    def generate_password(self, **options) -> str:
        return self.password_generator.generate(**options)

    def get_clipboard_value(
        self,
        entry_id: str,
        field: str = "password",
        *,
        publish_event: bool = True,
    ) -> str:
        if field not in {"password", "username", "notes", "totp_secret", "all"}:
            raise EntryManagerError("Vault operation could not be completed.")

        entry = self.get_entry(entry_id)
        if entry is None:
            raise EntryManagerError("Vault operation could not be completed.")

        sharing_metadata = entry.get("sharing_metadata", {})
        if bool(sharing_metadata.get("never_copy_to_clipboard", False)):
            raise EntryManagerError("Clipboard copying is disabled for this entry.")

        if field == "all":
            values = (
                ("Username", entry.get("username", "")),
                ("Password", entry.get("password", "")),
                ("URL", entry.get("url", "")),
                ("Notes", entry.get("notes", "")),
            )
            value = "\n".join(f"{label}: {item}" for label, item in values if item)
        else:
            value = str(entry.get(field, ""))
        if not value:
            raise EntryManagerError("The selected field is empty.")
        if publish_event:
            self._publish_event(
                ClipboardCopied("ClipboardCopied", now_utc(), entry_id, field)
            )
        return value

    def _get_entry(self, entry_id: str) -> dict[str, Any] | None:
        row = self.db.execute(
            """
            SELECT id, encrypted_data, created_at, updated_at, tags
            FROM vault_entries
            WHERE id = ?;
            """,
            (entry_id,),
        ).fetchone()
        return None if row is None else self._row_to_entry(row)

    def _row_to_entry(self, row) -> dict[str, Any]:
        entry_id = str(self._value(row, "id", 0))
        payload = self.encryption_service.decrypt_entry(
            self._value(row, "encrypted_data", 1),
            self.key_manager,
            associated_data=entry_id.encode("utf-8"),
        )
        payload["id"] = entry_id
        payload["created_at"] = payload.get(
            "created_at", self._value(row, "created_at", 2)
        )
        payload["updated_at"] = self._value(row, "updated_at", 3)
        if not isinstance(payload.get("tags"), list):
            payload["tags"] = self._deserialize_tags(self._value(row, "tags", 4))
        return payload

    def _normalize_entry_data(self, data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise EntryManagerError("Entry data must be a dictionary.")

        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        if not isinstance(tags, list):
            raise EntryManagerError("Tags must be a list or comma-separated text.")

        sharing_metadata = data.get("sharing_metadata", {})
        if sharing_metadata is None:
            sharing_metadata = {}
        if not isinstance(sharing_metadata, dict):
            raise EntryManagerError("Sharing metadata must be a dictionary.")

        return {
            "title": str(data.get("title", "")).strip(),
            "username": str(data.get("username", "")).strip(),
            "password": str(data.get("password", "")),
            "url": str(data.get("url", "")).strip(),
            "notes": str(data.get("notes", "")),
            "category": str(data.get("category", "")).strip(),
            "tags": [str(tag).strip() for tag in tags if str(tag).strip()],
            "totp_secret": str(data.get("totp_secret", "")).strip(),
            "sharing_metadata": sharing_metadata,
            "created_at": str(data.get("created_at", "")),
            "version": int(data.get("version", 1)),
        }

    def _validate_entry_data(self, data: dict[str, Any]) -> None:
        if not data["title"]:
            raise EntryManagerError("Entry title is required.")
        if not data["password"].strip():
            raise EntryManagerError("Entry password is required.")
        if not is_valid_url(data["url"]):
            raise EntryManagerError("Entry URL is invalid.")
        if data["version"] < 1:
            raise EntryManagerError("Entry version is invalid.")

    @contextmanager
    def _transaction(self, write: bool) -> Iterator[None]:
        transaction = getattr(self.db, "transaction", None)
        if callable(transaction):
            with transaction(write=write):
                yield
            return

        try:
            yield
        except Exception:
            if hasattr(self.db, "rollback"):
                self.db.rollback()
            raise
        else:
            if hasattr(self.db, "commit"):
                self.db.commit()

    def _publish_event(self, event) -> None:
        if self.event_bus is not None:
            self.event_bus.publish(event)

    @staticmethod
    def _serialize_tags(tags: list[str]) -> str:
        return json.dumps(tags, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _deserialize_tags(tags_text: str | None) -> list[str]:
        if not tags_text:
            return []
        try:
            value = json.loads(tags_text)
        except json.JSONDecodeError:
            value = [tag.strip() for tag in tags_text.split(",") if tag.strip()]
        return value if isinstance(value, list) else []

    @staticmethod
    def _value(row, name: str, index: int):
        try:
            return row[name]
        except (IndexError, KeyError, TypeError):
            return row[index]

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()
