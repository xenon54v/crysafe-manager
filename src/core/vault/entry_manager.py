from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from src.core.events import EventBus, now_utc
from src.core.key_manager import KeyManager
from src.core.vault.encryption_service import AESGCMEncryptionService
from src.core.vault.password_generator import PasswordGenerator


class EntryManagerError(Exception):
    """Ошибка при выполнении операции с записью хранилища."""


@dataclass
class EntryCreated:
    name: str
    timestamp: str
    entry_id: str


@dataclass
class EntryUpdated:
    name: str
    timestamp: str
    entry_id: str


@dataclass
class EntryDeleted:
    name: str
    timestamp: str
    entry_id: str


class EntryManager:
    """
    Центральный контроллер операций с записями хранилища.

    Отвечает за:
    - создание записи;
    - получение одной записи;
    - получение всех записей;
    - обновление записи;
    - удаление записи.

    Пользовательские поля записи не хранятся в базе открытым текстом.
    Они собираются в JSON, шифруются через AES-256-GCM и сохраняются
    в поле encrypted_data.
    """

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

        self.encryption_service = (
            encryption_service
            if encryption_service is not None
            else AESGCMEncryptionService()
        )

        self.password_generator = (
            password_generator
            if password_generator is not None
            else PasswordGenerator()
        )

    def create_entry(self, data_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Создаёт новую запись хранилища.

        В базу сохраняются только:
        - id;
        - encrypted_data;
        - created_at;
        - updated_at;
        - tags.
        """

        self._validate_entry_data(data_dict)

        entry_id = str(uuid.uuid4())
        created_at = self._utc_now()
        updated_at = created_at

        prepared_data = dict(data_dict)
        prepared_data["created_at"] = created_at
        prepared_data["version"] = prepared_data.get("version", 1)

        tags = prepared_data.get("tags", [])
        tags_text = self._serialize_tags(tags)

        encrypted_data = self.encryption_service.encrypt_entry(
            prepared_data,
            self.key_manager,
            associated_data=entry_id.encode("utf-8"),
        )

        try:
            self.db.execute(
                """
                INSERT INTO vault_entries (
                    id,
                    encrypted_data,
                    created_at,
                    updated_at,
                    tags
                )
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    entry_id,
                    encrypted_data,
                    created_at,
                    updated_at,
                    tags_text,
                ),
            )
            self._commit()

        except Exception as exc:
            self._rollback()
            raise EntryManagerError("Failed to create vault entry.") from exc

        self._publish_event(
            EntryCreated(
                name="EntryCreated",
                timestamp=now_utc(),
                entry_id=entry_id,
            )
        )

        entry = self.get_entry(entry_id)
        if entry is None:
            raise EntryManagerError("Created entry could not be loaded.")

        return entry

    def get_entry(self, entry_id: str) -> dict[str, Any] | None:
        """
        Возвращает одну запись по id.

        При чтении encrypted_data расшифровывается обратно в словарь.
        """

        cursor = self.db.execute(
            """
            SELECT id, encrypted_data, created_at, updated_at, tags
            FROM vault_entries
            WHERE id = ?;
            """,
            (entry_id,),
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_entry(row)

    def get_all_entries(self) -> list[dict[str, Any]]:
        """
        Возвращает все записи хранилища.

        Каждая запись расшифровывается из encrypted_data.
        """

        cursor = self.db.execute(
            """
            SELECT id, encrypted_data, created_at, updated_at, tags
            FROM vault_entries
            ORDER BY updated_at DESC;
            """
        )

        rows = cursor.fetchall()

        entries: list[dict[str, Any]] = []

        for row in rows:
            entries.append(self._row_to_entry(row))

        return entries

    def update_entry(
        self,
        entry_id: str,
        data_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Обновляет существующую запись.

        Старые данные расшифровываются, объединяются с новыми,
        затем снова шифруются и сохраняются в encrypted_data.
        """

        current_entry = self.get_entry(entry_id)

        if current_entry is None:
            raise EntryManagerError("Vault entry was not found.")

        updated_entry = dict(current_entry)
        updated_entry.update(data_dict)

        self._validate_entry_data(updated_entry)

        created_at = current_entry.get("created_at", self._utc_now())
        updated_at = self._utc_now()

        updated_entry["created_at"] = created_at
        updated_entry["updated_at"] = updated_at
        updated_entry["version"] = updated_entry.get("version", 1)

        tags = updated_entry.get("tags", [])
        tags_text = self._serialize_tags(tags)

        encrypted_data = self.encryption_service.encrypt_entry(
            updated_entry,
            self.key_manager,
            associated_data=entry_id.encode("utf-8"),
        )

        try:
            self.db.execute(
                """
                UPDATE vault_entries
                SET encrypted_data = ?,
                    updated_at = ?,
                    tags = ?
                WHERE id = ?;
                """,
                (
                    encrypted_data,
                    updated_at,
                    tags_text,
                    entry_id,
                ),
            )
            self._commit()

        except Exception as exc:
            self._rollback()
            raise EntryManagerError("Failed to update vault entry.") from exc

        self._publish_event(
            EntryUpdated(
                name="EntryUpdated",
                timestamp=now_utc(),
                entry_id=entry_id,
            )
        )

        entry = self.get_entry(entry_id)
        if entry is None:
            raise EntryManagerError("Updated entry could not be loaded.")

        return entry

    def delete_entry(
        self,
        entry_id: str,
        soft_delete: bool = True,
    ) -> bool:
        """
        Удаляет запись.

        Если soft_delete=True, запись переносится в таблицу deleted_entries.
        Если таблицы deleted_entries нет, выполняется обычное удаление.
        """

        current_entry = self.get_entry(entry_id)

        if current_entry is None:
            return False

        try:
            if soft_delete:
                moved = self._try_move_to_deleted_entries(entry_id)

                if not moved:
                    self._delete_permanently(entry_id)
            else:
                self._delete_permanently(entry_id)

            self._commit()

        except Exception as exc:
            self._rollback()
            raise EntryManagerError("Failed to delete vault entry.") from exc

        self._publish_event(
            EntryDeleted(
                name="EntryDeleted",
                timestamp=now_utc(),
                entry_id=entry_id,
            )
        )

        return True

    def generate_password(self, length: int = 20) -> str:
        return self.password_generator.generate(length=length)

    def _row_to_entry(self, row) -> dict[str, Any]:
        entry_id = row[0]
        encrypted_data = row[1]
        created_at = row[2]
        updated_at = row[3]
        tags_text = row[4]

        payload = self.encryption_service.decrypt_entry(
            encrypted_data,
            self.key_manager,
            associated_data=entry_id.encode("utf-8"),
        )

        payload["id"] = entry_id
        payload["created_at"] = payload.get("created_at", created_at)
        payload["updated_at"] = updated_at
        payload["tags"] = payload.get("tags", self._deserialize_tags(tags_text))

        return payload

    def _validate_entry_data(self, data_dict: dict[str, Any]) -> None:
        title = str(data_dict.get("title", "")).strip()
        password = str(data_dict.get("password", "")).strip()

        if not title:
            raise EntryManagerError("Entry title is required.")

        if not password:
            raise EntryManagerError("Entry password is required.")

    def _serialize_tags(self, tags: Any) -> str:
        if tags is None:
            return "[]"

        if isinstance(tags, str):
            tags_list = [
                tag.strip()
                for tag in tags.split(",")
                if tag.strip()
            ]
            return json.dumps(tags_list, ensure_ascii=False)

        if isinstance(tags, list):
            return json.dumps(tags, ensure_ascii=False)

        return json.dumps([], ensure_ascii=False)

    def _deserialize_tags(self, tags_text: str | None) -> list[str]:
        if not tags_text:
            return []

        try:
            tags = json.loads(tags_text)
        except json.JSONDecodeError:
            return [
                tag.strip()
                for tag in tags_text.split(",")
                if tag.strip()
            ]

        if isinstance(tags, list):
            return tags

        return []

    def _try_move_to_deleted_entries(self, entry_id: str) -> bool:
        """
        Пытается выполнить мягкое удаление.

        Если таблица deleted_entries ещё не создана, возвращает False.
        Тогда запись будет удалена обычным способом.
        """

        cursor = self.db.execute(
            """
            SELECT id, encrypted_data, created_at, updated_at, tags
            FROM vault_entries
            WHERE id = ?;
            """,
            (entry_id,),
        )

        row = cursor.fetchone()

        if row is None:
            return False

        try:
            deleted_at = self._utc_now()
            expires_at = (
                datetime.now(timezone.utc) + timedelta(days=30)
            ).isoformat()

            self.db.execute(
                """
                INSERT INTO deleted_entries (
                    id,
                    encrypted_data,
                    created_at,
                    updated_at,
                    deleted_at,
                    expires_at,
                    tags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    deleted_at,
                    expires_at,
                    row[4],
                ),
            )

            self._delete_permanently(entry_id)

            return True

        except Exception:
            return False

    def _delete_permanently(self, entry_id: str) -> None:
        self.db.execute(
            """
            DELETE FROM vault_entries
            WHERE id = ?;
            """,
            (entry_id,),
        )

    def _publish_event(self, event: Any) -> None:
        if self.event_bus is not None:
            self.event_bus.publish(event)

    def _commit(self) -> None:
        if hasattr(self.db, "commit"):
            self.db.commit()
            return

        if hasattr(self.db, "_connection"):
            self.db._connection.commit()

    def _rollback(self) -> None:
        if hasattr(self.db, "rollback"):
            self.db.rollback()
            return

        if hasattr(self.db, "_connection"):
            self.db._connection.rollback()

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()