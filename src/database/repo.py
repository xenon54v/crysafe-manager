from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.core.key_manager import KeyManager
from src.core.vault.encryption_service import AESGCMEncryptionService
from src.core.vault.entry_manager import EntryManager


@dataclass(frozen=True)
class _StaticKeyManager:
    key: bytes

    def get_active_key(self) -> bytes:
        return self.key


class VaultRepository:
    """Compatibility facade around the Sprint 3 encrypted entry controller."""

    def __init__(self, db, key_manager: KeyManager | None = None) -> None:
        self.db = db
        self.key_manager = key_manager or KeyManager()
        self.crypto = AESGCMEncryptionService()
        self.entries = EntryManager(
            db, self.key_manager, encryption_service=self.crypto
        )

    def count_entries(self) -> int:
        row = self.db.execute("SELECT COUNT(*) FROM vault_entries;").fetchone()
        return int(row[0])

    def insert_sample_entries(self, master_password: str) -> None:
        if self.count_entries() > 0:
            return
        self.key_manager.unlock_with_password(self.db, master_password)

        samples = (
            {
                "title": "Google",
                "username": "student@example.com",
                "password": "ExampleGooglePassword7!",
                "url": "https://google.com",
                "notes": "Personal account",
                "category": "Personal",
                "tags": ["mail", "personal"],
            },
            {
                "title": "GitHub",
                "username": "student",
                "password": "ExampleGitHubPassword8!",
                "url": "https://github.com",
                "notes": "Study repository",
                "category": "Study",
                "tags": ["code", "study"],
            },
        )
        for sample in samples:
            self.entries.create_entry(sample)

    def add_entry(
        self,
        master_password: str,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
        tags: str,
    ) -> None:
        self.key_manager.unlock_with_password(self.db, master_password)
        self.entries.create_entry(
            {
                "title": title,
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
                "tags": tags,
            }
        )

    def get_entries_for_table(self) -> list[dict[str, Any]]:
        return self.entries.get_all_entries()

    def delete_entry(self, entry_id: str) -> bool:
        return self.entries.delete_entry(str(entry_id), soft_delete=True)

    def get_entry_by_id(self, entry_id: str) -> dict[str, Any] | None:
        return self.entries.get_entry(str(entry_id))

    def update_entry(
        self,
        entry_id: str,
        master_password: str,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
        tags: str,
    ) -> bool:
        self.key_manager.unlock_with_password(self.db, master_password)
        self.entries.update_entry(
            str(entry_id),
            {
                "title": title,
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
                "tags": tags,
            },
        )
        return True

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        self.key_manager.unlock_with_password(self.db, old_password)

        encrypted_rows: list[tuple[str, str, bytes]] = []
        for table in ("vault_entries", "deleted_entries"):
            rows = self.db.execute(
                f"SELECT id, encrypted_data FROM {table} ORDER BY id;"
            ).fetchall()
            encrypted_rows.extend(
                (table, str(row["id"]), row["encrypted_data"]) for row in rows
            )

        plaintext_rows = [
            (
                table,
                entry_id,
                self.crypto.decrypt_entry(
                    encrypted_data,
                    self.key_manager,
                    associated_data=entry_id.encode("utf-8"),
                ),
            )
            for table, entry_id, encrypted_data in encrypted_rows
        ]

        new_salt = self.key_manager.generate_salt()
        new_key = self.key_manager.derive_key(new_password, new_salt)
        new_auth_hash = self.key_manager.create_auth_hash(new_password).hash
        temporary_key_manager = _StaticKeyManager(new_key)
        reencrypted_rows = [
            (
                table,
                entry_id,
                self.crypto.encrypt_entry(
                    payload,
                    temporary_key_manager,
                    associated_data=entry_id.encode("utf-8"),
                ),
            )
            for table, entry_id, payload in plaintext_rows
        ]

        with self.db.transaction():
            for table, entry_id, encrypted_data in reencrypted_rows:
                self.db.execute(
                    f"UPDATE {table} SET encrypted_data = ? WHERE id = ?;",
                    (encrypted_data, entry_id),
                )
            self.db.execute(
                """
                UPDATE key_store
                SET salt = ?, hash = ?, params = ?, version = version + 1
                WHERE key_type = ?;
                """,
                (
                    new_salt,
                    new_auth_hash,
                    self.key_manager._build_key_params(),
                    "master",
                ),
            )

        self.key_manager.activate_key(new_key, new_salt)
        plaintext_rows.clear()
        return True
