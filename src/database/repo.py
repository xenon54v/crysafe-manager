from datetime import datetime

from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager
from src.core.crypto.placeholder import AES256Placeholder, zero_bytes

class VaultRepository:
    def __init__(self, db):
        self.db = db
        self.crypto = AES256Placeholder()
        self.key_manager = KeyManager()

    def count_entries(self) -> int:
        cursor = self.db.execute("SELECT COUNT(*) FROM vault_entries;")
        return cursor.fetchone()[0]

    def insert_sample_entries(self, master_password: str) -> None:
        if self.count_entries() > 0:
            return

        self.key_manager.unlock_with_password(self.db, master_password)
        now = datetime.now().isoformat()

        samples = [
            {
                "title": "Google",
                "username": "ksenia@gmail.com",
                "password": "mypassword123",
                "url": "https://google.com",
                "notes": "Личный аккаунт",
                "tags": "mail,personal",
            },
            {
                "title": "GitHub",
                "username": "ksenon54",
                "password": "github_secret_2025",
                "url": "https://github.com",
                "notes": "Учебный репозиторий",
                "tags": "code,study",
            },
            {
                "title": "Telegram",
                "username": "@ksenia",
                "password": "telegram_demo_pass",
                "url": "https://web.telegram.org",
                "notes": "Мессенджер",
                "tags": "chat",
            },
        ]

        for item in samples:
            encrypted_password = self.crypto.encrypt(
                item["password"].encode("utf-8"),
                self.key_manager,
            )

            self.db.execute(
                """
                INSERT INTO vault_entries
                (title, username, encrypted_password, url, notes, tags, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    item["title"],
                    item["username"],
                    encrypted_password,
                    item["url"],
                    item["notes"],
                    item["tags"],
                    now,
                    now,
                ),
            )

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

        encrypted_password = self.crypto.encrypt(
            password.encode("utf-8"),
            self.key_manager,
        )

        now = datetime.now().isoformat()

        self.db.execute(
            """
            INSERT INTO vault_entries
            (title, username, encrypted_password, url, notes, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                title,
                username,
                encrypted_password,
                url,
                notes,
                tags,
                now,
                now,
            ),
        )

    def get_entries_for_table(self):
        cursor = self.db.execute(
            """
            SELECT id, title, username, url
            FROM vault_entries
            ORDER BY id;
            """
        )
        return cursor.fetchall()

    def delete_entry(self, entry_id: int) -> bool:
        cursor = self.db.execute(
            """
            DELETE FROM vault_entries
            WHERE id = ?;
            """,
            (entry_id,),
        )

        return cursor.rowcount > 0

    def get_entry_by_id(self, entry_id: int):
        cursor = self.db.execute(
            """
            SELECT id, title, username, encrypted_password, url, notes, tags
            FROM vault_entries
            WHERE id = ?;
            """,
            (entry_id,),
        )

        return cursor.fetchone()

    def update_entry(
        self,
        entry_id: int,
        master_password: str,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
        tags: str,
    ) -> bool:
        self.key_manager.unlock_with_password(self.db, master_password)

        encrypted_password = self.crypto.encrypt(
            password.encode("utf-8"),
            self.key_manager,
        )

        now = datetime.now().isoformat()

        cursor = self.db.execute(
            """
            UPDATE vault_entries
            SET title = ?,
                username = ?,
                encrypted_password = ?,
                url = ?,
                notes = ?,
                tags = ?,
                updated_at = ?
            WHERE id = ?;
            """,
            (
                title,
                username,
                encrypted_password,
                url,
                notes,
                tags,
                now,
                entry_id,
            ),
        )

        return cursor.rowcount > 0

    def change_master_password(
        self,
        old_password: str,
        new_password: str,
    ) -> bool:
        self.key_manager.unlock_with_password(self.db, old_password)

        cursor = self.db.execute(
            """
            SELECT id, encrypted_password
            FROM vault_entries
            ORDER BY id;
            """
        )
        rows = cursor.fetchall()

        decrypted_entries = []

        for entry_id, encrypted_password in rows:
            decrypted_password = bytearray(
                self.crypto.decrypt(
                    encrypted_password,
                    self.key_manager,
                )
            )

            decrypted_entries.append((entry_id, decrypted_password))

        new_salt = self.key_manager.generate_salt()
        new_auth_hash = self.key_manager.create_auth_hash(new_password).hash
        new_key = self.key_manager.derive_key(new_password, new_salt)

        self.key_manager.clear_active_key()
        self.key_manager._active_salt = new_salt
        self.key_manager._active_key = new_key
        self.key_manager.store_key()

        for entry_id, decrypted_password in decrypted_entries:
            new_encrypted_password = self.crypto.encrypt(
                bytes(decrypted_password),
                self.key_manager,
            )

            zero_bytes(decrypted_password)

            self.db.execute(
                """
                UPDATE vault_entries
                SET encrypted_password = ?,
                    updated_at = ?
                WHERE id = ?;
                """,
                (
                    new_encrypted_password,
                    datetime.now().isoformat(),
                    entry_id,
                ),
            )

        self.db.execute(
            """
            UPDATE key_store
            SET salt = ?,
                hash = ?,
                params = ?
            WHERE key_type = ?;
            """,
            (
                new_salt,
                new_auth_hash,
                self.key_manager._build_key_params(),
                "master",
            ),
        )

        return True