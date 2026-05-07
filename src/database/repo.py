from datetime import datetime

from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager

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