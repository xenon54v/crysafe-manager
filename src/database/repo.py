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

    def _derive_sample_key(self, master_password: str) -> bytes:
        sample_salt = b"sample_salt_1234"
        return self.key_manager.derive_key(master_password, sample_salt)

    def insert_sample_entries(self, master_password: str) -> None:
        if self.count_entries() > 0:
            return

        key = self._derive_sample_key(master_password)
        now = datetime.now().isoformat()

        samples = [
            {
                "title": "Google",
                "username": "ksenia@gmail.com",
                "password": "mypassword123",
                "url": "https://google.com",
                "notes": "Личный аккаунт",
                "tags": "mail,personal"
            },
            {
                "title": "GitHub",
                "username": "ksenon54",
                "password": "github_secret_2025",
                "url": "https://github.com",
                "notes": "Учебный репозиторий",
                "tags": "code,study"
            },
            {
                "title": "Telegram",
                "username": "@ksenia",
                "password": "telegram_demo_pass",
                "url": "https://web.telegram.org",
                "notes": "Мессенджер",
                "tags": "chat"
            }
        ]

        for item in samples:
            encrypted_password = self.crypto.encrypt(item["password"].encode("utf-8"), key)

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
                    now
                )
            )

    def add_entry(
        self,
        master_password: str,
        title: str,
        username: str,
        password: str,
        url: str,
        notes: str,
        tags: str
    ) -> None:
        key = self._derive_sample_key(master_password)
        encrypted_password = self.crypto.encrypt(password.encode("utf-8"), key)
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
                now
            )
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