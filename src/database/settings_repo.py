from __future__ import annotations

import json
from dataclasses import asdict

from src.core.audit.audit_logger import AuditConfig
from src.core.clipboard.clipboard_service import ClipboardConfig, SecurityLevel
from src.core.vault.encryption_service import (
    AESGCMEncryptionService,
    VaultEncryptionError,
)


class SettingsRepositoryError(RuntimeError):
    """Raised when encrypted application settings cannot be loaded or saved."""


class SettingsRepository:
    CLIPBOARD_KEY = "clipboard_config"
    AUDIT_KEY = "audit_config"

    def __init__(self, db, key_manager) -> None:
        self.db = db
        self.key_manager = key_manager
        self.encryption = AESGCMEncryptionService()

    def load_clipboard_config(self) -> ClipboardConfig:
        row = self.db.execute(
            "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?;",
            (self.CLIPBOARD_KEY,),
        ).fetchone()
        if row is None:
            config = ClipboardConfig.profile("standard")
            self.save_clipboard_config(config)
            return config

        try:
            if int(row[1]) != 1:
                raise SettingsRepositoryError("Clipboard settings are not encrypted.")
            raw = self.encryption.decrypt(
                bytes(row[0]),
                self.key_manager,
                associated_data=self._associated_data(self.CLIPBOARD_KEY),
            )
            data = json.loads(raw.decode("utf-8"))
            return ClipboardConfig(
                timeout_seconds=data.get("timeout_seconds"),
                notifications_enabled=bool(data.get("notifications_enabled", True)),
                security_level=SecurityLevel(data.get("security_level", "basic")),
                application_whitelist=tuple(data.get("application_whitelist", [])),
                block_after_suspicious_access=bool(
                    data.get("block_after_suspicious_access", False)
                ),
                ephemeral_mode=bool(data.get("ephemeral_mode", False)),
            )
        except SettingsRepositoryError:
            raise
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            VaultEncryptionError,
        ) as exc:
            raise SettingsRepositoryError(
                "Clipboard settings are invalid or damaged."
            ) from exc

    def save_clipboard_config(self, config: ClipboardConfig) -> None:
        if not isinstance(config, ClipboardConfig):
            raise TypeError("Clipboard settings must use ClipboardConfig.")
        data = asdict(config)
        data["security_level"] = config.security_level.value
        data["application_whitelist"] = list(config.application_whitelist)
        raw = json.dumps(
            data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        try:
            encrypted = self.encryption.encrypt(
                raw,
                self.key_manager,
                associated_data=self._associated_data(self.CLIPBOARD_KEY),
            )
            self.db.execute(
                """
                INSERT INTO settings (setting_key, setting_value, encrypted)
                VALUES (?, ?, 1)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    encrypted = 1;
                """,
                (self.CLIPBOARD_KEY, encrypted),
            )
        except Exception as exc:
            raise SettingsRepositoryError(
                "Clipboard settings could not be saved."
            ) from exc

    def load_audit_config(self) -> AuditConfig:
        row = self.db.execute(
            "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?;",
            (self.AUDIT_KEY,),
        ).fetchone()
        if row is None:
            config = AuditConfig()
            self.save_audit_config(config)
            return config
        try:
            if int(row[1]) != 1:
                raise SettingsRepositoryError("Audit settings are not encrypted.")
            raw = self.encryption.decrypt(
                bytes(row[0]),
                self.key_manager,
                associated_data=self._associated_data(self.AUDIT_KEY),
            )
            return AuditConfig(**json.loads(raw.decode("utf-8")))
        except SettingsRepositoryError:
            raise
        except (
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            VaultEncryptionError,
        ) as exc:
            raise SettingsRepositoryError(
                "Audit settings are invalid or damaged."
            ) from exc

    def save_audit_config(self, config: AuditConfig) -> None:
        if not isinstance(config, AuditConfig):
            raise TypeError("Audit settings must use AuditConfig.")
        raw = json.dumps(
            asdict(config),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            encrypted = self.encryption.encrypt(
                raw,
                self.key_manager,
                associated_data=self._associated_data(self.AUDIT_KEY),
            )
            self.db.execute(
                """
                INSERT INTO settings (setting_key, setting_value, encrypted)
                VALUES (?, ?, 1)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    encrypted = 1;
                """,
                (self.AUDIT_KEY, encrypted),
            )
        except Exception as exc:
            raise SettingsRepositoryError("Audit settings could not be saved.") from exc

    @classmethod
    def _associated_data(cls, setting_key: str) -> bytes:
        return f"settings:{setting_key}:v1".encode()
