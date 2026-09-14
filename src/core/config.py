from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Environment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


@dataclass(frozen=True)
class EncryptionSettings:
    scheme: str = "AES-256-GCM"
    kdf: str = "PBKDF2-HMAC-SHA256"
    kdf_params: dict | None = None


@dataclass(frozen=True)
class AppConfig:
    env: Environment
    db_path: Path
    encryption: EncryptionSettings
    user_prefs: dict


class ConfigManager:
    def __init__(self, env: Environment | None = None) -> None:
        self._env = env or self._detect_env()

    def _detect_env(self) -> Environment:
        raw = os.getenv("CRYPTOSAFE_ENV", Environment.DEVELOPMENT.value).lower()
        return (
            Environment.PRODUCTION
            if raw == Environment.PRODUCTION.value
            else Environment.DEVELOPMENT
        )

    def load(self) -> AppConfig:
        project_root = Path(__file__).resolve().parents[2]
        default_db = (
            project_root
            / "data"
            / (
                "cryptosafe_dev.db"
                if self._env == Environment.DEVELOPMENT
                else "cryptosafe.db"
            )
        )

        db_path = (
            Path(os.getenv("CRYPTOSAFE_DB_PATH", str(default_db)))
            .expanduser()
            .resolve()
        )

        enc = EncryptionSettings(
            scheme=os.getenv("CRYPTOSAFE_ENC_SCHEME", "AES-256-GCM"),
            kdf=os.getenv("CRYPTOSAFE_KDF", "PBKDF2-HMAC-SHA256"),
            kdf_params=None,
        )

        prefs = {
            "language": os.getenv("CRYPTOSAFE_LANG", "en"),
            "theme": os.getenv("CRYPTOSAFE_THEME", "system"),
        }

        return AppConfig(
            env=self._env, db_path=db_path, encryption=enc, user_prefs=prefs
        )
