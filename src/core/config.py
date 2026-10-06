from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Environment(str, Enum):
    """Supported runtime environments."""

    DEVELOPMENT = "development"
    PRODUCTION = "production"


@dataclass(frozen=True)
class EncryptionSettings:
    """Names and parameters of the configured cryptographic algorithms."""

    scheme: str = "AES-256-GCM"
    kdf: str = "PBKDF2-HMAC-SHA256"
    kdf_params: dict | None = None


@dataclass(frozen=True)
class AppConfig:
    """Resolved application configuration."""

    env: Environment
    db_path: Path
    encryption: EncryptionSettings
    user_prefs: dict


class ConfigManager:
    """Build application configuration from safe defaults and environment values."""

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
        """Resolve paths, cryptographic settings, and user preferences."""

        project_root = Path(__file__).resolve().parents[2]
        default_db = self.default_data_directory(project_root) / (
            "cryptosafe_dev.db"
            if self._env == Environment.DEVELOPMENT
            else "cryptosafe.db"
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

    def default_data_directory(self, project_root: Path | None = None) -> Path:
        """Return a writable data directory for source and packaged execution."""

        if self._env == Environment.DEVELOPMENT and not getattr(sys, "frozen", False):
            root = project_root or Path(__file__).resolve().parents[2]
            return root / "data"

        system = platform.system()
        if system == "Windows":
            base = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
            return base / "CryptoSafe Manager"
        if system == "Darwin":
            return (
                Path.home() / "Library" / "Application Support" / "CryptoSafe Manager"
            )

        base = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        return base / "cryptosafe-manager"
