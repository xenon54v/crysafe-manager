from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import os


class Environment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


@dataclass(frozen=True)
class EncryptionSettings:
    """
    Placeholder settings for Sprint 1.
    Sprint 2/3 will replace these with real KDF params and AES-GCM settings.
    """
    scheme: str = "XOR_PLACEHOLDER"   # Sprint 1 placeholder
    kdf: str = "PLACEHOLDER_KDF"      # Sprint 1 placeholder
    kdf_params: dict | None = None    # future-ready


@dataclass(frozen=True)
class AppConfig:
    env: Environment
    db_path: Path
    encryption: EncryptionSettings
    user_prefs: dict


class ConfigManager:
    """
    Central config manager (ARC-2).
    - Environment-specific defaults (CFG-3)
    - No hardcoded secrets/keys (SEC-1)
    - Ready to be backed by DB settings table later (CFG-2)
    """

    def __init__(self, env: Environment | None = None) -> None:
        self._env = env or self._detect_env()

    def _detect_env(self) -> Environment:
        raw = os.getenv("CRYPTOSAFE_ENV", Environment.DEVELOPMENT.value).lower()
        return Environment.PRODUCTION if raw == Environment.PRODUCTION.value else Environment.DEVELOPMENT

    def load(self) -> AppConfig:
        # Default DB path depends on environment (CFG-3)
        default_db = Path("data") / ("cryptosafe_dev.db" if self._env == Environment.DEVELOPMENT else "cryptosafe.db")

        db_path = Path(os.getenv("CRYPTOSAFE_DB_PATH", str(default_db))).expanduser().resolve()

        enc = EncryptionSettings(
            scheme=os.getenv("CRYPTOSAFE_ENC_SCHEME", "XOR_PLACEHOLDER"),
            kdf=os.getenv("CRYPTOSAFE_KDF", "PLACEHOLDER_KDF"),
            kdf_params=None,
        )

        prefs = {
            "language": os.getenv("CRYPTOSAFE_LANG", "en"),
            "theme": os.getenv("CRYPTOSAFE_THEME", "system"),
        }

        return AppConfig(env=self._env, db_path=db_path, encryption=enc, user_prefs=prefs)
