from __future__ import annotations

from typing import Optional

# безопасный шаблон

class OSKeychain:
    SERVICE_NAME = "CryptoSafe Manager"

    def __init__(self) -> None:
        try:
            import keyring

            self._keyring = keyring
            self._available = True
        except Exception:
            self._keyring = None
            self._available = False

    def is_available(self) -> bool:
        return self._available and self._keyring is not None

    def save_secret(self, name: str, value: str) -> bool:
        if not self.is_available():
            return False

        try:
            self._keyring.set_password(self.SERVICE_NAME, name, value)
            return True
        except Exception:
            return False

    def load_secret(self, name: str) -> Optional[str]:
        if not self.is_available():
            return None

        try:
            return self._keyring.get_password(self.SERVICE_NAME, name)
        except Exception:
            return None

    def delete_secret(self, name: str) -> bool:
        if not self.is_available():
            return False

        try:
            self._keyring.delete_password(self.SERVICE_NAME, name)
            return True
        except Exception:
            return False