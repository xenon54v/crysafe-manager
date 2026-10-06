from __future__ import annotations

from typing import Optional


class OSKeychain:
    """Small fault-tolerant adapter around the operating-system keyring."""

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
        """Return whether a usable keyring backend was loaded."""

        return self._available and self._keyring is not None

    def save_secret(self, name: str, value: str) -> bool:
        """Store a secret and report failure without exposing backend errors."""

        if not self.is_available():
            return False

        try:
            self._keyring.set_password(self.SERVICE_NAME, name, value)
            return True
        except Exception:
            return False

    def load_secret(self, name: str) -> Optional[str]:
        """Load a secret or return ``None`` when the backend is unavailable."""

        if not self.is_available():
            return None

        try:
            return self._keyring.get_password(self.SERVICE_NAME, name)
        except Exception:
            return None

    def delete_secret(self, name: str) -> bool:
        """Delete a secret and return whether the operation succeeded."""

        if not self.is_available():
            return False

        try:
            self._keyring.delete_password(self.SERVICE_NAME, name)
            return True
        except Exception:
            return False
