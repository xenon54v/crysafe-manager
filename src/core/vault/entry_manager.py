from __future__ import annotations

from src.core.events import EventBus
from src.core.key_manager import KeyManager
from src.core.vault.encryption_service import AESGCMEncryptionService
from src.core.vault.password_generator import PasswordGenerator

class EntryManager:
    # Главный контроллер операций с записями хранилища.

    def __init__(
        self,
        db,
        key_manager: KeyManager,
        event_bus: EventBus | None = None,
        encryption_service: AESGCMEncryptionService | None = None,
        password_generator: PasswordGenerator | None = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager
        self.event_bus = event_bus

        self.encryption_service = (
            encryption_service
            if encryption_service is not None
            else AESGCMEncryptionService()
        )

        self.password_generator = (
            password_generator
            if password_generator is not None
            else PasswordGenerator()
        )

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self.encryption_service.encrypt(
            data,
            self.key_manager
        )

    def decrypt_bytes(self, encrypted_data: bytes) -> bytes:
        return self.encryption_service.decrypt(
            encrypted_data,
            self.key_manager
        )

    def generate_password(self, length: int = 16) -> str:
        return self.password_generator.generate(length=length)