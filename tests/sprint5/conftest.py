from __future__ import annotations

import pytest

from src.core.audit import AuditLogger
from src.core.key_manager import KeyManager
from src.database.db import Database


@pytest.fixture
def secure_audit(tmp_path):
    db = Database(tmp_path / "audit.db")
    db.connect()
    key_manager = KeyManager()
    key_manager.unlock_with_password(db, "StrongMasterPassword9!")
    logger = AuditLogger(db, key_manager)
    yield db, key_manager, logger
    logger.close()
    db.close()
