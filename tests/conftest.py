import pytest
from pathlib import Path
from src.database.db import Database


@pytest.fixture
def test_db(tmp_path):
    db_path = tmp_path / "test.db"
    db = Database(db_path)
    db.connect()
    yield db
    db.close()
