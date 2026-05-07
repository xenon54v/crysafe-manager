from pathlib import Path

from src.database.db import Database
from src.database.repo import VaultRepository


def test_password_change_reencrypts_vault_entries(tmp_path: Path):
    db_path = tmp_path / "test_rotation.db"

    db = Database(db_path)
    db.connect()

    repo = VaultRepository(db)

    old_password = "OldPassword123!"
    new_password = "NewPassword456!"

    for i in range(10):
        repo.add_entry(
            master_password=old_password,
            title=f"Service {i}",
            username=f"user{i}",
            password=f"secret-password-{i}",
            url=f"https://service{i}.example.com",
            notes="test note",
            tags="test"
        )

    assert repo.count_entries() == 10

    before_rows = db.execute(
        """
        SELECT id, encrypted_password
        FROM vault_entries
        ORDER BY id;
        """
    ).fetchall()

    changed = repo.change_master_password(
        old_password=old_password,
        new_password=new_password,
    )

    assert changed is True

    after_rows = db.execute(
        """
        SELECT id, encrypted_password
        FROM vault_entries
        ORDER BY id;
        """
    ).fetchall()

    assert before_rows != after_rows

    repo.key_manager.lock()
    repo.key_manager.unlock_with_password(db, new_password)

    rows = repo.get_entries_for_table()
    assert len(rows) == 10

    repo.key_manager.lock()

    try:
        repo.key_manager.unlock_with_password(db, old_password)
        assert False, "Old password should not unlock vault after rotation"
    except ValueError:
        pass

    db.close()