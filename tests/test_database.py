def test_tables_created(test_db):
    cursor = test_db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
    )

    tables = {row[0] for row in cursor.fetchall()}

    assert "vault_entries" in tables
    assert "audit_log" in tables
    assert "settings" in tables
    assert "key_store" in tables
