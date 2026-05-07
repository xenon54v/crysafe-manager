def test_tables_created(test_db):
    cursor = test_db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
    )

    tables = {row[0] for row in cursor.fetchall()}

    assert "vault_entries" in tables
    assert "audit_log" in tables
    assert "settings" in tables
    assert "key_store" in tables

def test_key_store_has_sprint2_columns(test_db):
    cursor = test_db.execute("PRAGMA table_info(key_store);")
    columns = {row[1] for row in cursor.fetchall()}

    assert "id" in columns
    assert "key_type" in columns
    assert "salt" in columns
    assert "hash" in columns
    assert "params" in columns
    assert "version" in columns
    assert "created_at" in columns


def test_default_settings_created(test_db):
    cursor = test_db.execute(
        """
        SELECT setting_key
        FROM settings;
        """
    )

    settings = {row[0] for row in cursor.fetchall()}

    assert "auto_lock_timeout" in settings
    assert "password_policy_min_length" in settings
    assert "password_policy_require_uppercase" in settings
    assert "password_policy_require_lowercase" in settings
    assert "password_policy_require_digit" in settings
    assert "password_policy_require_special" in settings
    assert "kdf_params_version" in settings