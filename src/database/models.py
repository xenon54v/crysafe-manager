SCHEMA_VERSION = 1


CREATE_TABLES_SQL = [
    """
    CREATE TABLE IF NOT EXISTS vault_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        username TEXT,
        encrypted_password BLOB NOT NULL,
        url TEXT,
        notes TEXT,
        tags TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        entry_id INTEGER,
        details TEXT,
        signature BLOB
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT UNIQUE NOT NULL,
        setting_value BLOB NOT NULL,
        encrypted INTEGER NOT NULL CHECK (encrypted IN (0,1))
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS key_store (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_type TEXT NOT NULL,
        salt BLOB NOT NULL,
        hash BLOB NOT NULL,
        params TEXT
    );
    """
]


CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_vault_title ON vault_entries(title);",
    "CREATE INDEX IF NOT EXISTS idx_audit_entry_id ON audit_log(entry_id);",
    "CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key);"
]
