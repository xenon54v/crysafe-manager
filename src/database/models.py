SCHEMA_VERSION = 4

CREATE_TABLES_SQL = [
    """
    CREATE TABLE IF NOT EXISTS vault_entries (
        id TEXT PRIMARY KEY,
        encrypted_data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        tags TEXT
    );
    """,

    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        entry_id TEXT,
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
        key_type TEXT UNIQUE NOT NULL,
        salt BLOB NOT NULL,
        hash TEXT NOT NULL,
        params TEXT,
        version INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """
]

CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at ON vault_entries(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at ON vault_entries(updated_at);",
    "CREATE INDEX IF NOT EXISTS idx_vault_entries_tags ON vault_entries(tags);",

    "CREATE INDEX IF NOT EXISTS idx_audit_entry_id ON audit_log(entry_id);",
    "CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key);",
    "CREATE INDEX IF NOT EXISTS idx_key_store_type ON key_store(key_type);"
]