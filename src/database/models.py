SCHEMA_VERSION = 6

ZERO_HASH = "0" * 64

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
    CREATE TABLE IF NOT EXISTS deleted_entries (
        id TEXT PRIMARY KEY,
        encrypted_data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        deleted_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        tags TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_keys (
        key_id TEXT PRIMARY KEY,
        algorithm TEXT NOT NULL,
        public_key BLOB NOT NULL,
        generation INTEGER NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        retired_at TEXT
    );
    """,
    f"""
    CREATE TABLE IF NOT EXISTS audit_log (
        sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
        id INTEGER UNIQUE,
        action TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL
            CHECK (severity IN ('INFO', 'WARN', 'ERROR', 'CRITICAL')),
        user_id TEXT NOT NULL,
        source TEXT NOT NULL,
        entry_id TEXT,
        details TEXT NOT NULL DEFAULT '{{}}',
        previous_hash TEXT NOT NULL DEFAULT '{ZERO_HASH}',
        entry_data BLOB NOT NULL,
        entry_hash TEXT NOT NULL,
        signature TEXT,
        key_id TEXT,
        algorithm TEXT NOT NULL DEFAULT 'UNSIGNED',
        FOREIGN KEY (key_id) REFERENCES audit_keys(key_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_state (
        state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
        last_sequence INTEGER NOT NULL DEFAULT 0,
        last_hash TEXT NOT NULL,
        key_id TEXT,
        anchor_signature TEXT,
        signing_generation INTEGER NOT NULL DEFAULT 0,
        integrity_status TEXT NOT NULL DEFAULT 'UNKNOWN',
        last_verified_at TEXT,
        last_rotation_at TEXT,
        last_archived_sequence INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (key_id) REFERENCES audit_keys(key_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_incidents (
        incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        details BLOB NOT NULL,
        checksum TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_archives (
        archive_id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        start_sequence INTEGER NOT NULL,
        end_sequence INTEGER NOT NULL,
        entry_count INTEGER NOT NULL,
        encrypted_data BLOB NOT NULL,
        format_version INTEGER NOT NULL DEFAULT 1,
        checksum TEXT NOT NULL,
        UNIQUE (start_sequence, end_sequence)
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
    """,
]

CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at ON vault_entries(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at ON vault_entries(updated_at);",
    "CREATE INDEX IF NOT EXISTS idx_vault_entries_tags ON vault_entries(tags);",
    "CREATE INDEX IF NOT EXISTS idx_deleted_entries_deleted_at ON deleted_entries(deleted_at);",
    "CREATE INDEX IF NOT EXISTS idx_deleted_entries_expires_at ON deleted_entries(expires_at);",
    "CREATE INDEX IF NOT EXISTS idx_deleted_entries_tags ON deleted_entries(tags);",
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);",
    "CREATE INDEX IF NOT EXISTS idx_audit_sequence ON audit_log(sequence_number);",
    "CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);",
    "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_entry_id ON audit_log(entry_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_incident_timestamp ON audit_incidents(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key);",
    "CREATE INDEX IF NOT EXISTS idx_key_store_type ON key_store(key_type);",
]

CREATE_TRIGGERS_SQL = [
    """
    CREATE TRIGGER IF NOT EXISTS audit_log_prevent_signed_update
    BEFORE UPDATE ON audit_log
    WHEN OLD.signature IS NOT NULL OR NEW.signature IS NULL
    BEGIN
        SELECT RAISE(ABORT, 'signed audit entries are immutable');
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_log_prevent_delete
    BEFORE DELETE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit entries are append-only');
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_keys_prevent_update
    BEFORE UPDATE ON audit_keys
    BEGIN
        SELECT RAISE(ABORT, 'audit keys are immutable');
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_keys_prevent_delete
    BEFORE DELETE ON audit_keys
    BEGIN
        SELECT RAISE(ABORT, 'audit keys are append-only');
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_incidents_prevent_update
    BEFORE UPDATE ON audit_incidents
    BEGIN
        SELECT RAISE(ABORT, 'audit incidents are immutable');
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_incidents_prevent_delete
    BEFORE DELETE ON audit_incidents
    BEGIN
        SELECT RAISE(ABORT, 'audit incidents are append-only');
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_archives_prevent_update
    BEFORE UPDATE ON audit_archives
    BEGIN
        SELECT RAISE(ABORT, 'audit archives are immutable');
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_archives_prevent_delete
    BEFORE DELETE ON audit_archives
    BEGIN
        SELECT RAISE(ABORT, 'audit archives are append-only');
    END;
    """,
]
