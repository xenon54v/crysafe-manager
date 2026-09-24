# CryptoSafe Manager

CryptoSafe Manager is a desktop password manager for the Applied Cryptography course. Sprint 5 adds a tamper-evident audit subsystem to the encrypted vault and secure clipboard implemented in Sprints 1-4.

## Sprint 5 features

- Ed25519 signatures with an HMAC-SHA256 fallback
- HKDF key separation with the `audit-signing` context and protected in-memory key material
- monotonic sequence numbers, SHA-256 hash chaining, and a signed head anchor that detects tail truncation
- signing-key generations for forward security and a separate public-key table
- structured UTC events for authentication, vault operations, searches, clipboard activity, system state, security alerts, and configuration changes
- recursive redaction of passwords, secrets, tokens, search text, and personal identifiers
- append-only SQLite triggers for signed records, public keys, incidents, and archives
- automatic migration of Sprint 1-4 audit rows without losing prior events
- full startup verification and configurable 24-hour checks of the most recent 1000 entries
- a separate encrypted incident journal for integrity failures and protection attempts
- an authenticated audit viewer with sorting, advanced filters, full-text search, 50-row pagination, JSON details, signature status, chain visualization, context actions, and dashboard metrics
- signed JSON, CSV, and PDF exports with date-range selection and optional AES-256-GCM encryption
- independent signed-JSON verification, manual verification reports, scheduled exports, retention cleanup, and encrypted database archives
- encrypted audit configuration and master-password confirmation before interactive export

The database prevents normal updates and deletions of signed audit records. Cryptographic verification also detects offline database modification, broken sequence order, changed content, invalid signatures, and removal of the newest records. The protected journal cannot reconstruct data that an attacker deletes from every copy of the database, so operational backups remain necessary.

## Installation on Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Installation on macOS and Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Wayland uses `wl-copy` and `wl-paste` when available. X11 uses `xclip` first and then `xsel`. Install one of these native tools for the most reliable Linux clipboard behavior.

## Run

```bash
python -m src.main
```

The default development database is `data/cryptosafe_dev.db`. Set `CRYPTOSAFE_DB_PATH` before launch to use another path.

## Audit workflow

1. Unlocking the vault derives a generation-specific signing key from the active master key through HKDF.
2. Domain events are converted to structured audit entries by `AuditEventBridge`.
3. `AuditLogger` sanitizes details, links the previous record hash, signs the canonical JSON, and updates the signed head anchor.
4. Startup, periodic, or manual verification checks the sequence, hashes, signatures, public keys, and anchor.
5. A failed check creates an encrypted incident, updates the GUI, and locks the vault when the configured policy requires it.

## Tests

```bash
python -m pytest -q
```

The Sprint 5 suite covers tampering, tail truncation, append-only enforcement, redaction, key separation, forward key generations, 1000-signature verification, 10000-event throughput, indexed queries, viewer memory limits, event integration, encrypted settings, legacy migration, signed JSON verification, CSV/PDF export, encrypted exports, archives, access control, and SQL-injection attempts.

Basic static checks:

```bash
ruff check --select E4,E7,E9,F src tests
```

## Project structure

```text
src/
  core/
    audit/                 logger, signer, verifier, exports and scheduler
    clipboard/             service, platform adapters, monitor, secure memory
    crypto/                master password and key derivation
    vault/                 encryption, CRUD, generation, search, URL tools
  database/                schema, connection pool, settings and compatibility repositories
  gui/                     main window, audit/clipboard UI, dialogs and widgets
tests/
  sprint1/
  sprint2/
  sprint3/
  sprint4/
  sprint5/
```

Detailed Russian-language code documentation is provided in `docs/CryptoSafe_Manager_Sprint_5_Code_Explanation.docx`.
