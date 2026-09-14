# CryptoSafe Manager

CryptoSafe Manager is a desktop password manager for the Applied Cryptography course. Sprint 3 provides encrypted vault CRUD operations, password generation, search, filtering, and a CustomTkinter interface.

## Sprint 3 features

- AES-256-GCM encryption for every entry with a unique 12-byte nonce
- authentication of each encrypted BLOB and the entry ID through associated data
- SQLite storage without plaintext credential columns
- connection pooling and transactional create, read, update, and delete operations
- soft deletion with a 30-day expiration timestamp
- configurable password generator with strength checks and recent-password history
- multi-select table, password visibility controls, context actions, sorting, resizing, and column reordering
- real-time full-text and fuzzy search with field-specific filters
- category, date, tag, and password-strength filtering
- future fields for TOTP and sharing metadata
- clipboard events and automatic clipboard clearing prepared for Sprint 4

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

## Run

```bash
python -m src.main
```

The default development database is `data/cryptosafe_dev.db`. Set `CRYPTOSAFE_DB_PATH` before launch to use another path.

## Search syntax

Search checks the title, username, URL, notes, category, and tags. Typographical errors are tolerated for words of at least three characters.

```text
github
primry
title:"work"
username:student tag:study
```

The interface also provides category, date, and password-strength filters. The last 10 queries remain available during the unlocked session.

## Tests

```bash
python -m pytest -q
```

The Sprint 3 suite covers encryption integrity, CRUD transactions, rollback, connection pooling, concurrent operations, 10,000 generated passwords, search behavior, and the required 1,000-entry performance checks.

## Project structure

```text
src/
  core/
    crypto/                 master password and key derivation
    vault/                  encryption, CRUD, generation, search, URL tools
  database/                 schema, connection pool, repositories, audit log
  gui/                      main window, entry dialogs, reusable widgets
tests/
  sprint1/
  sprint2/
  sprint3/
```

Detailed code documentation is provided in `docs/CryptoSafe_Manager_Sprint_3_Code_Explanation.docx`.
