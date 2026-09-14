# CryptoSafe Manager

CryptoSafe Manager is a desktop password manager for the Applied Cryptography course. Sprint 4 adds a secure, cross-platform clipboard to the encrypted Sprint 3 vault.

## Sprint 4 features

- automatic clipboard clearing from 5 seconds to 5 minutes, or an explicit no-timeout mode
- manual clearing and mandatory clearing on replacement, vault lock, logout, and application exit
- Windows `CF_UNICODETEXT`, macOS `NSPasteboard`, Linux Wayland/X11, and `pyperclip` fallback adapters
- Linux support for both `CLIPBOARD` and `PRIMARY` selections
- clipboard ownership monitoring with safe degraded operation when an OS cannot expose access information
- observer-based GUI updates and `ClipboardCopied` / `ClipboardCleared` domain events
- countdown in the status bar, native tray status, non-blocking notifications, and a per-entry activity indicator
- masked clipboard preview with master-password authentication before full reveal
- per-entry “never copy” policy and a “Copy all” context action
- XOR-masked, page-locked process memory with explicit zeroing after clear
- optional session-only in-memory clipboard and Windows anti-screenshot protection
- encrypted clipboard settings with Standard, Secure, and Public Computer profiles
- metadata-only security audit events that never include clipboard values

The system clipboard APIs do not reliably report when another process only reads an unchanged value. CryptoSafe detects ownership/content changes on every platform and provides an explicit access-reporting hook for platform integrations. The Public Computer profile avoids this OS limitation by using the process-isolated in-memory clipboard.

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

Wayland uses `wl-copy` and `wl-paste` when available. X11 uses `xclip` first and then `xsel`. Install one of these native tools for the most reliable Linux behavior.

## Run

```bash
python -m src.main
```

The default development database is `data/cryptosafe_dev.db`. Set `CRYPTOSAFE_DB_PATH` before launch to use another path.

## Clipboard profiles

| Profile | Timeout | Security | Behavior |
| --- | ---: | --- | --- |
| Standard | 30 seconds | Basic | notifications and automatic clear |
| Secure | 15 seconds | Advanced | accelerated clear and blocking after suspicious access |
| Public Computer | 5 seconds | Paranoid | session-only in-memory clipboard and blocking |

## Tests

```bash
python -m pytest -q
```

The Sprint 4 suite covers timer accuracy, Windows/macOS/Linux adapter behavior, encrypted settings, memory masking and zeroing, rapid copy replacement, monitoring, cooperative crash cleanup, audit safety, and performance limits.

## Project structure

```text
src/
  core/
    clipboard/             service, platform adapters, monitor, secure memory
    crypto/                master password and key derivation
    vault/                 encryption, CRUD, generation, search, URL tools
  database/                schema, connection pool, settings and audit repositories
  gui/                     main window, clipboard UI, dialogs, reusable widgets
tests/
  sprint1/
  sprint2/
  sprint3/
  sprint4/
```

Detailed Russian-language code documentation is provided in `docs/CryptoSafe_Manager_Sprint_4_Code_Explanation.docx`.
