# CryptoSafe Manager

CryptoSafe Manager is a sprint-based educational project: a cross-platform password manager with GUI, encrypted local database, and modular architecture.

---

## Vision

- Secure local vault (encrypted at rest)
- Modular and extensible architecture
- Event-driven design
- Audit logging and future signature validation
- Clipboard protection and auto-lock
- Backup/restore and packaging support

---

## Sprint Roadmap (8 Sprints)

1. **Foundation** – architecture, DB schema, placeholder crypto, event bus, GUI shell, tests, CI
2. **Key Management** – master password + key derivation + key_store integration
3. **Real Encryption** – replace XOR placeholder with AES-GCM
4. **Clipboard Security** – copy/auto-clear + clipboard events
5. **Audit Signatures** – implement signature validation + viewer
6. **Import/Export** – structured import/export flows
7. **Auto-lock** – inactivity timer + session integration
8. **Packaging & Backup** – finalize backup/restore + Docker/build scripts

---

## Setup (Windows / PowerShell)

Create virtual environment:

```markdown
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

---

## Architecture Overview (MVC-like Separation)

- **Model** → `src/database/`
- **Core (controller-like)** → `src/core/`
- **View** → `src/gui/`

---

## Architecture Diagram (MVC Flow)

```mermaid
flowchart LR
    GUI[GUI Layer\nsrc/gui] --> CORE[Core Layer\nsrc/core]
    CORE --> DB[Database Layer\nsrc/database]
    CORE --> EVT[Event Bus\nsrc/core/events.py]
    EVT --> GUI