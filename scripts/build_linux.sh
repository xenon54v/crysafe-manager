#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYINSTALLER_BIN="${PYINSTALLER_BIN:-$PROJECT_DIR/.venv/bin/pyinstaller}"

cd "$PROJECT_DIR"
"$PYINSTALLER_BIN" \
  --noconfirm \
  --clean \
  --distpath release \
  --workpath build/pyinstaller \
  packaging/cryptosafe-manager.spec

release/CryptoSafeManager/cryptosafe-manager --check

