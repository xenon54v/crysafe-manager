#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$PROJECT_DIR/.venv/bin/python}"

cd "$PROJECT_DIR"
mkdir -p tests/report
"$PYTHON_BIN" -m pytest -q \
  --cov=src/core \
  --cov=src/database \
  --cov-fail-under=80 \
  --cov-report=term-missing \
  --cov-report=json:tests/report/coverage.json \
  --junitxml=tests/report/junit.xml
"$PYTHON_BIN" scripts/generate_test_report.py \
  --junit tests/report/junit.xml \
  --coverage tests/report/coverage.json \
  --output tests/report/index.html

