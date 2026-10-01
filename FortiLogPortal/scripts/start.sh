#!/usr/bin/env bash
# Alternativa Linux/macOS (desenvolvimento)
set -e
cd "$(dirname "$0")/.."
[ -d .venv ] || { python3 -m venv .venv; .venv/bin/pip install -r requirements.txt; }
[ -f config/.env ] || cp config/.env.example config/.env
exec .venv/bin/python backend/run.py "$@"
