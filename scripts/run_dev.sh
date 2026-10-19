#!/usr/bin/env bash
# Start the RASP development server (Milestone 1: mock model, no DB needed).
set -euo pipefail
cd "$(dirname "$0")/.."
uv run uvicorn rasp.main:app --reload --host 127.0.0.1 --port "${RASP_PORT:-8000}"
