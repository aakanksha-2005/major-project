#!/usr/bin/env bash
# Run the full RASP quality gate: lint, format check, tests.
set -euo pipefail
cd "$(dirname "$0")/.."
uv run ruff check src tests migrations
uv run ruff format --check src tests migrations
uv run pytest "$@"
