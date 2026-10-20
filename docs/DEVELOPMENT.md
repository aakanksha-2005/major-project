# RASP — Development Guide

**Stack:** Python ≥3.12 (developed on 3.14), FastAPI, Pydantic 2.x,
jsonschema, SQLAlchemy 2.x async + asyncpg (PostgreSQL), Alembic,
pytest, ruff.

## 1. Setup

```powershell
# from the repository root
uv sync            # creates .venv and installs runtime + dev dependencies
# PostgreSQL for the default persistent mode (and the postgres-marked tests):
docker compose up -d
uv run alembic upgrade head
```

No API keys or network access are required. Tests do **not** require a
database (the default suite forces the explicit `in_memory` mode); only the
`postgres`-marked tests do.

## 2. Run the application

```powershell
uv run uvicorn rasp.main:app --reload --host 127.0.0.1 --port 8000
```

Interactive docs: <http://127.0.0.1:8000/docs>

Bash equivalent: `scripts/run_dev.sh`.

## 3. Quality gates (run before every commit)

```powershell
uv run pytest                 # full suite (needs PostgreSQL for the last 14)
uv run pytest -m "not postgres"  # everything that runs without a database
uv run pytest -m postgres     # isolated rasp_test database only
uv run ruff check src tests migrations   # lint
uv run ruff format src tests migrations  # format
```

Individual groups:

```powershell
uv run pytest tests/unit
uv run pytest tests/integration
uv run pytest tests/adversarial
uv run pytest tests/postgres
```

## 4. Configuration

Copy `.env.example` to `.env` and adjust `RASP_*` variables. Important
security-relevant settings:

| Variable | Default | Notes |
|---|---|---|
| `RASP_POLICY_PATH` | `config/policies.example.yaml` | startup fails on invalid policy |
| `RASP_MODEL_PROVIDER` | `mock` | only `mock` implemented; others refuse startup |
| `RASP_MAX_AGENT_STEPS` | `3` | tool-loop budget |
| `RASP_MAX_REQUEST_BYTES` | `1000000` | 413 beyond this |
| `RASP_DEV_AUTH_ENABLED` | `true` | development header identity |
| `RASP_STORE_PRINCIPAL_IDS` | `false` | keep false: audit pseudonymization |
| `RASP_PERSISTENCE` | `postgres` | `in_memory` is an explicit, documented opt-out |
| `RASP_DATABASE_URL` | `postgresql+asyncpg://rasp:rasp@127.0.0.1:5433/rasp` | never commit real credentials |
| `RASP_DATABASE_STATEMENT_TIMEOUT_MS` | `5000` | hung queries become denials |
| `RASP_DATABASE_POOL_SIZE` / `_POOL_TIMEOUT` | `5` / `5.0` | asyncpg pool sizing |
| `RASP_LOG_LEVEL` | `INFO` | unknown values refuse startup |
| `RASP_LOG_FORMAT` | `json` | `json` or `text`; unknown values refuse startup |

## 5. Identity headers (development only)

```http
X-Dev-Principal: your-name
X-Dev-Permissions: documents:read,system:status,audit:read
```

Missing headers ⇒ zero permissions ⇒ everything sensitive is denied
(fail closed). This is not production authentication.

## 6. Architecture rules (enforced in code review)

1. **Never** call a tool handler except through `ControlledExecutor`.
2. Model output is untrusted: no code path may read permissions, roles,
   or approvals from message text.
3. New tools require: registry definition + policy entry + schema +
   tests (positive and negative). Startup refuses mismatches.
4. Security fixes require a regression test in the same change.
5. Audit events must never gain content fields (prompt/args/outputs). The
   same rule applies to logs: log identifiers, decisions, and reason codes —
   never content. There is deliberately no log API that accepts content.
6. Deny paths must fail closed; no "just this once" fallbacks.
7. Approval decisions require separation of duties (requester ≠ approver) and
   single-use consumption (claim before execute); never introduce a path that
   reaches a handler on an approved action without claiming the record first.

## 7. Adding a tool (checklist)

1. Implement a pure handler in `src/rasp/tools/builtin.py` (no network,
   no shell, no SQL, no filesystem writes in demo tools).
2. Register a `ToolDefinition` in `container.builtin_tool_definitions()`
   with input/output JSON Schema, permission, risk, approval flag.
3. Add a matching entry to `config/policies.example.yaml`.
4. Tests: unit (engine allow/deny for it), integration (execute endpoint),
   and a negative case (missing permission / disabled / bad args).
5. Run the full suite.

## 8. Testing strategy

- **Unit** — components in isolation (engine, registry, executor with
  counter handlers, approval digests/state machine/lifecycle/claim,
  approval concurrency, audit/redaction, logging formatter, fail-closed
  persistence doubles).
- **Integration** — full ASGI app via httpx; no network, no DB, no keys.
  Includes an unreachable-database suite proving handlers are never reached,
  the approval decision API (authz, scoping, idempotency, forging), and the
  structured-logging content canaries.
- **Adversarial** — injection, impersonation, tampering, bypass, size
  limits, approval forging/replay/self-approval, log content; every assertion
  proves enforcement or flags the gap honestly.
- **PostgreSQL** (`tests/postgres/`, marker `postgres`) — real database:
  clean migration state (head `0002_approval_consumed`), restart durability
  (incl. consumed approvals), approval transitions, race-safe claim,
  duplicate-pending idempotency, durable decision audit events, audit scoping,
  content-free storage.
- The default suite forces `RASP_PERSISTENCE=in_memory` (see
  `tests/conftest.py`) so it stays runnable without infrastructure.
- PostgreSQL tests **skip with an explicit reason** when unreachable — never
  a silent pass or a substitute engine. Destructive fixtures refuse to run
  unless the database name contains "test".

## 9. Migrations

The schema is defined once in `migrations/versions/`; never create tables by
hand or at import time.

```powershell
uv run alembic upgrade head        # apply
uv run alembic current             # verify revision
uv run alembic revision -m "..."   # new empty revision for the next change
```

`migrations/env.py` reads the URL from `RASP_DATABASE_URL` (nothing secret in
`alembic.ini`) and runs through the async engine, so the same asyncpg driver
serves the app and migrations. After any model change, update the migration
and re-run the full suite with PostgreSQL up.

## 10. Contribution workflow

1. Inspect existing code before changing it; preserve others' work.
2. Small, reviewable commits; explain security-relevant decisions in the
   commit message.
3. Run lint, format, and tests; report failures honestly — never claim
   unrun results.
4. Update `docs/LIMITATIONS.md` when a limitation changes.
