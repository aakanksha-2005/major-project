# Deployment and database operations (Milestone 3)

This document describes the verified PostgreSQL workflow: starting the
database, initializing/migrating the schema, running the application, backing
up and recovering data, and the exact behavior when persistence fails. It also
covers the Milestone 3 structured-logging configuration.

> **Prototype status.** These are development-grade procedures for a
> single-instance prototype. They are not a production runbook: no TLS, no
> connection encryption, documented development credentials, and no HA story.
> See [LIMITATIONS.md](LIMITATIONS.md).

---

## 1. Persistence modes

| `RASP_PERSISTENCE` | Backend | Durable? | Use |
|---|---|---|---|
| `postgres` (default) | PostgreSQL via SQLAlchemy (async) | yes | the target store; audit + approvals + policy metadata survive restarts |
| `in_memory` | bounded buffers | **no** — restart loses everything | explicit opt-out for demos and the documented test strategy |

Any other value **refuses startup** (no silent fallback). Switching modes is a
configuration decision, never something the application does on its own.

The `in_memory` mode is used *explicitly* by the default test suite
(`tests/conftest.py` sets it) so that `uv run pytest` never requires a
database. PostgreSQL-backed tests live in `tests/postgres/`, are marked
`postgres`, and skip with an explicit reason when the server is unreachable —
they are never silently redirected to another engine.

## 2. Starting PostgreSQL

### 2.1 Docker Compose (shipped)

```powershell
docker compose up -d          # starts postgres:16-alpine + creates rasp_test
docker compose ps             # wait for "healthy"
docker compose down           # stop (data volume persists)
docker compose down -v        # stop AND delete all data
```

Details:

- Creates two databases in one container: `rasp` (application) and
  `rasp_test` (isolated test target, see §6).
- **Host port is 5433, not 5432** (`5433:5432` in `docker-compose.yml`) so
  RASP never collides with a PostgreSQL already occupying 5432 on the host.
  If you change it, change `RASP_DATABASE_URL` (and
  `RASP_TEST_DATABASE_URL`) to match.
- Development-only credentials, documented and non-secret:
  user `rasp`, password `rasp`. Change them before any shared deployment and
  keep real credentials out of git (`.env` is git-ignored; `.env.example`
  contains placeholders only).

### 2.2 Native PostgreSQL service

Any PostgreSQL ≥ 14 works: create a database and user, then set
`RASP_DATABASE_URL` accordingly, e.g.
`postgresql+asyncpg://rasp:rasp@127.0.0.1:5433/rasp`.

## 3. Migrations (schema initialization)

Migrations are the **only** way the schema is created
(`migrations/versions/2026_10_19_0001_initial.py`,
`migrations/versions/2026_10_20_0002_approval_consumed.py`; head is
`0002_approval_consumed`):

```powershell
uv run alembic upgrade head              # apply all migrations (connects to RASP_DATABASE_URL)
uv run alembic upgrade head --sql        # print SQL without connecting (offline review)
uv run alembic current                   # show applied revision
uv run alembic downgrade base            # drop everything (destructive; requires review)
```

- The URL comes from `RASP_DATABASE_URL` in the environment — it is **never**
  committed to `alembic.ini`.
- Tables created: `policies` (which policy versions were in force and their
  configuration), `approval_requests` (digest-bound approvals with a status
  CHECK constraint including the `consumed` terminal state, a `consumed_at`
  timestamp, a partial unique index allowing at most one *pending* record per
  exact action, and an `ix_approval_action` lookup index), and `audit_events`
  (sanitized, content-free columns mirroring the `AuditEvent` schema — there is
  no column for prompts, arguments, outputs, credentials, or records).
- Milestone 3 adds revision `0002_approval_consumed` (single-use consumption);
  `alembic upgrade head` brings any prior `0001_initial` database forward.
  `alembic upgrade head` is idempotent; re-running it is safe.

## 4. Application startup (end-to-end quickstart)

```powershell
docker compose up -d
uv run alembic upgrade head
uv run uvicorn rasp.main:app --reload --host 127.0.0.1 --port 8000
```

The engine connects lazily: importing or starting the application does not
require the database to be up *at that instant*, but any action that needs
persistence will fail closed (§5). Statement timeouts
(`RASP_DATABASE_STATEMENT_TIMEOUT_MS`, default 5000 ms) bound every query so
a hung database surfaces as a denial, not a hung request.

To run without a database at all (demo mode):

```powershell
$env:RASP_PERSISTENCE = "in_memory"
uv run uvicorn rasp.main:app --reload
```

## 5. Failure behavior (fail closed — tested)

Database failure **prevents sensitive actions from executing**:

| Situation | Behavior |
|---|---|
| Mutating (non-read-only) tool, audit write fails | **DENY** with `reason_code: persistence_error`; pre-execution authorization event could not be recorded, so the handler never runs |
| Approval-required tool, pending record cannot be persisted | **DENY** with `reason_code: persistence_error` (an unpersistable approval could never be honored) |
| Approval state cannot be read (lookup fails) | **DENY** with `reason_code: persistence_error` (an unknowable approval state is never treated as "no approval") |
| Approval claim fails after approval (concurrent winner / DB outage) | **DENY** (`approval_invalid` or `persistence_error`); the handler never runs and the approval is never over-consumed |
| Read-only tool, post-hoc audit write fails | Executes (documented fallback), response/outcome carries `security_flags: ["audit_persistence_failed"]` |
| Plain chat, request-level audit write fails | Chat still responds; `audit_persistence_failed` flag appears in `security_flags` |
| `GET /v1/audit` or `/v1/approvals`, query fails | Structured **503** `persistence_unavailable` (never an unhandled crash) |

Unit and app-level tests for all of these run *without* PostgreSQL
(`tests/unit/test_persistence_fail_closed.py`,
`tests/integration/test_db_unavailable.py`).

## 6. Test database safety

PostgreSQL-backed tests (`pytest -m postgres`, files under `tests/postgres/`)
use `RASP_TEST_DATABASE_URL` (default
`postgresql+psycopg://rasp:rasp@127.0.0.1:5433/rasp_test`):

- The fixtures **refuse to run** (explicit `pytest.fail`, not a skip) if the
  configured database name does not contain `test` — destructive setup can
  never touch a real database.
- Tables are truncated before each test; the schema is created only through
  `alembic upgrade head`.
- If the server is unreachable, the tests **skip with an explicit reason**
  ("PostgreSQL is unreachable — skipped, not passed"), clearly distinguishable
  from passing tests.

## 7. Backup and recovery

What is stored (and what is deliberately not):

- `audit_events` — identifiers, decisions, digests, timings. **No content.**
- `approval_requests` — approvals bound to action digests + reviewer decisions.
- `policies` — policy metadata/config JSON per version.

Backup (development-grade):

```powershell
# Full logical backup (all three tables + history)
docker compose exec -T postgres pg_dump -U rasp -d rasp -Fc > rasp_backup.dump

# Restore into a fresh database
docker compose exec -T postgres pg_restore -U rasp -d rasp --clean --if-exists < rasp_backup.dump
```

Recovery procedure:

1. Restore the dump (above) **or** start from an empty database.
2. `uv run alembic upgrade head` — brings the schema to the current revision
   (safe against an already-current restore).
3. Start the application; verify `GET /v1/health`.

Honest expectations for this prototype:

- **No point-in-time recovery, no WAL archiving, no replication.** The dump is
  your recovery point; its age is your RPO.
- Audit rows reference `policy_version` as a plain column (no foreign key) so
  forensic writes are never blocked by metadata ordering; approval rows *do*
  reference `policies` (the approval flow always persists policy metadata
  first). If you restore a database without its `policies` rows, approvals
  from older versions may not resolve — restore `policies` together with the
  other tables (a dump includes all of them).
- Losing `approval_requests` means pending approvals are gone: requesters
  must re-submit. Lost approvals never grant execution — the enforcement path
  re-checks approval state at execution time, so an outage degrades to
  denial, never to bypass.

## 8. Operational security notes

- Development credentials (`rasp`/`rasp`) are documented placeholders — never
  commit real ones; `.env` is git-ignored and `.env.example` holds no secrets.
- The application connects as a normal user of one database; grant it only
  what its migrations create (in the compose setup the same user owns both
  `rasp` and `rasp_test` for simplicity — split these for shared environments).
- `pool_pre_ping` recycles dead connections after a database restart; pooling
  and statement timeouts are tunable via `RASP_DATABASE_POOL_SIZE`,
  `RASP_DATABASE_POOL_TIMEOUT`, `RASP_DATABASE_STATEMENT_TIMEOUT_MS`.
- Restarting the database while the app runs is safe: in-flight writes fail
  closed (§5), subsequent checkouts recover automatically.

## 9. Structured logging (Milestone 3)

Configured via `RASP_LOG_LEVEL` (default `INFO`) and `RASP_LOG_FORMAT`
(default `json`, or `text` for local reading). **Unknown values refuse
startup** — there is no silent fallback.

- Every request runs through the request-id middleware
  (`src/rasp/observability/logging.py`), which establishes a request id
  (honouring a well-formed inbound `X-Request-Id`, `^[A-Za-z0-9._-]{1,64}$`),
  echoes it back in the response, and emits **one** access line per request:
  `method`, `path`, `status`, `duration_ms`, and the (pseudonymized) request id.
- Query strings and request/response bodies are **never** logged.
- Application logs contain identifiers, decisions, and reason codes only.
  There is no log API that accepts prompts, tool arguments, outputs, records,
  or credentials — the privacy guarantee holds by construction and is asserted
  by content-canary tests (`tests/integration/test_logging.py`,
  `tests/adversarial/`).
- The handler attaches to the `rasp` logger only; root and uvicorn handlers are
  left untouched, so RASP logs integrate with whatever sink the environment
  provides. Ship them to an access-controlled, appropriately-retained store
  (aggregation is a deployment responsibility).
