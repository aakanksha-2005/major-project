# RASP — Runtime Agent Safety Platform

**Runtime security and authorization layer for LLM applications and tool-using AI agents.**

> **Status: experimental prototype (v0.1.0, Milestone 6) — not production-certified.**
> RASP is not a firewall replacement, a truth detector, or a guarantee against
> prompt injection. See [Known Limitations](docs/LIMITATIONS.md) before relying
> on any control described here.

---

## 1. Project overview and mission

RASP inspects proposed tool calls from a language model, validates their
arguments, enforces explicit permissions, requires human approval when policy
demands it, mediates execution through a trusted boundary, screens results,
and records privacy-conscious audit events.

**Core invariant:** *A model response is an untrusted proposal, never an
authorization decision.* Model-generated text, claimed identities, claimed
approvals, and risk scores cannot override application-enforced permissions.

## 2. Current prototype status

| Milestone | Content | Status |
|---|---|---|
| M0 | Repo baseline, architecture, threat model | ✅ done |
| M1 | Mock model + registry + policy engine + executor + audit + tests | ✅ done |
| M2 | PostgreSQL persistence (SQLAlchemy, Alembic) | ✅ done |
| M3 | Approval decision endpoints, reviewer authz, idempotency, structured logging | ✅ done |
| M4 | Local LLM adapter (OpenAI-compatible + Ollama native) | ✅ done |
| M5 | Adversarial evaluation report with metrics | ✅ done |
| M6 | Controlled pilot preparation (governance docs + machine-checked gate) | ✅ done |

**Implemented now:** deterministic mock model, **local LLM adapters
(OpenAI-compatible and Ollama-native, no cloud credentials)**, 6 synthetic
tools, deterministic
policy engine (allow / deny / require_approval / allow_with_constraints),
controlled executor with timeouts and output validation, PostgreSQL persistence
for audit events, approvals and policy metadata (SQLAlchemy async + Alembic;
`in_memory` remains an explicit opt-out), pseudonymized principals,
digest-bound approvals with a validated state machine and **single-use
consumption**, reviewer decision endpoints (`approve`/`reject`/`revoke`) with
separation of duties and scoped read access, idempotent decisions, structured
JSON logging with request-id correlation, body-size limits, development header
identity, REST API, **a deterministic offline adversarial evaluation harness
with a generated report ([docs/ADVERSARIAL_EVALUATION.md](docs/ADVERSARIAL_EVALUATION.md))**,
**a machine-checked controlled-pilot readiness gate
([docs/PILOT_READINESS.md](docs/PILOT_READINESS.md), [docs/GOVERNANCE.md](docs/GOVERNANCE.md),
[docs/PILOT_PLAN.md](docs/PILOT_PLAN.md))**, and **303 automated tests**
(including 14 that run against a real PostgreSQL instance).

**Planned (not implemented):** rate limiting, real authentication,
multi-instance operation, and a comparative harness that measures real
models' safety behavior.

## 3. Architecture and request lifecycle

```text
Client ─► size-limit middleware ─► FastAPI gateway
   ─► ChatOrchestrator ─► ModelAdapter (mock) ─► text or tool proposal (UNTRUSTED)
        │ text                ─► risk scan + output screening ─► response
        └ tool proposal ─► ControlledExecutor
                              ├─ DENY ──────────────► nothing executes (audited)
                              ├─ REQUIRE_APPROVAL ──► pending record (nothing executes)
                              │                        └ reviewer approves/rejects/revokes
                              │                          (POST /v1/approvals/{id}/…)
                              └─ ALLOW ─► claim approval (approved→consumed, single use)
                                        ─► constraints ─► timeout ─► registered handler
                                        ─► output schema check ─► redaction ─► audit ─► model
```

Full detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 4. Threat model summary

Attacks covered by enforced-and-tested controls: unknown/disabled tool
invocation, argument smuggling, missing permissions, forged approvals,
approval tampering/tampered arguments, executor bypass probes, policy
weakening at startup, policy-engine crash (fail closed), handler failure
and timeout, oversized payloads, audit access control, injection attempts
whose *flags never substitute for authorization*, plus (M3) self-approval,
approval replay/double-execution, unauthorized approval access, and
content leaking into logs.

Explicitly **not** claimed: complete injection detection, tamper-proof
audit, sandboxing of registered handlers, production authentication.
Details: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## 5. Features: implemented vs planned

See status table in §2. Every "implemented" claim is covered by a test in
`tests/` and was executed for this release (**303 passed**, including 14
PostgreSQL-backed tests; 0 skipped when the database is running, and the
PostgreSQL tests **skip with an explicit reason** — never silently — when it
is not). Model-adapter tests are fully offline (injected `httpx.MockTransport`);
the M5 evaluation harness is fully offline and deterministic.

## 6. Supported model adapters

| Adapter | Provider id | Status |
|---|---|---|
| Deterministic mock | `mock` | implemented (default; offline) |
| Local OpenAI-compatible runtime | `local` | **implemented (M4)** — Ollama, LM Studio, llama.cpp, vLLM, … |
| Local Ollama native API | `ollama` | **implemented (M4)** |
| Hosted provider | — | not started; needs explicit authorization |

Setting `RASP_MODEL_PROVIDER` to anything unimplemented **refuses startup**
(no silent fallback). Every adapter implements the same `ModelAdapter`
interface; the local adapters require **no cloud credentials** and contact only
the configured local host. See §13a for configuration and fail-closed behavior.

## 7. Prerequisites

- **Python ≥ 3.12** (developed on 3.14)
- **[uv](https://docs.astral.sh/uv/)** (dependency/env management)
- **Docker** (or a native PostgreSQL ≥ 14) for the default persistent mode
- No API keys or network access are needed. The default test suite still runs
  without PostgreSQL (it uses the explicit `in_memory` mode); only the
  `postgres`-marked tests need a database.

## 8. Local installation (verified)

```powershell
git clone https://github.com/aakanksha-2005/major-project.git
cd major-project
uv sync
```

## 9. Environment configuration

```powershell
Copy-Item .env.example .env   # edit as needed; NEVER commit .env
```

Key settings: `RASP_POLICY_PATH`, `RASP_MODEL_PROVIDER` (`mock` default, or
`local`/`ollama`), `RASP_LOCAL_MODEL_BASE_URL` / `RASP_LOCAL_MODEL_NAME`,
`RASP_MAX_AGENT_STEPS`, `RASP_MAX_REQUEST_BYTES`, `RASP_DEV_AUTH_ENABLED`,
`RASP_PERSISTENCE` (`postgres` default, or explicit `in_memory`),
`RASP_DATABASE_URL` (default `postgresql+asyncpg://rasp:rasp@127.0.0.1:5433/rasp`),
`RASP_LOG_LEVEL` / `RASP_LOG_FORMAT` (`json` default, or `text`; unknown
values refuse startup), `RASP_PILOT_MODE` (`off` default, or `controlled`)
and `RASP_PILOT_ACKNOWLEDGED_GAPS` (required in controlled mode; unknown or
missing ids refuse startup — see §13c).
Full list: [.env.example](.env.example).

## 10. Database initialization and migrations

PostgreSQL is the default persistence layer; `in_memory` is an explicit
opt-out (restart loses everything). The schema is created **only** through
Alembic migrations.

```powershell
docker compose up -d            # PostgreSQL 16 on host port 5433 + rasp_test DB
uv run alembic upgrade head     # create/upgrade the schema (idempotent)
uv run alembic current          # → 0002_approval_consumed (head)
```

Notes:

- Host port **5433** (not 5432) so RASP never collides with an existing local
  PostgreSQL; the compose file and `RASP_DATABASE_URL` must be changed together.
- Development-only credentials (`rasp`/`rasp`) are documented placeholders.
- Audit events, approvals, and policy metadata survive application restarts;
  this was verified end-to-end (chat + denied tool + approval request, restart,
  then `/v1/audit` and the approval row still present).
- **Database failure never authorizes an action**: if the audit write for a
  mutating tool cannot be persisted, the executor denies with
  `reason_code: persistence_error` *before* the handler runs. Read-only tools
  may still run but are flagged `audit_persistence_failed`; `/v1/audit`
  returns a structured `503 persistence_unavailable` instead of crashing.
- Full runbook (backup/restore, failure matrix, test DB safety):
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## 11. Application startup (verified)

```powershell
uv run uvicorn rasp.main:app --reload --host 127.0.0.1 --port 8000
```

Interactive API docs: <http://127.0.0.1:8000/docs>
Health: `GET http://127.0.0.1:8000/v1/health`

## 12. API examples (verified against the running server)

Development identity headers (development-only mechanism — forgeable, local
use only; see §16):

```text
X-Dev-Principal: demo-student
X-Dev-Permissions: system:status,documents:read,announcements:publish
```

**Chat (mock model, deterministic):**

```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8000/v1/chat -Method Post `
  -Headers $h -ContentType "application/json" `
  -Body '{"message":"explain quicksort"}'
```

**Allowed tool with enforced constraints:**

```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8000/v1/tools/execute -Method Post `
  -Headers $h -ContentType "application/json" `
  -Body '{"tool_id":"document_search","arguments":{"query":"binary search","max_results":3}}'
# → 200, outcome "allow_with_constraints", output capped by policy
```

**Disabled tool (deny):**

```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8000/v1/tools/execute -Method Post `
  -Headers $h -ContentType "application/json" `
  -Body '{"tool_id":"record_delete","arguments":{"record_id":"syn-rec-001"}}'
# → 403 {"error":{"code":"tool_disabled",...}}  — handler never runs
```

**Approval-gated tool:**

```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8000/v1/tools/execute -Method Post `
  -Headers $h -ContentType "application/json" `
  -Body '{"tool_id":"publish_announcement","arguments":{"title":"Lab open","body":"Synthetic"}}'
# → 202 {"approval_id":"…"} — nothing executed, pending record created
```

Endpoints: `POST /v1/chat`, `POST /v1/tools/execute`, `GET /v1/tools`,
`GET /v1/audit` (needs `audit:read`), `GET /v1/health`, and the Milestone 3
approval decision API:
`GET /v1/approvals` (needs `approvals:read`; own scope unless
`approvals:review`), `GET /v1/approvals/{id}`,
`POST /v1/approvals/{id}/approve|reject|revoke` (needs `approvals:review`).

**Approval lifecycle (M3):**

```powershell
# The requester parks an approval-gated action (202, nothing executed):
$pending = Invoke-WebRequest -Uri http://127.0.0.1:8000/v1/tools/execute -Method Post `
  -Headers $requester -ContentType "application/json" `
  -Body '{"tool_id":"publish_announcement","arguments":{"title":"Lab open","body":"Synthetic"}}'
$id = ($pending.Content | ConvertFrom-Json).approval_id

# A DIFFERENT principal with approvals:review approves it
# (a requester can never approve their own request → 403 self_review_forbidden):
Invoke-WebRequest -Uri "http://127.0.0.1:8000/v1/approvals/$id/approve" -Method Post `
  -Headers $reviewer          # → 200, status "approved"

# Re-submitting the identical action now executes it EXACTLY once,
# consuming the approval (approved → consumed):
Invoke-WebRequest -Uri http://127.0.0.1:8000/v1/tools/execute -Method Post `
  -Headers $requester -ContentType "application/json" `
  -Body '{"tool_id":"publish_announcement","arguments":{"title":"Lab open","body":"Synthetic"}}'
# → 200 executed

# Replaying the same action never re-executes: it opens a FRESH approval cycle.
# → 202 with a new approval_id
```

## 13. Mock-model demonstration

```powershell
# Deterministic tool-call scenarios (no credentials, no network):
#   scenario: text | call_system_status | call_document_search |
#             call_record_delete | call_publish_announcement |
#             call_application_submit | call_unknown_tool |
#             call_invalid_args | call_oversized_args
Invoke-WebRequest -Uri http://127.0.0.1:8000/v1/chat -Method Post `
  -Headers $h -ContentType "application/json" `
  -Body '{"message":"hi","scenario":"call_record_delete"}'
# → action_status "denied", reason_code "tool_disabled"
```

## 13a. Local LLM adapter (Milestone 4)

RASP can drive a **locally hosted** model instead of the mock, with no cloud
credentials and no egress beyond the configured host:

```powershell
# OpenAI-compatible server (Ollama, LM Studio, llama.cpp --server, vLLM, …):
$env:RASP_MODEL_PROVIDER = "local"
$env:RASP_LOCAL_MODEL_BASE_URL = "http://127.0.0.1:11434"   # /v1 is appended
$env:RASP_LOCAL_MODEL_NAME = "llama3.2"
# Ollama's native API instead:
# $env:RASP_MODEL_PROVIDER = "ollama"
uv run uvicorn rasp.main:app --reload
```

- The adapter posts to `{base_url}/v1/chat/completions`, parses text and
  OpenAI-style `tool_calls` (arguments may be a JSON string or an object), and
  returns the same `ModelResponse` as the mock — still an **untrusted
  proposal**.
- **Fail closed:** any transport error, non-2xx response, malformed JSON, or
  missing field raises `ModelAdapterError`. The chat lifecycle then returns a
  safe message with `security_flags: ["model_unavailable"]`, **no tool call is
  executed**, and no endpoint/credential is leaked. A model outage is never
  treated as authorization.
- Timeouts: `RASP_LOCAL_MODEL_TIMEOUT_SECONDS` (default 30). Optional bearer
  token: `RASP_LOCAL_MODEL_API_KEY` (never logged).
- Tested offline with an injected `httpx.MockTransport` — no network or running
  model is required to run the suite (`tests/unit/test_local_model.py`,
  `tests/integration/test_local_model_api.py`,
  `tests/adversarial/test_local_model_adversarial.py`).

## 13b. Adversarial evaluation harness (Milestone 5)

RASP ships a **reproducible, offline adversarial evaluation harness**: a corpus
of attack scenarios driven through the *real* ASGI pipeline, scored by whether
enforcement contained them, rendered into a committed report.

```powershell
uv run python -m rasp.evaluation.runner            # write report + results
uv run python -m rasp.evaluation.runner --check    # fail if any case failed
```

- **Corpus** (`src/rasp/evaluation/corpus.py`): cases across identity
  escalation, approval forgery/replay/binding/duties, tool & argument
  manipulation, prompt injection, audit-scope escape, and resource exhaustion.
  Each case references the `T-ids` in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Harness** (`harness.py`): drives each case through the app in explicit
  `in_memory` mode. A case counts as **prevented** only when *every* declared
  expectation holds — required statuses, required reason codes, and the guarded
  mutating handler absent from the execution log. A single unmet expectation is
  reported as a **failure**; metrics are derived from those verdicts and cannot
  drift from what ran.
- **Artifacts:** [docs/ADVERSARIAL_EVALUATION.md](docs/ADVERSARIAL_EVALUATION.md)
  (human-readable) and `docs/adversarial_evaluation.json` (machine-readable).
  Tests assert the committed artifacts match a fresh run, and **test the tester**
  (a deliberately-broken case must be reported as a failure).

The current run: **16/16 cases prevented, 0 false allows, 0 false denies.** This
measures whether *RASP's enforcement layer* contains a declared attack; it does
**not** measure a real LLM's propensity to attempt attacks, and a 100% rate is
not a security proof (see [docs/LIMITATIONS.md](docs/LIMITATIONS.md)).

## 13c. Controlled-pilot readiness gate (Milestone 6)

RASP is a prototype. Before any *real* (supervised, synthetic-data-only) pilot,
the operator must pass a **machine-checked gate** that records explicit
acceptance of every documented gap:

```powershell
$env:RASP_PILOT_MODE = "controlled"
$env:RASP_PILOT_ACKNOWLEDGED_GAPS = "dev_identity_not_production_auth,synthetic_data_only_until_auth_and_hardening," +
  "audit_rows_mutable_by_db_credentials,no_log_signing_or_sink_control," +
  "no_live_model_safety_evaluation,no_rate_limiting,single_instance_no_ha," +
  "manual_db_recovery_runbook,human_oversight_required,no_fairness_or_accessibility_evaluation"
uv run uvicorn rasp.main:app
# → refuses to start unless EVERY id above is present and recognized
```

- **Opt-in & fail-closed:** `RASP_PILOT_MODE=off` (default) changes nothing; any
  unknown mode, or an unknown/missing acknowledgement id, **refuses startup**
  (same pattern as `RASP_MODEL_PROVIDER`/`RASP_PERSISTENCE`).
- **No false authority:** passing the gate grants **no** extra permissions —
  enforcement is identical (tested: a disabled tool stays denied in pilot
  mode). It records that a named human accepted the documented gaps.
- **Not a certification.** Real authentication, encryption/backups, and data
  protection remain **hard prerequisites** the gate cannot verify — see
  [docs/PILOT_READINESS.md](docs/PILOT_READINESS.md),
  [docs/PILOT_PLAN.md](docs/PILOT_PLAN.md), and
  [docs/GOVERNANCE.md](docs/GOVERNANCE.md).
- Tests: `tests/unit/test_pilot_readiness.py`.

## 14. Policy configuration

Single YAML file, validated at startup; the app **refuses to start** on
invalid or contradictory security settings (weakened default-deny values,
enabled critical tools without approval, policy/registry mismatches).
Defaults live in [config/policies.example.yaml](config/policies.example.yaml).

```yaml
tools:
  document_search:
    enabled: true
    risk: low
    permission: documents:read
    requires_approval: false
    constraints:
      argument_caps: { max_results: 5 }   # over-cap ⇒ denied
      output_max_items: 5                 # enforced truncation
```

Precedence (documented, deterministic): authentication → unknown tool →
missing policy entry → disabled → invalid args → argument caps →
permission → approval → allow. A deny at any step is final.

## 15. Running automated tests (verified)

```powershell
uv run pytest                  # full suite: 303 passed (with PostgreSQL running)
uv run pytest -m "not postgres"  # 289 passed / 14 skipped — no database required
uv run pytest -m postgres        # 14 passed against rasp_test
uv run pytest tests/unit
uv run pytest tests/integration
uv run pytest tests/adversarial
uv run pytest tests/evaluation
uv run ruff check src tests migrations    # All checks passed
uv run ruff format --check src tests migrations
```

The default suite sets `RASP_PERSISTENCE=in_memory` explicitly, so unit,
integration and adversarial tests need **no** database, model credentials, or
network. PostgreSQL tests live in `tests/postgres/` and are marked `postgres`:
when the server is unreachable they **skip with an explicit reason** ("SKIPPED,
not passed") and are never silently redirected to SQLite or another engine.
They use an isolated `*_test` database and refuse to run destructive fixtures
against any database name lacking "test".

## 16. Security and privacy design

- Default deny; least privilege; independent enforcement in trusted code.
- Fail closed: policy errors deny sensitive actions and are audited; a
  model/provider failure (`ModelAdapterError`) yields a safe `model_unavailable`
  response with no tool execution, never an authorization.
- Audit events are structurally **content-free** (no prompts, arguments,
  or outputs — schema guarantee) with salted pseudonymized principals.
- Local model adapters require no cloud credentials and contact only the
  configured local host; prompts/arguments/outputs are never logged.
- Approvals are digest-bound to the exact action and **single-use**: an
  approval authorizes exactly one execution and is atomically consumed by it.
  Replaying the action never re-executes it.
- **Separation of duties:** a requester can never approve their own request
  (`403 self_review_forbidden`); fail-closed withdrawals (reject/revoke) remain
  available to withdraw authority.
- Structured logs are content-free (identifiers, decisions, reason codes only)
  and carry a request id shared with the audit trail. There is no API that
  accepts prompt/argument/output text for logging.
- Known secret shapes are redacted from tool output and final responses.
- Development identity uses request headers and is **forgeable** — local
  prototype only; real authentication is a prerequisite for any shared use.
- Details: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md),
  [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## 17. Ethics and responsible use

- Synthetic data only; no real personal or public-service records.
- RASP must never be the sole decision-maker for benefits, eligibility,
  legal status, healthcare, policing, or other consequential services.
- A risk score is never evidence of wrongdoing; explanations for denials
  are generic and reviewable by humans.
- Do not claim "jailbreak-proof", "100% secure", "bias-free", or
  "certified" — no such evidence exists for this prototype. The M5 report's
  100% prevention rate means the *documented adversarial corpus* was
  contained, not that RASP is un-breakable.
- Fairness/accessibility evaluation across languages and user groups has
  **not** been performed yet and is required before any real-world pilot.
- Any real pilot must pass the M6 gate and its hard prerequisites
  ([docs/PILOT_READINESS.md](docs/PILOT_READINESS.md),
  [docs/GOVERNANCE.md](docs/GOVERNANCE.md)); passing the gate is not a
  certification.

## 18. Known limitations

Summarized: development-only identity; PostgreSQL fails closed but is a
single unencrypted instance (no HA/signing, `in_memory` remains an opt-out);
pattern-based injection/secret detection is incomplete; no rate limiting; the
local model adapter is fail-closed but real local-model safety behavior is not
yet measured (the M5 harness scores *RASP's enforcement*, not a model's
propensity to attack); approval reviewer authz rests on the same forgeable dev
headers until production authentication lands; single-process prototype. The
M6 pilot gate **records** acceptance of these gaps but does not resolve them.
Full list: [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## 19. Security vulnerability reporting

Do **not** open a public issue for security vulnerabilities. Contact the
repository maintainers privately (GitHub profile of `aakanksha-2005`),
include reproduction steps, affected version/commit, and impact. Expect
acknowledgement before any public disclosure. Fixes ship with a regression
test.

## 20. Contribution and license

- Read [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) first (architecture rules,
  tool-addition checklist, quality gates).
- Small reviewable changes; run `scripts/run_tests.sh` (or the §15 commands)
  before committing; report failures honestly.
- License: Apache-2.0 (see [LICENSE](LICENSE)). Contributors so far:
  `aakanksha-2005` (repository owner), `dilleshwar-17` (development).

---

*Built as a verifiable security control: enforcement lives in trusted
application code, tests measure what is actually prevented, and what
remains unprotected is documented rather than implied.*
