# RASP — Architecture

**Status:** Milestone 6 (mock + local LLM adapters, PostgreSQL persistence,
approval decision API, structured logging, adversarial evaluation harness,
controlled-pilot readiness gate) ·
**Version:** 0.1.0 · **Not production-certified**

## 1. Purpose

RASP (Runtime Agent Safety Platform) is an independent runtime enforcement
layer for LLM applications and tool-using agents. It evaluates proposed
tool calls against explicit, testable policies and mediates execution.

**Core invariant:** *A model response is an untrusted proposal, never an
authorization decision.* No model-generated message, tool-call argument,
claimed identity, claimed approval, or risk score may override
application-enforced permissions.

## 2. Component map

```text
Client (HTTP)
   │  X-Dev-Principal / X-Dev-Permissions  (development identity)
   ▼
Body-size limit middleware ──► 413 on oversized payloads
   ▼
RequestId middleware (observability/) ──► per-request id + one content-free access log line
   ▼
FastAPI gateway (api/) ──► schema validation, error envelope
   │
   ├─ GET  /v1/health          minimal health, no internals
   ├─ POST /v1/chat            mediated request lifecycle
   ├─ GET  /v1/tools           registered tool metadata
   ├─ POST /v1/tools/execute   direct mediated execution
   ├─ GET  /v1/audit           authorized, scoped, paginated events
   └─ approval decision API    (routes_approvals.py)
        ├─ GET  /v1/approvals              scoped list (approvals:read)
        ├─ GET  /v1/approvals/{id}         own record or reviewer (else 404)
        └─ POST /v1/approvals/{id}/approve|reject|revoke  (approvals:review)
   ▼
ChatOrchestrator (gateway/lifecycle.py)
   │  trust labels: system_policy | user | retrieved | tool_output | model
   │  risk scan (supplementary flags only)
   ▼
ModelAdapter (models/)  ── MockModelAdapter (deterministic, M1) / local adapters (M4)
   │  returns text OR tool proposals  ← UNTRUSTED
   ▼
ControlledExecutor (executor/)          ◄── THE enforcement boundary
   │  1. fresh PolicyEngine.evaluate()
   │  2. DENY → audit(not_executed), handler never called
   │  3. REQUIRE_APPROVAL → lookup the effective record for THIS exact action:
   │       • live pending      → stay parked (idempotent, same approval id)
   │       • approved          → re-verify binding, CLAIM (approved→consumed), execute
   │       • rejected/invalid  → engine denies fail-closed
   │       • expired/consumed  → open a FRESH approval cycle
   │  4. ALLOW → constraints → timeout → registered handler only
   │  5. output schema validation → redaction/truncation → audit
   ▼
ToolRegistry (tools/) ── trusted, application-registered handlers only
```

### Cross-cutting

- **Policy engine** (`policy/`) — deterministic, independently testable,
  documented precedence, fail-closed on internal error.
- **Audit** (`audit/`) — pseudonymized principals, structural no-content
  guarantee; PostgreSQL-backed by default (`persistence/`), explicit
  in-memory opt-out (see §5).
- **Approvals** (`approvals/`) — digest-bound records with expiry, a validated
  state machine, single-use consumption (`claim`), reviewer decisions
  (`decide`) with separation of duties, and action-scoped lookup
  (`find_for_action`); PostgreSQL-backed by default.
- **Observability** (`observability/`) — JSON/text structured logging,
  request-id contextvar and middleware; logs carry identifiers and decisions
  only (no content).
- **Model adapters** (`models/`) — one `ModelAdapter` interface with three
  implementations: the deterministic mock (M1) and two local adapters (M4) —
  `LocalOpenAICompatibleAdapter` (`POST {base}/v1/chat/completions`) and
  `OllamaModelAdapter` (native `POST {base}/api/chat`). Local adapters use no
  cloud credentials and contact only the configured host. Any transport error,
  non-2xx response, malformed JSON, or missing field raises
  `ModelAdapterError`; the orchestrator then fails closed
  (`security_flags: ["model_unavailable"]`, no execution). Adapters never log
  prompts, arguments, outputs, endpoints, or credentials.
- **Risk signals** (`risk/`) — supplementary flags; never override authz.
- **Privacy** (`privacy/`) — output screening, redaction, item caps.

## 3. Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| TB1: HTTP identity | header-based dev principal (M1+) | anything in message text |
| TB2: model output | policy + registry code (any adapter, incl. local M4) | model text and tool proposals |
| TB3: tool results | executor validation/screening | handler output content |
| TB4: policy config | validated YAML from disk | runtime API (cannot modify) |
| TB5: approvals | store records + digest math + reviewer decision (M3) | "the user approved" claims anywhere |
| TB6: logs (M3) | RASP emits identifiers/decisions only | log sink access is deployment's concern |

## 4. Request lifecycle (spec §4)

1. Receive request → body-size check → schema validation.
2. Resolve principal from **trusted headers only** (fail closed to a
   zero-permission principal when absent).
3. Generate `request_id`; scan user text for risk indicators (flags only).
4. Invoke model adapter (mock in M1) with a trusted system-policy message
   prepended by the orchestrator — never by the model.
5. Inspect response:
   - **text** → output screening → response;
   - **tool proposal** → executor (steps below) → result fed back to the
     model as explicitly untrusted `tool_output` content.
6. Loop bounded by `RASP_MAX_AGENT_STEPS` (default 3); budget exhaustion
   returns a safe fallback text — no extra tool attempts.
7. Emit audit events for request, decisions, executions, screening.

Executor per-call order: validate identifier → validate arguments (JSON
Schema) → fresh policy decision → deny / pending approval / enforce
constraints → timeout → execute registered handler → validate output
schema → disclosure screening → audit.

## 5. Persistence (Milestone 2)

Persistence sits behind the same small interfaces introduced in Milestone 1;
call sites did not change:

- `AuditService` → `AuditStore` protocol → `PostgresAuditStore` (default) or
  `InMemoryAuditStore` (explicit opt-out)
- `ApprovalStore` → `ApprovalBackend` protocol → `PostgresApprovalBackend`
  (default) or `InMemoryApprovalBackend`

Selected by `RASP_PERSISTENCE` (`postgres` default / `in_memory`). An unknown
value **refuses startup** — there is no silent fallback. The PostgreSQL
implementation uses SQLAlchemy 2.x async + asyncpg, with the schema created
exclusively by Alembic (`alembic upgrade head`). Three tables:

| Table | Contents |
|---|---|
| `policies` | which policy version/config was in force (JSON), persisted lazily on first decision event |
| `approval_requests` | digest-bound approvals; status CHECK constraint (incl. `consumed`); `consumed_at`; partial unique index = at most one **pending** record per exact action; `ix_approval_action` for effective-record lookup |
| `audit_events` | sanitized, content-free columns mirroring the audit schema (no prompts, arguments, outputs, or secrets — there is no column for them) |

Security-relevant properties:

- **Fail closed:** a mutating tool requires its pre-execution
  `TOOL_EXECUTION`/`authorized` audit event to persist *before* the handler
  runs; otherwise the decision is `DENY` with `reason_code: persistence_error`.
  A pending approval that cannot be persisted also denies.
- **Documented fallback:** read-only tools and plain chat may complete when the
  post-hoc audit write fails, but the outcome carries
  `security_flags: ["audit_persistence_failed"]`; `GET /v1/audit` returns a
  structured `503 persistence_unavailable`.
- **Approval state machine** is validated in the facade
  (pending→approved/rejected/expired/invalidated;
  approved→expired/invalidated/consumed; terminal states final) with an
  optimistic status guard in the backend, so concurrent/duplicate transitions
  cannot silently overwrite decisions.
- **Single-use approvals (M3):** an approved record authorizes exactly one
  execution. Before the handler runs, the executor claims it atomically
  (`UPDATE … WHERE status='approved'` → `consumed`, `RETURNING *`); a lost
  race, a revoked approval, or a persistence failure denies the action and the
  handler is never reached. Replay opens a fresh approval cycle.
- **Separation of duties (M3):** the store rejects a request to approve one's
  own approval record (`SelfReviewForbidden` → `403 self_review_forbidden`).
  Fail-closed reject/revoke remain available to withdraw authority.
- **Bounded queries:** statement timeout (`RASP_DATABASE_STATEMENT_TIMEOUT_MS`,
  default 5000 ms) turns a hung database into a denial, not a hung request.
- Engine creation is lazy, so importing the app or building it does not require
  a reachable database; any action that needs persistence then fails closed.

## 6. Failure behavior

| Failure | Behavior |
|---|---|
| Invalid/contradictory policy file | **startup refuses** (`PolicyConfigError`) |
| Unknown `RASP_LOG_LEVEL` / `RASP_LOG_FORMAT` | **startup refuses** (no silent fallback) |
| Unknown/disabled tool, missing permission | DENY before handler |
| Malformed arguments | DENY (`invalid_arguments`) before handler |
| Policy evaluation exception | DENY (`policy_error`) — fail closed, audited |
| Model/provider failure (transport, non-2xx, malformed JSON) | safe `model_unavailable` response, **no tool execution**, no authorization |
| Handler exception / timeout | `failed`/`timeout` result, sanitized category, audited |
| Output schema violation | result withheld (`invalid_tool_output`) |
| Oversized request body | 413 before application code |
| Missing principal headers | zero-permission principal → sensitive actions denied |
| Step budget exceeded | safe fallback text, no further tool calls |
| Database down / write fails (mutating tool) | DENY (`persistence_error`) before handler |
| Approval record cannot be persisted | DENY (`persistence_error`); no pending record |
| Approval state cannot be read / claim fails | DENY (`persistence_error`); handler never runs |
| Approval already consumed / revoked / lost race | DENY (`approval_invalid`); handler never runs |
| Decision requires a different status | 409 `invalid_approval_transition` |
| Requester attempts self-approval | 403 `self_review_forbidden` |
| Audit write fails after a read-only action | completes with `audit_persistence_failed` flag |
| `GET /v1/audit` storage outage | structured 503 `persistence_unavailable` |

## 7. Key modules

| Module | Responsibility |
|---|---|
| `main.py` | app factory; startup validation; logging + middleware wiring |
| `container.py` | component graph; policy/registry consistency check |
| `settings.py` | typed env configuration (`RASP_*`, incl. log level/format) |
| `api/` | routes, error envelope, body-size middleware |
| `api/routes_approvals.py` | approval list/fetch/decision endpoints + authz |
| `observability/logging.py` | JSON/text formatter, request-id middleware/context |
| `auth/dev_identity.py` | development principal resolution (NOT production auth) |
| `models/` | provider-neutral adapter; deterministic mock, local OpenAI-compatible + Ollama adapters (fail closed) |
| `tools/registry.py` | registration, lookup, JSON Schema validation |
| `tools/builtin.py` | six synthetic demo tools + execution log instrumentation |
| `policy/config.py` | YAML load, fail-closed validation |
| `policy/engine.py` | deterministic evaluation, documented precedence |
| `executor/executor.py` | the trusted execution boundary (approval lookup/claim) |
| `gateway/lifecycle.py` | chat loop, step budget, output gateway |
| `approvals/store.py` | approval facade: state machine, decide, claim, lookup |
| `audit/service.py` | pseudonymized, content-free events (backend-agnostic) |
| `persistence/` | SQLAlchemy models, async engine, PostgreSQL audit/approval/policy repositories |
| `privacy/redaction.py` | secret-shape redaction, truncation |
| `risk/signals.py` | injection indicators (defense in depth) |
| `evaluation/` | offline adversarial corpus + harness + report renderer/runner (M5) |
| `pilot/` | controlled-pilot readiness gate (fail-closed mode/acknowledgement validation) (M6) |

## 8. Approval lifecycle (Milestone 3)

```text
requester ──POST /v1/tools/execute──► REQUIRE_APPROVAL → pending record
                                            │  (idempotent per exact action)
reviewer  ──POST /v1/approvals/{id}/approve|reject|revoke──► decide()
                                            │  separation of duties:
                                            │  requester ≠ approver
requester ──POST /v1/tools/execute──► approved record found
                                            │  engine re-verifies digest binding
                                            └─ claim(): approved ─► consumed (atomic)
                                                    └─ handler runs ONCE
replay    ──POST /v1/tools/execute──► consumed record ─► FRESH pending cycle
```

Authorization matrix (`rasp/api/routes_approvals.py`):

| Caller | List / fetch | Decide |
|---|---|---|
| no approval permission | 403 `forbidden` | 403 `forbidden` |
| `approvals:read` only | own records; others → 404 | 403 `forbidden` |
| `approvals:review` | all records | approve/reject/revoke |
| requester approving own record | — | 403 `self_review_forbidden` |

Decision bodies are empty and forbid extra fields (`422`), so no caller can
express a forged `approved`/`role` claim. Repeating the same decision is
idempotent (`200`, unchanged); a conflicting decision is `409`
`invalid_approval_transition`. Every decision emits a content-free
`approval_decided` audit event.

## 9. Adversarial evaluation (Milestone 5)

An offline, deterministic harness that proves the enforcement claims above
still hold under attack.

```text
corpus.py  (declared attacks + expected enforcement outcome)
   │
   ▼
harness.py  ── each case ──► fresh app (in_memory) ──► ASGI transport
   │                              (real policy/executor/approval pipeline)
   │  observe only: HTTP status, reason codes, action_status,
   │  security flags, execution log — never internal state
   ▼
score: prevented  iff every declared expectation holds
       false_allow iff a forbidden guarded handler executed
       false_deny  iff a declared minimum of executions did not occur
   │
   ▼
report.py  ──► docs/ADVERSARIAL_EVALUATION.md   (human-readable)
           └─► docs/adversarial_evaluation.json (machine-readable)
```

- The harness is an **observer**: it uses the public HTTP surface and the
  registered tools' execution log, exactly as an external evaluator would. It
  cannot weaken or bypass enforcement.
- Metrics (prevention rate, false allows/denies, per-category, per-threat) are
  **derived from per-case verdicts**, so a headline number cannot disagree with
  what ran.
- `tests/evaluation/` asserts (a) the whole corpus is prevented, (b) the
  committed artifacts equal a fresh run, and (c) **the tester works** — a case
  with a violated expectation is reported as a failure, not silently passed.
- M5 measures **RASP enforcement**, not a real model's propensity to attack
  (documented in `docs/LIMITATIONS.md`).

## 10. Controlled-pilot readiness gate (Milestone 6)

A fail-closed startup gate that prevents "controlled pilot" mode from being
enabled silently. It is enforced in `build_container()` alongside policy
validation, so `create_app()` refuses to serve on an unsatisfied gate.

```text
RASP_PILOT_MODE
   ├─ "off" (default)      ──► no gate; behavior unchanged
   ├─ "controlled"         ──► require EVERY documented gap id in
   │                            RASP_PILOT_ACKNOWLEDGED_GAPS
   │                            missing / unknown id ──► refuse startup
   └─ anything else          ──► refuse startup (no silent fallback)
```

- **Opt-in & fail-closed:** mirrors `RASP_MODEL_PROVIDER` / `RASP_PERSISTENCE`
  / log settings — an unknown value refuses startup.
- **No extra authority:** enabling controlled mode changes no enforcement. A
  disabled tool is still denied, and the health endpoint reveals no
  configuration (both tested).
- **Records, not certifies:** the gate records that a named human accepted the
  documented gaps (`docs/PILOT_READINESS.md` §3). Hard prerequisites — real
  authentication, encryption/backups, synthetic-only data — are **not**
  verifiable by the gate and remain the operator's responsibility
  (`docs/GOVERNANCE.md`, `docs/PILOT_PLAN.md`).
- Startup logs a `WARNING` when controlled mode is active.
