# RASP — Architecture

**Status:** Milestone 1 (mock-model prototype) · **Version:** 0.1.0 ·
**Not production-certified**

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
FastAPI gateway (api/) ──► schema validation, error envelope
   │
   ├─ GET  /v1/health          minimal health, no internals
   ├─ POST /v1/chat            mediated request lifecycle
   ├─ GET  /v1/tools           registered tool metadata
   ├─ POST /v1/tools/execute   direct mediated execution
   └─ GET  /v1/audit           authorized, scoped, paginated events
   ▼
ChatOrchestrator (gateway/lifecycle.py)
   │  trust labels: system_policy | user | retrieved | tool_output | model
   │  risk scan (supplementary flags only)
   ▼
ModelAdapter (models/)  ── MockModelAdapter (deterministic, M1)
   │  returns text OR tool proposals  ← UNTRUSTED
   ▼
ControlledExecutor (executor/)          ◄── THE enforcement boundary
   │  1. fresh PolicyEngine.evaluate()
   │  2. DENY → audit(not_executed), handler never called
   │  3. REQUIRE_APPROVAL → pending ApprovalStore record, nothing runs
   │  4. ALLOW → constraints → timeout → registered handler only
   │  5. output schema validation → redaction/truncation → audit
   ▼
ToolRegistry (tools/) ── trusted, application-registered handlers only
```

### Cross-cutting

- **Policy engine** (`policy/`) — deterministic, independently testable,
  documented precedence, fail-closed on internal error.
- **Audit** (`audit/`) — in-memory bounded buffer (M1), pseudonymized
  principals, structural no-content guarantee (see §5).
- **Approvals** (`approvals/`) — pending records with digest binding and
  expiry (decision endpoints arrive in Milestone 3).
- **Risk signals** (`risk/`) — supplementary flags; never override authz.
- **Privacy** (`privacy/`) — output screening, redaction, item caps.

## 3. Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| TB1: HTTP identity | header-based dev principal (M1) | anything in message text |
| TB2: model output | policy + registry code | model text and tool proposals |
| TB3: tool results | executor validation/screening | handler output content |
| TB4: policy config | validated YAML from disk | runtime API (cannot modify) |
| TB5: approvals | store records + digest math | "the user approved" claims anywhere |

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

## 5. Persistence (Milestone 1 decision)

Milestone 1 uses **in-memory stores** behind small interfaces:

- `AuditService` (bounded `deque`, threading lock)
- `ApprovalStore` (TTL, lazy expiry)

Rationale (per approved plan): mock-model tests must run without
PostgreSQL. Milestone 2 replaces the internals with PostgreSQL repositories
(SQLAlchemy 2.x + Alembic) without changing call sites. **Not durable yet —
events are lost on restart (documented in LIMITATIONS.md).**

## 6. Failure behavior

| Failure | Behavior |
|---|---|
| Invalid/contradictory policy file | **startup refuses** (`PolicyConfigError`) |
| Unknown/disabled tool, missing permission | DENY before handler |
| Malformed arguments | DENY (`invalid_arguments`) before handler |
| Policy evaluation exception | DENY (`policy_error`) — fail closed, audited |
| Handler exception / timeout | `failed`/`timeout` result, sanitized category, audited |
| Output schema violation | result withheld (`invalid_tool_output`) |
| Oversized request body | 413 before application code |
| Missing principal headers | zero-permission principal → sensitive actions denied |
| Step budget exceeded | safe fallback text, no further tool calls |

## 7. Key modules

| Module | Responsibility |
|---|---|
| `main.py` | app factory; startup validation; middleware wiring |
| `container.py` | component graph; policy/registry consistency check |
| `settings.py` | typed env configuration (`RASP_*`) |
| `api/` | routes, error envelope, body-size middleware |
| `auth/dev_identity.py` | development principal resolution (NOT production auth) |
| `models/` | provider-neutral adapter; deterministic mock |
| `tools/registry.py` | registration, lookup, JSON Schema validation |
| `tools/builtin.py` | six synthetic demo tools + execution log instrumentation |
| `policy/config.py` | YAML load, fail-closed validation |
| `policy/engine.py` | deterministic evaluation, documented precedence |
| `executor/executor.py` | the trusted execution boundary |
| `gateway/lifecycle.py` | chat loop, step budget, output gateway |
| `approvals/store.py` | pending records, binding, expiry |
| `audit/service.py` | pseudonymized, content-free events |
| `privacy/redaction.py` | secret-shape redaction, truncation |
| `risk/signals.py` | injection indicators (defense in depth) |
