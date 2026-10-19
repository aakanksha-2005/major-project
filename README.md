# RASP — Runtime Agent Safety Platform

**Runtime security and authorization layer for LLM applications and tool-using AI agents.**

> **Status: experimental prototype (v0.1.0, Milestone 1) — not production-certified.**
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
| M2 | PostgreSQL persistence (SQLAlchemy, Alembic) | ⏳ next |
| M3 | Approval decision endpoints, reviewer authz, idempotency, structured logging | planned |
| M4 | Local LLM adapter | planned |
| M5 | Adversarial evaluation report with metrics | planned |
| M6 | Controlled pilot preparation | planned |

**Implemented now:** deterministic mock model, 6 synthetic tools, deterministic
policy engine (allow / deny / require_approval / allow_with_constraints),
controlled executor with timeouts and output validation, in-memory audit with
pseudonymized principals, pending-approval creation with digest binding,
body-size limits, development header identity, REST API, 144 automated tests.

**Planned (not implemented):** PostgreSQL, approval reviewer endpoints, local
LLM adapter, rate limiting, real authentication, comparative evaluation harness.

## 3. Architecture and request lifecycle

```text
Client ─► size-limit middleware ─► FastAPI gateway
   ─► ChatOrchestrator ─► ModelAdapter (mock) ─► text or tool proposal (UNTRUSTED)
        │ text                ─► risk scan + output screening ─► response
        └ tool proposal ─► ControlledExecutor
                              ├─ DENY ──────────────► nothing executes (audited)
                              ├─ REQUIRE_APPROVAL ──► pending record (nothing executes)
                              └─ ALLOW ─► constraints ─► timeout ─► registered handler
                                        ─► output schema check ─► redaction ─► audit ─► model
```

Full detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 4. Threat model summary

Attacks covered by enforced-and-tested controls: unknown/disabled tool
invocation, argument smuggling, missing permissions, forged approvals,
approval tampering/tampered arguments, executor bypass probes, policy
weakening at startup, policy-engine crash (fail closed), handler failure
and timeout, oversized payloads, audit access control, injection attempts
whose *flags never substitute for authorization*.

Explicitly **not** claimed: complete injection detection, tamper-proof
audit, sandboxing of registered handlers, production authentication.
Details: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## 5. Features: implemented vs planned

See status table in §2. Every "implemented" claim is covered by a test in
`tests/` and was executed for this release (**144 passed**).

## 6. Supported model adapters

| Adapter | Provider id | Status |
|---|---|---|
| Deterministic mock | `mock` | implemented (only M1 target) |
| Local OpenAI-compatible runtime | `local` | planned (M4) |
| Hosted provider | — | not started; needs explicit authorization |

Setting `RASP_MODEL_PROVIDER` to anything unimplemented **refuses startup**
(no silent fallback).

## 7. Prerequisites

- **Python ≥ 3.12** (developed on 3.14)
- **[uv](https://docs.astral.sh/uv/)** (dependency/env management)
- No API keys, no database, no network needed for Milestone 1
- (Later) Docker for PostgreSQL — Milestone 2

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

Key settings: `RASP_POLICY_PATH`, `RASP_MODEL_PROVIDER=mock`,
`RASP_MAX_AGENT_STEPS`, `RASP_MAX_REQUEST_BYTES`, `RASP_DEV_AUTH_ENABLED`.
Full list: [.env.example](.env.example).

## 10. Database initialization and migrations

**Not in Milestone 1.** Audit events and pending approvals are in-memory
and lost on restart. PostgreSQL + Alembic migrations are Milestone 2; this
section will be replaced with verified commands when implemented.

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
`GET /v1/audit` (needs `audit:read`), `GET /v1/health`.
Approval *decision* endpoints arrive in Milestone 3 (planned).

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
uv run pytest                  # full suite: 144 passed
uv run pytest tests/unit
uv run pytest tests/integration
uv run pytest tests/adversarial
uv run ruff check src tests    # All checks passed
uv run ruff format --check src tests
```

No PostgreSQL, model credentials, or network are required. Milestone-2
database tests will use isolated fixtures and will be labeled separately
from skipped/available-infrastructure tests.

## 16. Security and privacy design

- Default deny; least privilege; independent enforcement in trusted code.
- Fail closed: policy errors deny sensitive actions and are audited.
- Audit events are structurally **content-free** (no prompts, arguments,
  or outputs — schema guarantee) with salted pseudonymized principals.
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
  "certified" — no such evidence exists for this prototype.
- Fairness/accessibility evaluation across languages and user groups has
  **not** been performed yet and is required before any real-world pilot.

## 18. Known limitations

Summarized: development-only identity; in-memory state (restart loses
audit/approvals); pattern-based injection/secret detection is incomplete;
no rate limiting; no local LLM yet; approval decisions not yet reachable
through the API (pending-only); single-process prototype.
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
