# RASP — Development Guide

**Stack:** Python ≥3.12 (developed on 3.14), FastAPI, Pydantic 2.x,
jsonschema, pytest, ruff. PostgreSQL arrives in Milestone 2.

## 1. Setup

```powershell
# from the repository root
uv sync            # creates .venv and installs runtime + dev dependencies
```

No API keys or database are required for Milestone 1.

## 2. Run the application

```powershell
uv run uvicorn rasp.main:app --reload --host 127.0.0.1 --port 8000
```

Interactive docs: <http://127.0.0.1:8000/docs>

Bash equivalent: `scripts/run_dev.sh`.

## 3. Quality gates (run before every commit)

```powershell
uv run pytest                 # full suite
uv run ruff check src tests   # lint
uv run ruff format src tests  # format
```

Individual groups:

```powershell
uv run pytest tests/unit
uv run pytest tests/integration
uv run pytest tests/adversarial
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
5. Audit events must never gain content fields (prompt/args/outputs).
6. Deny paths must fail closed; no "just this once" fallbacks.

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
  counter handlers, approval digests, audit/redaction).
- **Integration** — full ASGI app via httpx; no network, no DB, no keys.
- **Adversarial** — injection, impersonation, tampering, bypass, size
  limits; every assertion proves enforcement or flags the gap honestly.
- Tests must remain runnable without PostgreSQL/local-model infrastructure
  until those milestones land (documented fixtures, not silent skips).

## 9. Contribution workflow

1. Inspect existing code before changing it; preserve others' work.
2. Small, reviewable commits; explain security-relevant decisions in the
   commit message.
3. Run lint, format, and tests; report failures honestly — never claim
   unrun results.
4. Update `docs/LIMITATIONS.md` when a limitation changes.
