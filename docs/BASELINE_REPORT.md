# RASP — Baseline Inspection Report (Milestone 0)

**Date:** 2026-10-19
**Inspector:** KYRA (coding agent)
**Scope:** Repository `C:\Users\srira\OneDrive\Desktop\Projects\RASP` and remote `github.com/aakanksha-2005/major-project`

## 1. Existing architecture and stack

### Local working directory (before this work)

- **Empty directory.** No files, no source code, no dependency manifests,
  no tests, no configuration, no git repository.
- There was no existing architecture to preserve or reuse.

### Remote repository (`aakanksha-2005/major-project`)

- Public GitHub repository, **1 commit**, containing only an
  auto-generated placeholder `README.md` (`# major-project`).
- No description, topics, branches other than `main`, or other content.

## 2. What was already implemented

Nothing. This is a greenfield build. The original placeholder README was
preserved in git history (commit `18e68f3`, `Initial commit`) and replaced
with the project README as authorized by the project owner.

## 3. Environment inventory (execution environment)

| Tool | Version | Notes |
|---|---|---|
| Python | 3.14.6 | `requires-python >= 3.12` satisfied |
| uv | 0.12.5 | used for environment + dependency sync |
| git | 2.55.0 | global identity `dilleshwar-17` |
| Docker | 29.6.2 | available for Milestone 2 PostgreSQL |
| psql | not installed | PostgreSQL via Docker in M2 |
| GitHub CLI (`gh`) | not installed | collaborator management not automatable here |

Resolved dependency lock: `uv.lock` (fastapi/starlette/pydantic 2.x,
jsonschema, pyyaml, pytest 9.x, httpx, ruff). All resolved and installable
on Python 3.14.

## 4. Tests that pass or fail

Latest full run (Milestone 6):

```
304 passed, 0 skipped   (with PostgreSQL running; 14 are postgres-marked)
290 passed, 14 skipped  (no PostgreSQL: postgres tests SKIP with an explicit reason)
ruff check src tests migrations   -> All checks passed!
```

M5 adversarial evaluation (offline, deterministic):

```
uv run python -m rasp.evaluation.runner --check
cases=16 prevented=16 failures=0 prevention_rate=100.0% false_allows=0 false_denies=0
```

Live verification (real HTTP against `uvicorn rasp.main:app`):

- `GET /v1/health` → 200 minimal payload
- `POST /v1/chat` → 200 deterministic mock reply
- `POST /v1/tools/execute` (`document_search`) → 200 `allow_with_constraints`
- `POST /v1/tools/execute` (`record_delete`) → **403 `tool_disabled`**
- `POST /v1/tools/execute` (`publish_announcement`) → **202 pending approval**

## 5. Missing prerequisites

- **PostgreSQL** not running/installed locally (Docker available) —
  Milestone 2 target, intentionally not required by Milestone 1.
- **GitHub collaborator access**: `dilleshwar-17` is not yet a contributor
  on `aakanksha-2005/major-project`; push requires the owner's invitation
  (deferred by decision of the project owner).
- **Local model runtime** (M4) — optional. The adapter is implemented and
  tested offline (injected transport); running it against a real local model
  (Ollama/LM Studio/llama.cpp) is a `RASP_MODEL_PROVIDER=local` opt-in and not
  required by the test suite.

## 6. Security concerns discovered

1. **No prior code existed**, so no inherited vulnerabilities; the threat
   model is documented fresh in `docs/THREAT_MODEL.md`.
2. Residual risks in this prototype are documented in `docs/LIMITATIONS.md`
   (development header-based identity, pattern-based detection limits,
   in-memory stores).

## 7. Files created or modified

See README and `docs/ARCHITECTURE.md`. Summary:

- Project scaffolding: `pyproject.toml`, `uv.lock`, `.gitignore`, `.env.example`
- Source: `src/rasp/**` (gateway, models, tools, policy, risk, approvals,
  executor, audit, privacy, auth, api, schemas, container, main, settings)
- Policy: `config/policies.example.yaml`
- Tests: `tests/{unit,integration,adversarial,postgres,evaluation}/**` (304 tests)
- Evaluation: `src/rasp/evaluation/**` (corpus, harness, report, runner),
  `docs/ADVERSARIAL_EVALUATION.md`, `docs/adversarial_evaluation.json`
- Pilot governance: `src/rasp/pilot/**` (readiness gate),
  `docs/{PILOT_READINESS,PILOT_PLAN,GOVERNANCE}.md`
- Docs: `docs/{BASELINE_REPORT,ARCHITECTURE,THREAT_MODEL,LIMITATIONS,DEVELOPMENT}.md`,
  `README.md` (replaces placeholder), `scripts/*`

## 8. Proposed phased implementation plan

| Phase | Content | Status |
|---|---|---|
| M0 | Repository inspection, baseline, architecture, threat model | **done** |
| M1 | FastAPI + mock model + registry + policy engine + executor + audit + tests | **done** |
| M2 | PostgreSQL persistence (SQLAlchemy, Alembic, repositories) | **done** |
| M3 | Approval lifecycle endpoints, reviewer authz, idempotency, structured logging | **done** |
| M4 | Local LLM adapter (OpenAI-compatible + Ollama native, fail-closed) | **done** |
| M5 | Adversarial evaluation report with metrics | **done** |
| M6 | Controlled pilot preparation (governance docs + machine-checked gate) | **done** |

**Constraint honored:** no live systems, real personal data, or production
credentials were touched at any point.
