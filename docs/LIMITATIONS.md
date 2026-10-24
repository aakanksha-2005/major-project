# RASP — Known Limitations (v0.1, Milestone 6)

Honest disclosure of what is and is not covered. Updated per milestone.

## 1. What HAS been tested

| Area | Evidence |
|---|---|
| Policy decisions (allow/deny/constraint/approval, precedence, fail-closed) | `tests/unit/test_policy_engine.py` |
| Policy config validation (weakening attempts refuse startup) | `tests/unit/test_policy_config.py` |
| Registry/schema validation | `tests/unit/test_tool_registry.py` |
| Deny ⇒ handler never invoked (counter tools) | `tests/unit/test_executor.py` |
| Timeouts, output-schema validation, output caps, redaction | `tests/unit/test_executor.py` |
| Approval binding/tampering/expiry/replay-shaped cases | `tests/unit/test_approvals.py`, engine tests |
| Approval lifecycle: decide/claim/find_for_action, self-approval guard, idempotent decisions, single-use consumption, stale-pending retirement | `tests/unit/test_approval_lifecycle.py` |
| Exactly-once execution under concurrent approved requests (in-memory) | `tests/unit/test_approval_concurrency.py` |
| Approval decision endpoints: reviewer authz, own-scope reads, 404 not-found scoping, forged bodies, 409 conflicts | `tests/integration/test_approval_api.py` |
| Structured logging: content-free access lines, request-id correlation/echo, content canaries, unknown level/format refuses startup | `tests/integration/test_logging.py` |
| Audit structural privacy, pseudonymization, scoping | `tests/unit/test_audit_privacy.py`, `tests/integration/test_audit_api.py` |
| Chat lifecycle, step budget, 413 size limit | `tests/integration/test_api.py`, adversarial suite |
| Direct/indirect injection, impersonation, executor-bypass probes, approval forging/replay/self-approval, log content canary | `tests/adversarial/` |
| Model adapters: request building, OpenAI/Ollama response parsing, malformed/partial payloads, offline via injected `httpx.MockTransport` | `tests/unit/test_local_model.py` |
| Local adapter in the full pipeline; provider failure (transport, non-2xx) fails closed with `model_unavailable` and no execution | `tests/integration/test_local_model_api.py` |
| Hostile local-model output (tool calls, smuggled arguments, authority claims, malformed JSON) cannot bypass enforcement | `tests/adversarial/test_local_model_adversarial.py` |
| PostgreSQL migrations (head `0002_approval_consumed`), restart durability of consumed approvals, durable decision audit events, race-safe claim, approval transitions/idempotency, content-free columns | `tests/postgres/test_pg_lifecycle.py` |
| Database failure denies mutating actions before the handler; approval lookup/claim failures deny; read-only fallback is flagged; `/v1/audit` 503 | `tests/unit/test_persistence_fail_closed.py`, `tests/integration/test_db_unavailable.py` |
| Adversarial evaluation harness: corpus runs the real pipeline, scores prevention/containment, regenerates the committed report, and the tester itself is tested (broken cases must fail) | `tests/evaluation/test_evaluation_harness.py`, `docs/ADVERSARIAL_EVALUATION.md` |
| Controlled-pilot readiness gate: unknown mode refuses startup; missing/unknown acknowledgement id refuses startup; complete acknowledgements enable controlled mode; pilot mode grants no extra authority and does not leak via `/v1/health` | `tests/unit/test_pilot_readiness.py` |

Current run: **304 passed, 0 skipped** with PostgreSQL running (290 of them
need no database; the 14 `postgres`-marked tests skip with an explicit reason
when it is not). Lint and format clean.

The M5 adversarial evaluation harness scores **16/16 cases prevented, 0 false
allows, 0 false denies**. This measures whether *RASP's enforcement layer*
contains a declared attack; see §2 for what it does not measure.

## 2. What is NOT covered (untested attack classes)

- Real network-level attacks (TLS, DNS, HTTP smuggling, replays by a
  network adversary).
- Multi-user concurrency races beyond per-store locks and the tested
  single-approval claim race; no load testing.
- A compromised or malicious **registered handler** (handlers are trusted
  code by assumption).
- OS/process-level escape (RASP does not sandbox handlers).
- Real LLM misbehavior: adapter *plumbing* is tested offline, and the M5
  harness measures whether RASP's enforcement contains a corpus of declared
  attacks. It does **not** measure a real local model's propensity to attempt
  attacks — no comparative, live-model evaluation of safety behavior has been
  run. A local model can and will propose unsafe tool calls; RASP denies them
  by policy, but how *often* a given model does so is not measured here.
- The M5 corpus is hand-written and finite. A 100% prevention rate means those
  cases were contained, not that unlisted attacks would be; novel attack
  shapes are not covered.
- Rate limiting and fair-use abuse (not implemented yet).
- Audit tamper resistance: no signatures, hash chain, or external
  immutability. Events are durable in PostgreSQL, but anyone with database
  credentials can alter or delete them.
- PostgreSQL operational failure modes beyond the tested ones (disk
  exhaustion, replication lag, corruption, backup/restore drills): RASP
  fails closed on failed writes, but recovery is a manual, untested
  runbook-level procedure.
- Localization/fairness across languages and dialects (no multilingual
  evaluation has been performed).

## 3. Detection limitations (by design, documented honestly)

- **Prompt-injection indicators** are regular expressions over common
  phrasings. Novel, obfuscated, encoded, or non-English injections will be
  missed. *This is acceptable only because authorization does not depend
  on detection* — tool permission checks run regardless of flags.
- **Secret redaction** matches well-known shapes (private key blocks,
  `sk-…`, `ghp…`, `password=`, `AKIA…`). Secrets in other formats pass
  through.
- **Risk scores** are flag counts, advisory only, never a safety proof.
- False positives possible: legitimate coursework text can match an
  indicator (flags only; requests are not blocked because of flags alone).

## 4. Prototype-specific restrictions

- **Identity is development-only:** `X-Dev-Principal`/`X-Dev-Permissions`
  headers are forgeable by anyone who can reach the port. Never expose
  this build beyond localhost. Real authentication remains the single
  largest gap and a prerequisite for any deployment beyond localhost.
- **Persistence is durable but local:** audit events, approvals, and policy
  metadata persist in PostgreSQL across restarts. `RASP_PERSISTENCE=in_memory`
  is an explicit opt-out that loses everything on restart. The shipped setup
  is a single unencrypted development instance (documented credentials, no
  TLS) — not a production database deployment.
- **Approval workflow is single-use and enforced, but reviewer identity is
  development-only.** Pending creation, digest binding, expiry, reviewer
  decisions (approve/reject/revoke), separation of duties, idempotent
  decisions, and single-use consumption (`approved → consumed`) all exist and
  are tested. However, *who* a reviewer is still comes from the forgeable
  `X-Dev-Permissions` header — so an attacker who can reach the port and set
  `approvals:review` can decide on any request. Authorization here is only
  meaningful once real authentication is in place.
- **Logs are content-free by construction, but the sink is not controlled.**
  RASP never logs prompts, arguments, or outputs, and there is no code path
  that accepts content for logging. Where logs are shipped, retained, and who
  can read them is a deployment responsibility; no log signing exists.
- **Model adapters:** the deterministic mock (`RASP_MODEL_PROVIDER=mock`) plus
  local, credential-free adapters `local` (OpenAI-compatible HTTP) and
  `ollama` (Ollama native API). Any other provider refuses startup. The local
  adapters are tested offline (injected transport) and fail closed on provider
  errors; no cloud/hosted provider is implemented or required.
- **The M6 pilot gate records acceptance, it does not resolve gaps.** Setting
  `RASP_PILOT_MODE=controlled` and acknowledging every documented gap in
  `RASP_PILOT_ACKNOWLEDGED_GAPS` is required before a controlled pilot, and an
  unknown mode or unknown/missing acknowledgement refuses startup. But the gate
  **cannot verify** real authentication, encryption, backups, or that the data
  is synthetic — those remain human responsibilities
  (`docs/PILOT_READINESS.md`, `docs/GOVERNANCE.md`).
- **Single process, no rate limiting.** Do not deploy publicly.
- **Policy file** is read at startup only; changes require restart.

## 5. Data and fairness notes

- All data in fixtures/tools is synthetic and labeled as such.
- No fairness/bias evaluation has been conducted; do not interpret
  decisions as judgments about people. RASP must never be the sole
  decision-maker for consequential services (see `docs/ETHICS`-level
  commitments in the README).
- Denial messages are intentionally generic and contain no policy internals.

## 6. Deployment restrictions

- Local development only, synthetic data only.
- No live public-service systems, no real personal records, no production
  credentials — and none are required to run the test suite.
- Any use beyond localhost requires: real authentication (prerequisite for
  meaningful approval reviewer authorization),
  a hardened (encrypted, backed-up, access-controlled) database deployment,
  a *live*, comparative model-safety evaluation (the M5 harness covers
  RASP enforcement, not model behavior), and an independent
  security/privacy review.
- A controlled, synthetic-data-only pilot is permitted **only** after passing
  the M6 gate and its hard prerequisites (`docs/PILOT_READINESS.md`); passing
  the gate is not a certification and does not enable real-data use.
