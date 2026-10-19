# RASP — Known Limitations (v0.1, Milestone 1)

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
| Audit structural privacy, pseudonymization, scoping | `tests/unit/test_audit_privacy.py`, `tests/integration/test_audit_api.py` |
| Chat lifecycle, step budget, 413 size limit | `tests/integration/test_api.py`, adversarial suite |
| Direct/indirect injection, impersonation, executor-bypass probes | `tests/adversarial/` |

Current run: **144 passed** (`uv run pytest`), lint and format clean.

## 2. What is NOT covered (untested attack classes)

- Real network-level attacks (TLS, DNS, HTTP smuggling, replays by a
  network adversary).
- Multi-user concurrency races beyond per-store locks; no load testing.
- A compromised or malicious **registered handler** (handlers are trusted
  code by assumption).
- OS/process-level escape (RASP does not sandbox handlers).
- Real LLM misbehavior: all model tests use the deterministic mock;
  local-model behavior arrives in Milestone 4.
- Rate limiting and fair-use abuse (not implemented yet).
- Audit tamper resistance: no signatures, hash chain, or external
  immutability. An attacker with process access can alter the in-memory
  buffer.
- Postgres failure modes (no database in M1).
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
  this build beyond localhost. Production authentication is a Milestone 3
  prerequisite.
- **In-memory state:** audit events and pending approvals are lost on
  restart. PostgreSQL persistence is Milestone 2.
- **Approval workflow is partial:** pending creation + digest binding +
  expiry exist and are tested; reviewer decision endpoints and reviewer
  authorization are Milestone 3. Until then, no approved state can be
  reached through the API — approvals can only be created and inspected.
- **Model adapter:** only the deterministic mock (`RASP_MODEL_PROVIDER=mock`)
  exists. Setting anything else refuses startup. Local adapter = M4.
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
- Any use beyond localhost requires: real authentication (M3),
  persistent audit (M2), an adversarial evaluation report (M5), and an
  independent security/privacy review.
