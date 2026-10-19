# RASP — Threat Model

**Status:** Milestone 2 · **Not production-certified**
Scope: the Milestone 2 prototype (mock model, synthetic tools, PostgreSQL
persistence with explicit `in_memory` opt-out, development identity). Later
milestones change the surface and require this document to be updated.

## 1. Assets

| Asset | Sensitivity |
|---|---|
| Tool execution authority (ability to run registered tools) | high |
| Policy configuration integrity | high |
| Approval integrity (who approved what, exactly) | high |
| Audit trail completeness/sanity | medium |
| Synthetic demonstration data | low (explicitly fake) |
| Future: student/PII data, credentials, real records | high (post-M1) |

## 2. Adversaries

1. **A1 — Malicious or jailbroken model output**: proposes unauthorized
   tool calls, extra arguments, or forged "approvals" in text.
2. **A2 — Malicious user**: prompt injection, identity/role claims in
   text, oversized payloads, probing for private data.
3. **A3 — Indirect injection via content**: instructions smuggled in
   retrieved documents or tool output.
4. **A4 — Misconfigured operator**: contradictory policy weakening.
5. **A5 — Network caller without valid identity**: unauthenticated access
   attempts (M1: absent headers ⇒ zero permissions).
6. **A6 — Compromised dependency / supply chain** (out of code scope;
   mitigated by lockfile + audit tooling).

## 3. Trust boundaries

Defined in `docs/ARCHITECTURE.md` §3 (TB1–TB5). Summary: identity comes
from trusted headers, proposals from the model are untrusted, tool output
is untrusted, policy comes from validated disk config only, and approval
claims in text are meaningless.

## 4. Attack surface and mitigations

| # | Attack | Mitigation (implemented) | Residual risk |
|---|---|---|---|
| 1 | Unknown tool identifier (`exfiltrate_credentials`, dotted paths, case/whitespace variants) | Registry default-deny; exact-key lookup (tested) | none known at this layer |
| 2 | Disabled tool executed despite permissions | `enabled: false` deny step before execution (tested) | none known |
| 3 | Invalid/smuggled arguments (`extra` keys, wrong types) | JSON Schema `additionalProperties:false` validation pre-execution (tested) | schema quality is manual |
| 4 | Policy cap bypass (schema-valid but oversized values) | Policy `argument_caps` checked after schema (tested) | caps are per-config |
| 5 | Missing/absent permission | Header-derived permissions only; text claims ignored (tested) | **header identity is forgeable in M1** (dev-only) |
| 6 | Forged approval ("user approved this" in text/body) | Body forbids approval fields (422); text ignored; store-only records (tested) | decision endpoints deferred to M3 |
| 7 | Approval tampering (changed args/principal/policy version) | sha256 action digest binding + TTL (tested) | reviewer authz is M3 |
| 8 | Model registers/edits tools or policy | No code path exists; policy read from disk at startup (tested via API-probe test) | filesystem access is infra's job |
| 9 | Executor bypass attempts (direct handler references, other endpoints) | Only registered IDs exist; 404 elsewhere (tested) | process-level isolation not implemented |
| 10 | Policy engine crash → silent allow | `PolicyEvaluationError` → deny, audited (tested) | none known |
| 11 | Handler crash/timeout | Sanitized `error_category`, result withheld, audited (tested) | handler side effects pre-crash possible for mutating tools |
| 12 | Unsafe output (schema-violating, secret-shaped) | Output schema validation + pattern redaction (tested) | **pattern detection incomplete** |
| 13 | Unbounded tool loops | `max_agent_steps` budget (tested) | per-request budgets only |
| 14 | Oversized payloads (DoS) | Body-size middleware → 413 (tested) | rate limiting not yet implemented |
| 15 | Audit access by unauthorized/scoped-out callers | `audit:read` gate; own-scope filtering; `audit:admin` for all (tested) | durable store, but no integrity signing; DB credentials can alter rows |
| 16 | Prompt injection (direct/indirect) | Trust labels; flags; authorization independent of content (tested) | **detection is best-effort**; enforcement must not rely on it — and does not |
| 17 | Secrets in logs/events | Audit schema structurally has no content fields (tested) | app-level logging not yet centralized/redaction-tested |
| 18 | Policy weakening at load | Defaults hard-wired `deny` (Literal types); critical+enabled requires approval; registry/policy consistency check (tested) | file access control is infra's job |
| 19 | Database unavailable / write fails → action executes unlogged | Mutating tools deny (`persistence_error`) before the handler; approvals that cannot persist deny (tested without and with a real DB) | read-only post-hoc audit fallback is flagged, not blocked |
| 20 | Concurrent duplicate approvals / state rollback | Partial unique index (one pending per exact action), optimistic expected-status guard, validated state machine (tested on PostgreSQL) | reviewer authorization still M3 |

## 5. Explicit non-claims

RASP does **not** claim to:

- detect all prompt injections or jailbreaks;
- stop a compromised application process from calling handlers directly;
- provide tamper-proof audit (no signatures/chain in M2);
- replace the target system's own authorization;
- provide production authentication (M1 headers are development-only);
- be bias-free, jailbreak-proof, or certified.

## 6. Assumptions

1. The repository build environment and dependency lockfile are trusted.
2. Runners deploy RASP behind real authentication before any shared use
   (Milestone 3+ hardening).
3. Registered handlers are correct, reviewed, non-networked demo code.
4. Synthetic data only until the pilot governance gate (Phase 5/6).
5. One application instance is expected per deployment for policy caching;
   shared PostgreSQL state is durable, but no multi-instance coordination or
   migration orchestration is provided.

## 7. Residual risks (documented, unresolved in M1)

| Risk | Severity | Disposition |
|---|---|---|
| Header-based identity is forgeable by anyone with network access | **high** (if exposed) | acceptable for local dev only; M3 auth design required before any shared deployment |
| Database outage | medium | mutating actions/approvals fail closed; read-only actions flagged; `/v1/audit` 503; recovery is a manual dump/restore runbook (`docs/DEPLOYMENT.md`) |
| Audit rows are mutable by anyone with DB credentials | medium | no signing/append-only control yet; documented |
| Pattern-based redaction misses novel secret formats | medium | documented limitation; defense-in-depth layer only |
| No rate limiting / concurrency controls | medium | pre-deployment requirement |
| Injection indicators may false-positive on coursework | low | flags are advisory; authorization unaffected |
