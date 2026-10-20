# RASP — Controlled Pilot Readiness (Milestone 6)

**Status:** pre-pilot assessment · **Not production-certified**

This document is the honest gate between the RASP prototype and any *real*
use. It lists what must be true before a controlled pilot, what is currently
**not** true, and what the machine-checked pilot gate (`RASP_PILOT_MODE`,
`src/rasp/pilot/readiness.py`) does and does not guarantee.

> **Read this first.** A controlled pilot is *supervised, scoped, and
> reversible*, on **synthetic or explicitly de-identified** data, with a named
> human accountable for every mutating action. RASP remains an experimental
> prototype; this document does not certify it.

---

## 1. Readiness verdict

**Not ready for any pilot that uses real personal data or consequential
decisions.** RASP is ready for **supervised, synthetic-data-only controlled
pilots** *after* the operator (a) enables controlled mode and acknowledges
every gap below, and (b) resolves the hard prerequisite in §2 for their
environment.

| Area | State for a controlled pilot | Blocker? |
|---|---|---|
| Runtime enforcement (default-deny, approval, single-use, fail-closed) | implemented + tested | no |
| Adversarial evaluation (M5 corpus) | 16/16 prevented, 0 false allows | no |
| Persistence (PostgreSQL, migrations, durability) | implemented + tested | no |
| **Real authentication / trustworthy identity** | **not implemented** | **YES — hard prerequisite** |
| Data protection (encryption, retention, backups) | **not implemented by RASP** | **YES — deployment's job** |
| Live model safety evaluation | **not performed** | conditional (see §3) |
| Rate limiting / abuse controls | **not implemented** | conditional |
| High availability / multi-instance | **not provided** | conditional |
| Fairness / accessibility evaluation | **not performed** | conditional |

---

## 2. Hard prerequisites (cannot be acknowledged away)

These must be resolved by the deploying organization **before the pilot gate
is even meaningful**. The gate does not and cannot verify them — that would
require systems RASP deliberately does not implement.

1. **Real authentication.** The identity mechanism in this build
   (`X-Dev-Principal` / `X-Dev-Permissions`) is forgeable. Any caller who can
   reach the port can claim any permission, including `approvals:review`.
   A pilot MUST sit behind a real identity provider that RASP trusts, or be
   network-isolated to the point where only a trusted, single operator can
   reach it. *Until then, every authorization decision — including approvals —
   is only as trustworthy as the network.*
2. **Data protection.** RASP is a single unencrypted PostgreSQL instance with
   documented placeholder credentials and no TLS. A pilot MUST provide
   encryption in transit and at rest, credential management, backups, and a
   retention policy. RASP's audit events are pseudonymized but **mutable** by
   anyone with database credentials — there is no signing or append-only
   control.
3. **Synthetic or de-identified data only.** Do not run a pilot on real
   personal, health, financial, or public-service records. RASP cannot yet
   justify processing them.

---

## 3. Documented gaps (must be explicitly acknowledged)

Enabling `RASP_PILOT_MODE=controlled` requires the operator to name **every**
id below in `RASP_PILOT_ACKNOWLEDGED_GAPS`. A missing or unknown id refuses
startup. Each id maps to an unresolved risk documented in
`docs/LIMITATIONS.md` and `docs/THREAT_MODEL.md`.

| Acknowledgement id | What the operator accepts |
|---|---|
| `dev_identity_not_production_auth` | Identity/permissions (and therefore reviewer authorization) are development-only and forgeable until real auth is in place. |
| `synthetic_data_only_until_auth_and_hardening` | The pilot uses only synthetic or explicitly de-identified data. |
| `audit_rows_mutable_by_db_credentials` | Audit events are pseudonymized but not tamper-proof; DB credentials can alter them. |
| `no_log_signing_or_sink_control` | RASP guarantees what it does *not* log (no prompts/args/outputs), not where logs are retained, nor who can read them. |
| `no_live_model_safety_evaluation` | The M5 report scores RASP enforcement, **not** a real model's propensity to attempt attacks; no live comparative model evaluation has been run. |
| `no_rate_limiting` | There is no rate limiting or abuse control; a reachable instance can be flooded. |
| `single_instance_no_ha` | Single process, single database; no high availability or multi-instance coordination. |
| `manual_db_recovery_runbook` | Database recovery is a manual, drill-untested procedure (see `docs/DEPLOYMENT.md`). |
| `human_oversight_required` | A named human reviews every mutating action; RASP is never the sole decision-maker (see §5). |
| `no_fairness_or_accessibility_evaluation` | No fairness/bias or accessibility evaluation has been performed; RASP must not be used for consequential decisions about people. |

---

## 4. What the pilot gate does and does not do

**Does:**

- Default `off`; enabling controlled mode is an explicit, recorded act.
- Refuses startup on an unknown mode, an unknown acknowledgement id, or any
  missing acknowledgement (fail closed, same pattern as
  `RASP_MODEL_PROVIDER` / `RASP_PERSISTENCE` / log settings).
- Logs a **warning** at startup when controlled mode is enabled.
- Survives an independent test suite (`tests/unit/test_pilot_readiness.py`).

**Does not:**

- Make RASP safe, certified, or production-ready.
- Verify authentication, encryption, backups, or network isolation (§2).
- Prevent an operator from lying about the data or the environment.
- Change any enforcement behavior: enabling controlled mode grants **no**
  additional authority (tested — a disabled tool stays denied).

---

## 5. Pre-pilot checklist (operator sign-off)

Complete and retain this before enabling controlled mode.

- [ ] Real authentication or strict network isolation is in place (§2.1).
- [ ] Encryption, backups, credential management, and retention are in place (§2.2).
- [ ] Data is synthetic or explicitly de-identified (§2.3).
- [ ] A named **pilot owner** is accountable for the run.
- [ ] A named **human reviewer** approves every mutating action; separation of
      duties is enforced (requester ≠ approver).
- [ ] Pilot scope, success criteria, and **abort criteria** are defined and
      agreed (see `docs/PILOT_PLAN.md`).
- [ ] Audit retention and access are decided; readers are named.
- [ ] A rollback/stop plan exists (who stops the pilot, how, and how fast).
- [ ] All §3 acknowledgement ids are set in `RASP_PILOT_ACKNOWLEDGED_GAPS`.
- [ ] The M5 report and `docs/LIMITATIONS.md` have been read by the owner.

---

## 6. Exit criteria (when the pilot must stop)

The pilot MUST be stopped immediately when any of the following occurs:

- any mutating action executes that was not explicitly approved by the named
  human reviewer;
- a denied action reaches a tool implementation;
- identity/permissions cannot be trusted for the environment in use;
- any real personal data is discovered in the pilot;
- audit events are lost, unreadable, or found altered;
- the database fails in a way that is not fail-closed.

Record the incident, stop the pilot, and follow the reporting process in
`SECURITY.md`.

---

## 7. Honest closing statement

RASP demonstrates that a model's output can be treated as an untrusted
proposal and mediated by independent, fail-closed enforcement. That is the
claim this repository supports with tests. Everything about *who* is calling,
*what real data* is involved, and *whether a model is actually safe* is
explicitly out of scope here and remains the operator's responsibility before
any pilot touches reality.
