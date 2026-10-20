# RASP — Controlled Pilot Plan (Milestone 6)

**Status:** pilot *template* · **Not production-certified**

This is the plan an organization completes and agrees to **before** running a
controlled pilot of RASP. It is deliberately small in scope: a supervised,
synthetic-data-only trial that exercises RASP's enforcement on a bounded set of
tools, with a named human in the loop and an unambiguous stop button.

> Read `docs/PILOT_READINESS.md` first — its hard prerequisites (§2) and
> acknowledgement list (§3) are conditions of this plan.

---

## 1. Purpose and hypotheses

A controlled pilot answers **narrow, falsifiable** questions about RASP, not
about whether an AI "works".

| # | Hypothesis | How it is measured |
|---|---|---|
| H1 | RASP denies every unauthorized tool call the model proposes. | Count of unauthorized proposals that executed = **0** against the pilot's tool set. |
| H2 | RASP never executes a mutating action without a valid human approval. | Count of unapproved mutating executions = **0**. |
| H3 | Denials are explainable and reviewable without leaking policy internals. | Every denial returns a stable reason code; reviewers can reconstruct *who/what/why* from the audit trail. |
| H4 | A model/provider outage never becomes authorization. | A killed model endpoint produces `model_unavailable` with **nothing executed**. |
| H5 | The approval workflow is workable for humans. | Median time-to-decision and reviewer feedback over the pilot window. |

---

## 2. Scope

**In scope**

- A **single** deployment instance, reachable only by named participants.
- A **bounded tool set** (start with read-only tools; add at most one mutating
  tool that requires approval).
- **Synthetic or de-identified** data only.
- RASP enforcement, approval workflow, audit usability, and fail-closed
  behavior under induced failure.

**Explicitly out of scope**

- Real personal, health, financial, or public-service data.
- Any consequential decision about a person (eligibility, benefits, legal
  status, employment, policing).
- Unattended/automated use; the pilot is supervised at all times.
- Load, scale, or multi-instance testing.
- Claims of production readiness, certification, or "jailbreak-proofing".

---

## 3. Roles

| Role | Responsibility |
|---|---|
| **Pilot owner** | Accountable for the run; accepts the §3 gaps in `PILOT_READINESS.md`; holds the stop authority. |
| **Human reviewer(s)** | Approve/reject/revoke every mutating action; must differ from the requester (separation of duties is enforced). |
| **Operators** | Run the instance, watch logs/audit, respond to incidents. |
| **Observers** | Independently record what happened (may be the same people in a small pilot). |

No participant may approve their own request — RASP enforces this
(`403 self_review_forbidden`), but the *process* must also respect it.

---

## 4. Success criteria

The pilot is **successful** when, over the agreed window:

1. H1–H4 measured **0** violations (no unauthorized or unapproved execution; a
   model outage executed nothing).
2. Every decision is reconstructable from the audit trail.
3. No exit criterion (§6) was triggered.
4. Reviewers judge the workflow usable (H5), with any friction recorded.

Success means *the pilot's narrow claims held*. It does **not** mean RASP is
production-ready.

---

## 5. Human-oversight rules

- Every mutating action requires an explicit human decision; there is no
  "auto-approve".
- Approvals are **single-use** and bound to the exact action; a changed
  argument set is a new, unapproved action.
- Reviewers see *what* they are approving (tool, digest-bound action),
  independent of any text the model produced.
- The model's claims ("an admin approved this") are **never** evidence of
  approval.
- Denials are final until a human re-assesses; the model cannot appeal.

---

## 6. Abort criteria (stop conditions)

Stop the pilot immediately — do not "observe a bit longer" — if any of these
occur. These mirror `PILOT_READINESS.md` §6.

- Any mutating action executes without a valid human approval.
- Any denied action reaches a tool implementation.
- Permissions/identity cannot be trusted for the environment.
- Any real personal data appears in the pilot.
- Audit events are lost, unreadable, or found altered.
- A database failure is not fail-closed.
- The pilot owner judges the residual risk unacceptable for any reason.

**Stop procedure:** (1) halt traffic to the instance; (2) disable the pilot
(`RASP_PILOT_MODE=off` and stop the service); (3) snapshot logs and audit;
(4) record the incident; (5) report per `SECURITY.md` if security-relevant.

---

## 7. Rollback and duration

- **Duration:** fixed, short, and pre-agreed (e.g. two weeks), with a review at
  the end and the option to stop at any moment.
- **Rollback:** the pilot runs on isolated infrastructure with synthetic data;
  rollback is "stop the instance and discard the pilot database".
- **Post-pilot:** a written report stating exactly which hypotheses held, what
  failed, and the resulting decision (extend / change / stop). No silent
  continuation.

---

## 8. What this plan will not let you conclude

Even a green pilot does **not** show that RASP is safe for real data, for
consequential decisions, for unattended operation, or against novel attacks.
Those require the prerequisites in `PILOT_READINESS.md` §2 and a separate,
independent security and privacy review.
