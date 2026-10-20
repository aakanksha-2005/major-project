# RASP — Governance Checklist (Milestone 6)

**Status:** pre-pilot controls · **Not production-certified**

A single checklist for governing any use of RASP beyond a local demo. It links
the code-enforced gate to the human decisions that RASP cannot and must not
make for you.

Related: `docs/PILOT_READINESS.md` (gaps and prerequisites),
`docs/PILOT_PLAN.md` (the pilot itself), `docs/THREAT_MODEL.md`,
`docs/LIMITATIONS.md`, `SECURITY.md`.

---

## 1. The one rule

> **A model response is an untrusted proposal, never an authorization
> decision.** No text, claimed identity, claimed approval, or risk score may
> authorize an action. Authorization comes only from trusted context and
> application-enforced policy.

Every checkpoint below exists to protect this rule in practice.

---

## 2. Gate: before enabling controlled mode

| # | Check | Evidence / owner |
|---|---|---|
| G1 | Real authentication or strict network isolation in place | deployment owner |
| G2 | Encryption (transit + rest), backups, credential management | deployment owner |
| G3 | Data is synthetic or explicitly de-identified | data owner |
| G4 | Pilot owner named and accountable | org |
| G5 | Human reviewer named; separation of duties understood | org |
| G6 | Scope, success criteria, abort criteria agreed (`PILOT_PLAN.md`) | pilot owner |
| G7 | All `PILOT_READINESS.md` §3 gaps acknowledged in `RASP_PILOT_ACKNOWLEDGED_GAPS` | operator |
| G8 | `RASP_PILOT_MODE=controlled` starts **without** refusing (gate satisfied) | operator |

If `RASP_PILOT_MODE=controlled` refuses startup, the gate is **not** satisfied
— read the error, fix the missing acknowledgement id, and do not work around
it.

---

## 3. Responsibilities RASP does not carry

RASP is an enforcement *component*. It does not:

- authenticate callers (dev headers are forgeable);
- encrypt, back up, or retain your data;
- make a model safe, truthful, or unbiased;
- sign or make audit events tamper-proof;
- decide whether an action is *appropriate* — that is the human reviewer's job;
- replace the target system's own authorization.

Each of these is an organizational responsibility. Documenting them here is
part of the governance, not a disclaimer to skip.

---

## 4. Data-handling rules

- **Synthetic or de-identified only** until §2 prerequisites are met.
- Prompts, tool arguments, and outputs are **never** logged by RASP; do not add
  logging that captures them.
- Audit events are pseudonymized but mutable by DB credentials — treat audit
  integrity as a deployment control, not a RASP guarantee.
- Decide retention and access **before** the pilot; name the readers.

---

## 5. Change control

- Policy changes are read at startup; a change requires a restart and review.
- The pilot gate, policy validation, and adapter/provider selection all
  **fail closed** on unknown values — never "fix" a refusal by loosening the
  value to something arbitrary.
- Any change to enforcement code ships with a regression test (see
  `CONTRIBUTING.md`).

---

## 6. Incident handling

- Trigger the abort criteria in `PILOT_PLAN.md` §6 immediately.
- Preserve logs and audit before any cleanup.
- Report security-relevant incidents per `SECURITY.md` (privately, not via a
  public issue).
- Record what happened and whether any documented assumption was wrong; feed it
  back into `docs/THREAT_MODEL.md`.

---

## 7. Non-claims (governance must not assert these)

Governance documents, READMEs, and reports **must not** describe RASP as
"production-ready", "secure", "certified", "jailbreak-proof", "bias-free", or
"compliant". The M5 report's 100% prevention rate means the documented corpus
was contained — not that RASP is un-breakable.

---

## 8. Review cadence

- Review this checklist and `PILOT_READINESS.md` at each milestone.
- Re-run the quality gate (`docs/DEVELOPMENT.md`) and the M5 evaluation before
  any pilot window.
- After a pilot, write the report required by `PILOT_PLAN.md` §7 and decide
  explicitly: extend, change, or stop.
