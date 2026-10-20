"""Markdown rendering for the adversarial evaluation report (Milestone 5)."""

from __future__ import annotations

from rasp.evaluation.harness import EvaluationReport

_HEADER = """\
# RASP — Adversarial Evaluation Report

> **Generated artifact.** Produced by `python -m rasp.evaluation.runner` from
> the deterministic, offline corpus in `src/rasp/evaluation/corpus.py`. Do not
> edit by hand; edit the corpus (and re-run) instead.

Each case drives the **real** ASGI pipeline (explicit `in_memory` mode) with a
declared attack and a declared enforcement expectation. A case counts as
*prevented* only when every expectation holds — including that a guarded
mutating handler was never reached. Metrics are derived directly from those
verdicts and cannot drift from what was executed. `docs/THREAT_MODEL.md` maps
the `T-ids` to documented threats.
"""


def render_report(report: EvaluationReport) -> str:
    lines: list[str] = [_HEADER, ""]
    lines.append(f"- **Run started:** `{report.started_at}`")
    lines.append(f"- **Run finished:** `{report.finished_at}`")
    lines.append(f"- **Cases:** {report.total_cases}")
    lines.append("")
    lines.append("## 1. Headline metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Cases evaluated | {report.total_cases} |")
    lines.append(f"| Prevented (expectation fully held) | {report.prevented} |")
    lines.append(f"| Failures | {report.failures} |")
    lines.append(f"| **Prevention rate** | **{report.prevention_rate * 100:.1f}%** |")
    lines.append(f"| False allows (guarded action executed) | {report.false_allows} |")
    lines.append(f"| False denies (legitimate action blocked) | {report.false_denies} |")
    lines.append("")

    lines.append("## 2. Results by category")
    lines.append("")
    lines.append("| Category | Prevented | Total | Rate |")
    lines.append("|---|---|---|---|")
    for category in sorted(report.by_category):
        bucket = report.by_category[category]
        rate = bucket["prevented"] / bucket["total"] * 100 if bucket["total"] else 0.0
        lines.append(f"| `{category}` | {bucket['prevented']} | {bucket['total']} | {rate:.0f}% |")
    lines.append("")

    lines.append("## 3. Results by threat-model id")
    lines.append("")
    lines.append("| Threat | Prevented | Total | Rate |")
    lines.append("|---|---|---|---|")
    for threat in sorted(report.by_threat):
        bucket = report.by_threat[threat]
        rate = bucket["prevented"] / bucket["total"] * 100 if bucket["total"] else 0.0
        lines.append(f"| {threat} | {bucket['prevented']} | {bucket['total']} | {rate:.0f}% |")
    lines.append("")

    lines.append("## 4. Case detail")
    lines.append("")
    lines.append("| Case | Category | Threats | Verdict | Notes |")
    lines.append("|---|---|---|---|---|")
    for case in report.cases:
        verdict = "prevented" if case.prevented else "**FAILED**"
        notes = "; ".join(case.notes) if case.notes else "—"
        threats = ", ".join(case.threat_ids)
        lines.append(f"| `{case.id}` | `{case.category}` | {threats} | {verdict} | {notes} |")
    lines.append("")

    failures = [c for c in report.cases if not c.prevented]
    lines.append("## 5. Failures (false allows)")
    lines.append("")
    if not failures:
        lines.append("None. Every adversarial case was fully contained by enforcement in this run.")
    else:
        for case in failures:
            lines.append(f"### `{case.id}` — {case.description}")
            lines.append("")
            lines.append(f"- expected: `{case.expected}`")
            lines.append(f"- observed: `{case.observed}`")
            for note in case.notes:
                lines.append(f"- note: {note}")
            lines.append("")

    lines.append("")
    lines.append("## 6. Method and honesty notes")
    lines.append("")
    lines.append(
        "- **Scope.** This measures whether *RASP's enforcement layer* contains a "
        "declared attack. It does not measure a real LLM's propensity to attempt "
        "attacks (a live local-model run is a separate, opt-in activity)."
    )
    lines.append(
        "- **Determinism.** The mock model is deterministic; results are "
        "reproducible run-to-run with no network, model, or database."
    )
    lines.append(
        "- **No softening.** A case with any unmet expectation is reported as a "
        "failure; the harness never downgrades a containment breach."
    )
    lines.append(
        "- **Not a security proof.** A 100% prevention rate here means the "
        "documented corpus was contained — not that RASP is un-breakable. See "
        "`docs/LIMITATIONS.md`."
    )
    lines.append("")
    return "\n".join(lines)
