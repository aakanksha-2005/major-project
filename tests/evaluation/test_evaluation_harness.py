"""Tests for the Milestone 5 adversarial evaluation harness.

These tests do three distinct jobs:

1. **Run the corpus** through the real pipeline and assert the enforcement
   outcomes meet documented thresholds (offline, deterministic).
2. **Test the tester** — prove the harness actually *fails* a case whose
   expectation is violated, so a green report means something.
3. **Guard the committed artifacts** — the checked-in report/JSON must match
   a fresh run, so claims in `docs/ADVERSARIAL_EVALUATION.md` cannot drift
   silently from what the code does.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from rasp.evaluation.corpus import CASES, cases_by_id
from rasp.evaluation.harness import report_to_json, run_evaluation
from rasp.evaluation.report import render_report

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO_ROOT / "docs" / "ADVERSARIAL_EVALUATION.md"
RESULTS_PATH = REPO_ROOT / "docs" / "adversarial_evaluation.json"


@pytest.fixture(scope="module")
def report():
    import asyncio

    return asyncio.run(run_evaluation())


def test_corpus_ids_are_unique():
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids)), "every evaluation case id must be unique"


def test_every_case_declares_a_threat_and_category():
    for case in CASES:
        assert case.category, f"{case.id} has no category"
        assert case.threat_ids, f"{case.id} references no threat-model ids"
        assert case.description, f"{case.id} has no description"


def test_all_cases_prevented(report):
    """The core claim: every documented adversarial case is contained."""
    failures = [f"{c.id}: {'; '.join(c.notes)}" for c in report.cases if not c.prevented]
    assert not failures, "adversarial cases were NOT prevented:\n" + "\n".join(failures)


def test_no_false_allows(report):
    """A guarded mutating action must never execute when it was forbidden."""
    assert report.false_allows == 0
    assert all(not c.false_allow for c in report.cases)


def test_no_false_denies(report):
    """Legitimate actions in the corpus must still execute (no over-blocking)."""
    assert report.false_denies == 0


def test_prevention_rate_is_total(report):
    assert report.prevention_rate == 1.0
    assert report.failures == 0
    assert report.prevented == report.total_cases == len(CASES)


def test_metrics_are_derived_from_case_verdicts(report):
    """Metrics cannot disagree with the per-case verdicts they summarize."""
    assert report.prevented == sum(1 for c in report.cases if c.prevented)
    assert report.false_allows == sum(1 for c in report.cases if c.false_allow)
    assert report.false_denies == sum(1 for c in report.cases if c.false_deny)


def test_metrics_partition_by_category(report):
    total = sum(b["total"] for b in report.by_category.values())
    assert total == report.total_cases
    prevented = sum(b["prevented"] for b in report.by_category.values())
    assert prevented == report.prevented


# --- test the tester: a violated expectation MUST be reported as a failure ----


def test_harness_fails_a_case_that_demands_an_impossible_status():
    """Break an expectation and confirm the harness reports a failure.

    We rewrite one case to require a bogus HTTP status; if the harness were
    rubber-stamping, this would still pass. It must NOT.
    """
    import asyncio

    target = cases_by_id()["text-admin-claim"]
    broken = replace(
        target,
        expect=replace(target.expect, expect_status={0: 418}),
    )
    import rasp.evaluation.harness as harness_mod

    original = harness_mod.CASES
    try:
        harness_mod.CASES = (broken,)
        result = asyncio.run(run_evaluation())
    finally:
        harness_mod.CASES = original

    assert result.total_cases == 1
    assert result.prevented == 0
    assert result.failures == 1
    assert any("status mismatch" in note for note in result.cases[0].notes)


def test_harness_detects_a_containment_breach():
    """If a guarded action DID execute, the case must be a false allow.

    We pick a case whose guarded tool genuinely runs in a legitimate flow
    (replay-after-approval allows one execution) and forbid it, then assert
    the harness flags a false allow and a failure.
    """
    import asyncio

    import rasp.evaluation.harness as harness_mod

    target = cases_by_id()["replay-after-approval"]
    broken = replace(target, expect=replace(target.expect, forbid_execution=True))

    original = harness_mod.CASES
    try:
        harness_mod.CASES = (broken,)
        result = asyncio.run(run_evaluation())
    finally:
        harness_mod.CASES = original

    assert result.false_allows == 1
    assert result.prevented == 0
    assert any("containment breach" in note for note in result.cases[0].notes)


# --- committed artifacts must match a fresh run ------------------------------


def _strip_run_timestamps(text: str) -> str:
    """Drop the per-run timestamps so artifact comparisons are deterministic."""
    out = []
    for line in text.splitlines():
        if line.startswith("- **Run started:**") or line.startswith("- **Run finished:**"):
            continue
        out.append(line)
    return "\n".join(out)


def test_committed_report_matches_fresh_run(report):
    assert REPORT_PATH.exists(), "docs/ADVERSARIAL_EVALUATION.md is missing"
    committed = _strip_run_timestamps(REPORT_PATH.read_text(encoding="utf-8"))
    fresh = _strip_run_timestamps(render_report(report))
    assert committed == fresh


def test_committed_results_match_fresh_run(report):
    assert RESULTS_PATH.exists(), "docs/adversarial_evaluation.json is missing"
    committed = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    fresh = json.loads(report_to_json(report))
    # Timestamps differ per run; compare everything else.
    for key in ("total_cases", "prevented", "failures", "false_allows", "false_denies"):
        assert committed[key] == fresh[key], f"{key} drifted"
    committed_cases = {c["id"]: c["prevented"] for c in committed["cases"]}
    fresh_cases = {c["id"]: c["prevented"] for c in fresh["cases"]}
    assert committed_cases == fresh_cases
