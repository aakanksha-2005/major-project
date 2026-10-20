"""Entrypoint: run the adversarial evaluation and write the report artifacts.

Usage:

    uv run python -m rasp.evaluation.runner            # write report + results
    uv run python -m rasp.evaluation.runner --check     # fail if any case failed

Writes:
    docs/ADVERSARIAL_EVALUATION.md   (human-readable report)
    docs/adversarial_evaluation.json (machine-readable results)

Exits non-zero on any failure when ``--check`` is given, so CI can gate on it.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rasp.evaluation.harness import report_to_json, run_evaluation
from rasp.evaluation.report import render_report

REPO_ROOT = Path(__file__).resolve().parents[3]
REPORT_PATH = REPO_ROOT / "docs" / "ADVERSARIAL_EVALUATION.md"
RESULTS_PATH = REPO_ROOT / "docs" / "adversarial_evaluation.json"


async def _main(write: bool, check: bool) -> int:
    report = await run_evaluation()
    rendered = render_report(report)

    if write:
        REPORT_PATH.write_text(rendered, encoding="utf-8")
        RESULTS_PATH.write_text(report_to_json(report) + "\n", encoding="utf-8")

    print(
        f"cases={report.total_cases} prevented={report.prevented} "
        f"failures={report.failures} prevention_rate={report.prevention_rate * 100:.1f}% "
        f"false_allows={report.false_allows} false_denies={report.false_denies}"
    )
    for case in report.cases:
        if not case.prevented:
            print(f"  FAILED {case.id}: {'; '.join(case.notes)}")

    if check and report.failures:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the RASP adversarial evaluation.")
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="do not write report artifacts (print metrics only)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any case failed",
    )
    args = parser.parse_args()
    return asyncio.run(_main(write=not args.no_write, check=args.check))


if __name__ == "__main__":
    sys.exit(main())
