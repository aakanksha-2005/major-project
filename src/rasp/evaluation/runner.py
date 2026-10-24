"""Entrypoint: run the adversarial evaluation and write the report artifacts.

Usage:

    uv run python -m rasp.evaluation.runner            # write report + results
    uv run python -m rasp.evaluation.runner --check     # verify only; never writes
    uv run python -m rasp.evaluation.runner --write     # write, even with --check

Writes (only when writing is enabled):
    docs/ADVERSARIAL_EVALUATION.md   (human-readable report)
    docs/adversarial_evaluation.json (machine-readable results)

``--check`` is a *verification* gate: it never mutates the working tree, so a
clean checkout stays clean. Exits non-zero when any case failed.
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


def resolve_write(*, no_write: bool, check: bool, write: bool) -> bool:
    """Decide whether artifacts are written (pure, so it is testable).

    - ``--no-write`` always wins (never write).
    - ``--check`` is verification-only, so it does not write by default:
      a clean checkout stays clean after a gate run.
    - ``--write`` explicitly re-enables writing (e.g. ``--check --write``).
    """
    if no_write:
        return False
    if write:
        return True
    return not check


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the RASP adversarial evaluation.")
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="never write report artifacts (wins over --write)",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="write report artifacts even when --check is given",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify only (no writes); exit non-zero if any case failed",
    )
    args = parser.parse_args()
    write = resolve_write(no_write=args.no_write, check=args.check, write=args.write)
    return asyncio.run(_main(write=write, check=args.check))


if __name__ == "__main__":
    sys.exit(main())
