"""Adversarial evaluation package (Milestone 5).

A reproducible, offline harness that drives a corpus of adversarial cases
through the *real* RASP ASGI pipeline and scores whether enforcement held.

Nothing here weakens or bypasses enforcement: the harness only observes the
public HTTP surface and the registered tools' execution log, exactly as an
attacker-turned-evaluator would.
"""

from rasp.evaluation.corpus import CASES, EvalCase
from rasp.evaluation.harness import CaseResult, EvaluationReport, run_evaluation

__all__ = [
    "CASES",
    "CaseResult",
    "EvalCase",
    "EvaluationReport",
    "run_evaluation",
]
