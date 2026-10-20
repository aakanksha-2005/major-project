"""The adversarial evaluation harness (Milestone 5).

Drives every :class:`~rasp.evaluation.corpus.EvalCase` through the real ASGI
application (in the explicit, offline ``in_memory`` mode) and records whether
enforcement held.

Scoring is intentionally strict and mechanical:

- A case is **prevented** only if *every* declared expectation holds:
  required statuses observed, required reason codes observed, and the guarded
  mutating handler absent from the execution log (unless the case legitimately
  allows exactly-once execution).
- A case is a **failure** (a "false allow") if the expectation does not hold.
  The harness never softens a failure into a pass.

The metrics are derived from these per-case verdicts, so they cannot drift
from what was actually tested.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from httpx import ASGITransport, AsyncClient

from rasp.evaluation.corpus import CASES, EvalCase, Step
from rasp.main import create_app
from rasp.settings import Settings
from rasp.tools import builtin

# Permission bundle reused from the documented dev-identity fixtures. Kept
# explicit here so the evaluation is self-contained.
DEFAULT_PERMS = "system:status,documents:read,applications:preview,approvals:read"


@dataclass
class StepResult:
    index: int
    kind: str
    status: int
    reason_codes: list[str] = field(default_factory=list)
    action_status: str | None = None
    security_flags: list[str] = field(default_factory=list)
    error_code: str | None = None
    approval_id: str | None = None
    executed_count: int = 0


@dataclass
class CaseResult:
    id: str
    category: str
    threat_ids: tuple[str, ...]
    description: str
    prevented: bool
    # True when an action that should have been blocked actually executed.
    false_allow: bool
    # True when a legitimate action did NOT execute (over-blocking).
    false_deny: bool
    expected: dict[str, Any]
    observed: dict[str, Any]
    steps: list[StepResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class EvaluationReport:
    started_at: str
    finished_at: str
    total_cases: int
    prevented: int
    failures: int
    false_allows: int
    false_denies: int
    prevention_rate: float
    by_category: dict[str, dict[str, int]]
    by_threat: dict[str, dict[str, int]]
    cases: list[CaseResult]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # dataclasses -> JSON-safe (tuples are fine, json handles them).
        return data


def _headers_for(principal: str, perms: str) -> dict[str, str]:
    headers = {"X-Dev-Principal": principal}
    if perms:
        headers["X-Dev-Permissions"] = perms
    return headers


async def _run_case(case: EvalCase) -> CaseResult:
    # A fresh app per case keeps approval state independent and deterministic.
    settings = Settings(persistence="in_memory", policy_path="config/policies.example.yaml")
    app = create_app(settings)
    container = app.state.container
    builtin.EXECUTION_LOG.clear()

    case_perms = case.perms or DEFAULT_PERMS
    pending_approval_id: str | None = None
    step_results: list[StepResult] = []
    observed_statuses: dict[int, int] = {}
    observed_reason_codes: set[str] = set()
    last_action_status: str | None = None
    last_flags: list[str] = []
    notes: list[str] = []

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://eval") as client:
        for index, step in enumerate(case.steps):
            principal = step.principal or case.principal
            perms = step.perms if step.perms is not None else case_perms
            headers = _headers_for(principal, perms)
            result = await _perform_step(
                client,
                step,
                headers,
                pending_approval_id=pending_approval_id,
            )
            step_results.append(result)
            observed_statuses[index] = result.status
            observed_reason_codes.update(result.reason_codes)
            if result.action_status is not None:
                last_action_status = result.action_status
            if result.security_flags:
                last_flags = result.security_flags
            if result.kind == "execute" and result.status == 202:
                # Capture the parked approval id for a later approve step.
                pending_approval_id = result.approval_id
            if result.error_code:
                notes.append(f"step {index}: error {result.error_code}")

    # --- score ---
    guard = case.expect.guard_tool
    executed = list(builtin.EXECUTION_LOG)
    guard_executed = bool(guard) and any(e.startswith(f"{guard}:") for e in executed)
    total_executions = sum(r.executed_count for r in step_results)

    prevented = True
    for index, expected_status in case.expect.expect_status.items():
        if observed_statuses.get(index) != expected_status:
            prevented = False
            notes.append(
                f"status mismatch at step {index}: "
                f"expected {expected_status}, got {observed_statuses.get(index)}"
            )
    if case.expect.expect_reason_in:
        missing = [c for c in case.expect.expect_reason_in if c not in observed_reason_codes]
        if missing:
            prevented = False
            notes.append(f"missing reason codes: {missing}")
    if case.expect.expect_action_status is not None:
        if last_action_status != case.expect.expect_action_status:
            prevented = False
            notes.append(
                f"action_status mismatch: expected {case.expect.expect_action_status}, "
                f"got {last_action_status}"
            )
    if case.expect.expect_flags_in:
        missing_flags = [f for f in case.expect.expect_flags_in if f not in last_flags]
        if missing_flags:
            prevented = False
            notes.append(f"missing security flags: {missing_flags}")
    if case.expect.forbid_execution and guard_executed:
        prevented = False
        notes.append(f"guarded mutating handler '{guard}' EXECUTED (containment breach)")
    if case.expect.min_executions and total_executions < case.expect.min_executions:
        prevented = False
        notes.append(
            f"expected at least {case.expect.min_executions} execution(s), "
            f"observed {total_executions} (over-blocking)"
        )

    false_allow = guard_executed and case.expect.forbid_execution
    # Over-blocking: the case declares a minimum number of legitimate
    # executions and fewer actually ran. Measured from response bodies (which
    # cover read-only tools too), not the partial mutating-only log.
    false_deny = total_executions < case.expect.min_executions

    builtin.EXECUTION_LOG.clear()
    await container.close()

    expected = {
        "forbid_execution": case.expect.forbid_execution,
        "guard_tool": case.expect.guard_tool,
        "min_executions": case.expect.min_executions,
        "expect_status": {str(k): v for k, v in case.expect.expect_status.items()},
        "expect_reason_in": list(case.expect.expect_reason_in),
        "expect_action_status": case.expect.expect_action_status,
        "expect_flags_in": list(case.expect.expect_flags_in),
    }
    observed = {
        "observed_status": {str(k): v for k, v in observed_statuses.items()},
        "observed_reason_codes": sorted(observed_reason_codes),
        "action_status": last_action_status,
        "security_flags": last_flags,
        "total_executions": total_executions,
        "execution_log": executed,
    }
    return CaseResult(
        id=case.id,
        category=case.category,
        threat_ids=case.threat_ids,
        description=case.description,
        prevented=prevented,
        false_allow=false_allow,
        false_deny=false_deny,
        expected=expected,
        observed=observed,
        steps=step_results,
        notes=notes,
    )


async def _perform_step(
    client: AsyncClient,
    step: Step,
    headers: dict[str, str],
    *,
    pending_approval_id: str | None,
) -> StepResult:
    if step.kind == "chat":
        body: dict[str, Any] = {"message": step.message or "hello"}
        if step.scenario:
            body["scenario"] = step.scenario
        response = await client.post("/v1/chat", json=body, headers=headers)
        return _chat_result(step, response)

    if step.kind == "execute":
        body = {"tool_id": step.tool_id, "arguments": step.arguments}
        body.update(step.extra_body)
        response = await client.post("/v1/tools/execute", json=body, headers=headers)
        return _execute_result(step, response)

    if step.kind == "approve":
        approval_id = pending_approval_id or "missing"
        response = await client.post(f"/v1/approvals/{approval_id}/approve", headers=headers)
        reason_codes = _reason_from_error(response)
        return StepResult(
            index=0,
            kind=step.kind,
            status=response.status_code,
            reason_codes=reason_codes,
            error_code=_error_code(response),
        )

    if step.kind == "list_approvals":
        response = await client.get("/v1/approvals", headers=headers)
        return StepResult(
            index=0,
            kind=step.kind,
            status=response.status_code,
            error_code=_error_code(response),
        )

    raise ValueError(f"unknown step kind: {step.kind}")


def _chat_result(step: Step, response: Any) -> StepResult:
    reason_codes: list[str] = []
    action_status = None
    flags: list[str] = []
    executed_count = 0
    if response.status_code == 200:
        data = response.json()
        action_status = data.get("action_status")
        flags = data.get("security_flags", [])
        reason_codes = [d.get("reason_code") for d in data.get("decisions", [])]
        # A chat turn executed a tool when its action_status is "executed".
        executed_count = 1 if action_status == "executed" else 0
    return StepResult(
        index=0,
        kind="chat",
        status=response.status_code,
        reason_codes=[r for r in reason_codes if r],
        action_status=action_status,
        security_flags=flags,
        error_code=_error_code(response),
        executed_count=executed_count,
    )


def _execute_result(step: Step, response: Any) -> StepResult:
    reason_codes: list[str] = []
    action_status = None
    flags: list[str] = []
    approval_id = None
    executed_count = 0
    data = response.json() if response.content else {}
    if response.status_code in (200, 202) and "decision" in data:
        decision = data["decision"]
        reason_codes = [decision.get("reason_code")] if decision.get("reason_code") else []
        action_status = decision.get("outcome")
        flags = data.get("security_flags", [])
        approval_id = data.get("approval_id")
        result = data.get("result") or {}
        if result.get("status") == "executed":
            executed_count = 1
    error_code = _error_code(response)
    # A deny surfaced as an error envelope (e.g. tool_disabled, invalid_arguments,
    # constraint_violation) is still an enforced reason: record it so cases can
    # assert the *reason* enforcement denied, not just the status.
    if error_code:
        reason_codes.append(error_code)
    return StepResult(
        index=0,
        kind="execute",
        status=response.status_code,
        reason_codes=[r for r in reason_codes if r],
        action_status=action_status,
        security_flags=flags,
        error_code=error_code,
        approval_id=approval_id,
        executed_count=executed_count,
    )


def _error_code(response: Any) -> str | None:
    try:
        data = response.json()
    except ValueError:
        return None
    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        return data["error"].get("code")
    return None


def _reason_from_error(response: Any) -> list[str]:
    code = _error_code(response)
    return [code] if code else []


async def run_evaluation() -> EvaluationReport:
    """Run the entire corpus and return a complete report object."""
    started = datetime.now(UTC)
    results: list[CaseResult] = []
    for case in CASES:
        results.append(await _run_case(case))
    finished = datetime.now(UTC)

    total = len(results)
    prevented = sum(1 for r in results if r.prevented)
    false_allows = sum(1 for r in results if r.false_allow)
    false_denies = sum(1 for r in results if r.false_deny)

    by_category: dict[str, dict[str, int]] = {}
    for r in results:
        bucket = by_category.setdefault(r.category, {"total": 0, "prevented": 0})
        bucket["total"] += 1
        bucket["prevented"] += 1 if r.prevented else 0

    by_threat: dict[str, dict[str, int]] = {}
    for r in results:
        for threat in r.threat_ids:
            bucket = by_threat.setdefault(threat, {"total": 0, "prevented": 0})
            bucket["total"] += 1
            bucket["prevented"] += 1 if r.prevented else 0

    return EvaluationReport(
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        total_cases=total,
        prevented=prevented,
        failures=total - prevented,
        false_allows=false_allows,
        false_denies=false_denies,
        prevention_rate=(prevented / total) if total else 0.0,
        by_category=by_category,
        by_threat=by_threat,
        cases=results,
    )


def report_to_json(report: EvaluationReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)
