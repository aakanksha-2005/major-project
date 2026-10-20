"""Milestone 3 concurrency: an approval authorizes exactly one execution.

When several identical approved requests race, the atomic claim
(approved -> consumed) must let exactly one win; every other caller is
denied and never reaches the tool handler. This runs against the real
in-memory backend, without PostgreSQL.
"""

from __future__ import annotations

import asyncio

from rasp.approvals.store import ApprovalStore
from rasp.audit.service import AuditService
from rasp.auth.dev_identity import Principal
from rasp.container import builtin_tool_definitions
from rasp.executor.executor import ControlledExecutor
from rasp.policy.config import load_policy_file
from rasp.policy.engine import PolicyEngine
from rasp.schemas.execution import ExecutionStatus
from rasp.schemas.model import ToolProposal
from rasp.schemas.policy import DecisionOutcome, ReasonCode
from rasp.settings import Settings
from rasp.tools import builtin
from rasp.tools.registry import ToolRegistry

ARGS = {"title": "race", "body": "b"}
PERMS = frozenset({"announcements:publish"})
REQUESTER = "pid_race_requester"
REVIEWER = "pid_race_reviewer"


def _stack() -> tuple[ControlledExecutor, ApprovalStore, Principal]:
    registry = ToolRegistry()
    for definition in builtin_tool_definitions():
        registry.register(definition)
    config = load_policy_file("config/policies.example.yaml")
    engine = PolicyEngine(config, registry)
    approvals = ApprovalStore(ttl_seconds=60)
    audit = AuditService(Settings(persistence="in_memory"))
    executor = ControlledExecutor(
        registry=registry, engine=engine, approvals=approvals, audit=audit
    )
    return executor, approvals, Principal(principal_id="race-requester", permissions=PERMS)


async def test_concurrent_approved_executions_run_exactly_once():
    executor, approvals, principal = _stack()

    # Park the action, then approve it from a different principal.
    parked = await executor.execute(
        ToolProposal(tool_id="publish_announcement", arguments=ARGS),
        principal=principal,
        request_id="race-1",
    )
    approval_id = parked.approval_id
    assert parked.decision.outcome == DecisionOutcome.REQUIRE_APPROVAL
    await approvals.decide(approval_id, "approve", reviewer_ref=REVIEWER)
    assert builtin.EXECUTION_LOG == []

    # Fire many identical executions of the now-approved action concurrently.
    async def run(index: int):
        return await executor.execute(
            ToolProposal(tool_id="publish_announcement", arguments=ARGS),
            principal=principal,
            request_id=f"race-exec-{index}",
        )

    outcomes = await asyncio.gather(*(run(i) for i in range(8)))

    executed = [o for o in outcomes if o.result.status == ExecutionStatus.EXECUTED]
    # Exactly one execution won the claim.
    assert len(executed) == 1
    assert builtin.EXECUTION_LOG == ["publish_announcement:race"]

    # The approval is consumed exactly once.
    record = await approvals.get(approval_id)
    assert record is not None and record.status.value == "consumed"

    # Every other caller failed closed: either denied (claim lost the race /
    # approval no longer valid) or re-parked on a fresh approval cycle. In no
    # case does a second caller execute the action.
    for outcome in outcomes:
        if outcome.result.status == ExecutionStatus.EXECUTED:
            continue
        assert outcome.decision.outcome in (
            DecisionOutcome.DENY,
            DecisionOutcome.REQUIRE_APPROVAL,
        )
        if outcome.decision.outcome == DecisionOutcome.DENY:
            assert outcome.decision.reason_code == ReasonCode.APPROVAL_INVALID
        assert outcome.result.status in (
            ExecutionStatus.BLOCKED,
            ExecutionStatus.PENDING_APPROVAL,
        )


async def test_concurrent_decisions_leave_one_consistent_state():
    """Racing approve calls converge: one transition, idempotent repeats OK."""
    _, approvals, principal = _stack()
    parked = await approvals.create_pending(
        request_id="r",
        principal_ref=REQUESTER,
        tool_id="publish_announcement",
        action_digest="a" * 64,
        policy_version="1.0",
    )

    results = await asyncio.gather(
        *(approvals.decide(parked.approval_id, "approve", reviewer_ref=REVIEWER) for _ in range(6)),
        return_exceptions=True,
    )
    statuses = {r.status.value for r in results if not isinstance(r, Exception)}
    # All successful results agree; the record ends APPROVED exactly once.
    final = await approvals.get(parked.approval_id)
    assert final.status.value == "approved"
    assert statuses == {"approved"}
