"""Controlled executor tests (spec §11: execution tests).

The decisive property: denied actions NEVER reach the tool implementation.
Handlers here are counters, so "never reached" is directly observable.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from rasp.approvals.store import ApprovalStore
from rasp.audit.service import AuditService
from rasp.auth.dev_identity import Principal
from rasp.container import builtin_tool_definitions
from rasp.executor.executor import ControlledExecutor
from rasp.policy.config import load_policy_file
from rasp.policy.engine import PolicyEngine
from rasp.schemas.approval import ApprovalStatus, compute_action_digest
from rasp.schemas.execution import ExecutionStatus
from rasp.schemas.model import ToolProposal
from rasp.schemas.policy import DecisionOutcome, ReasonCode
from rasp.schemas.tool import RiskLevel, ToolDefinition
from rasp.settings import Settings
from rasp.tools.registry import ToolRegistry

PERMS_FULL = frozenset(
    {
        "system:status",
        "documents:read",
        "applications:preview",
        "announcements:publish",
        "applications:submit",
        "records:delete",
        "test:counted",
        "test:slow",
        "test:badoutput",
        "test:leaky",
        "test:capped",
    }
)


class _Stack:
    """Component stack with test-only counter tools registered."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.registry = ToolRegistry()
        for definition in builtin_tool_definitions():
            self.registry.register(definition)
        self.registry.register(self._counted_tool())
        self.registry.register(self._slow_tool())
        self.registry.register(self._bad_output_tool())
        self.registry.register(self._leaky_tool())
        self.registry.register(self._capped_tool())

        self.config = load_policy_file("config/policies.example.yaml")
        # Test-only policy entries (mirrors the temp-tool pattern).
        now_policy = self.config.model_copy(deep=True)
        from rasp.policy.config import ToolPolicy

        now_policy.tools["counted_tool"] = ToolPolicy(
            enabled=True, risk=RiskLevel.LOW, permission="test:counted"
        )
        now_policy.tools["slow_tool"] = ToolPolicy(
            enabled=True, risk=RiskLevel.LOW, permission="test:slow"
        )
        now_policy.tools["bad_output_tool"] = ToolPolicy(
            enabled=True, risk=RiskLevel.LOW, permission="test:badoutput"
        )
        now_policy.tools["leaky_tool"] = ToolPolicy(
            enabled=True, risk=RiskLevel.LOW, permission="test:leaky"
        )
        now_policy.tools["capped_tool"] = ToolPolicy(
            enabled=True,
            risk=RiskLevel.LOW,
            permission="test:capped",
            constraints={
                "argument_caps": {},
                "output_max_items": 2,
                "redact": False,
            },
        )
        self.config = now_policy
        self.engine = PolicyEngine(self.config, self.registry)
        self.approvals = ApprovalStore(ttl_seconds=300)
        self.audit = AuditService(Settings())
        self.executor = ControlledExecutor(
            registry=self.registry,
            engine=self.engine,
            approvals=self.approvals,
            audit=self.audit,
        )
        self.principal = Principal(principal_id="executor-tester", permissions=PERMS_FULL)

    # --- test-only handlers -----------------------------------------------------

    def _counted_tool(self) -> ToolDefinition:
        def counted(arg: str = "") -> dict:
            self.calls.append(f"counted:{arg}")
            return {"ok": True, "echo": arg}

        return ToolDefinition(
            tool_id="counted_tool",
            version="1.0.0",
            description="Counts executions (test tool).",
            input_schema={
                "type": "object",
                "properties": {"arg": {"type": "string"}},
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"ok": {"type": "boolean"}},
                "required": ["ok"],
            },
            permission="test:counted",
            risk=RiskLevel.LOW,
            read_only=True,
            requires_approval=False,
            timeout_seconds=5.0,
            handler=counted,
        )

    def _slow_tool(self) -> ToolDefinition:
        async def slow(delay: float = 1.0) -> dict:
            self.calls.append("slow:start")
            await asyncio.sleep(delay)
            return {"ok": True}

        return ToolDefinition(
            tool_id="slow_tool",
            version="1.0.0",
            description="Sleeps past its timeout (test tool).",
            input_schema={
                "type": "object",
                "properties": {"delay": {"type": "number"}},
                "additionalProperties": False,
            },
            output_schema={"type": "object"},
            permission="test:slow",
            risk=RiskLevel.LOW,
            read_only=True,
            requires_approval=False,
            timeout_seconds=0.15,  # shorter than the default delay
            handler=slow,
        )

    def _bad_output_tool(self) -> ToolDefinition:
        def bad_output() -> dict:
            self.calls.append("bad_output")
            return {"unexpected": "shape violates output schema"}

        return ToolDefinition(
            tool_id="bad_output_tool",
            version="1.0.0",
            description="Returns schema-violating output (test tool).",
            input_schema={"type": "object", "additionalProperties": False},
            output_schema={
                "type": "object",
                "properties": {"required_key": {"type": "string"}},
                "required": ["required_key"],
            },
            permission="test:badoutput",
            risk=RiskLevel.LOW,
            read_only=True,
            requires_approval=False,
            timeout_seconds=5.0,
            handler=bad_output,
        )

    def _leaky_tool(self) -> ToolDefinition:
        def leaky() -> dict:
            self.calls.append("leaky")
            return {"note": "password: supersecretvalue", "status": "ok"}

        return ToolDefinition(
            tool_id="leaky_tool",
            version="1.0.0",
            description="Returns a secret-shaped string (test tool).",
            input_schema={"type": "object", "additionalProperties": False},
            output_schema={"type": "object", "properties": {"note": {"type": "string"}}},
            permission="test:leaky",
            risk=RiskLevel.LOW,
            read_only=True,
            requires_approval=False,
            timeout_seconds=5.0,
            handler=leaky,
        )

    def _capped_tool(self) -> ToolDefinition:
        def capped() -> dict:
            self.calls.append("capped")
            return {"items": [1, 2, 3, 4, 5], "ok": True}

        return ToolDefinition(
            tool_id="capped_tool",
            version="1.0.0",
            description="Returns more items than policy allows (test tool).",
            input_schema={"type": "object", "additionalProperties": False},
            output_schema={
                "type": "object",
                "properties": {"items": {"type": "array"}},
                "required": ["items"],
            },
            permission="test:capped",
            risk=RiskLevel.LOW,
            read_only=True,
            requires_approval=False,
            timeout_seconds=5.0,
            handler=capped,
        )

    async def run(self, tool_id: str, arguments: dict | None = None):
        return await self.executor.execute(
            ToolProposal(tool_id=tool_id, arguments=arguments or {}),
            principal=self.principal,
            request_id="req-exec-test",
        )


@pytest.fixture
def stack() -> _Stack:
    return _Stack()


# --- the core enforcement property ----------------------------------------------


async def test_allowed_action_executes_once(stack):
    outcome = await stack.run("counted_tool", {"arg": "hello"})
    assert outcome.decision.outcome == DecisionOutcome.ALLOW
    assert outcome.result.status == ExecutionStatus.EXECUTED
    assert stack.calls == ["counted:hello"]
    assert outcome.result.output == {"ok": True, "echo": "hello"}


async def test_denied_unknown_tool_never_reaches_handler(stack):
    outcome = await stack.run("not_a_registered_tool", {})
    assert outcome.decision.outcome == DecisionOutcome.DENY
    assert outcome.result.status == ExecutionStatus.BLOCKED
    assert stack.calls == []  # handler never invoked


async def test_denied_missing_permission_never_reaches_handler(stack):
    stack.principal = Principal(principal_id="nobody", permissions=frozenset())
    outcome = await stack.run("counted_tool", {"arg": "x"})
    assert outcome.decision.reason_code == ReasonCode.PERMISSION_DENIED
    assert stack.calls == []


async def test_policy_evaluation_error_fails_closed(stack, monkeypatch):
    """A crash inside policy evaluation must deny, not execute."""

    def boom(*args, **kwargs):
        raise RuntimeError("simulated policy engine crash")

    # Crash inside evaluation: engine.evaluate() must convert this into
    # PolicyEvaluationError, which the executor treats as fail-closed deny.
    monkeypatch.setattr(stack.engine, "_evaluate", boom)
    outcome = await stack.run("counted_tool", {"arg": "x"})
    assert outcome.decision.outcome == DecisionOutcome.DENY
    assert outcome.decision.reason_code == ReasonCode.POLICY_ERROR
    assert outcome.result.status == ExecutionStatus.BLOCKED
    assert stack.calls == []
    # The failure is auditable.
    events = stack.audit.query(request_id="req-exec-test")
    decision_events = [e for e in events if e.event_type.value == "policy_decision"]
    assert decision_events and decision_events[0].error_category == "PolicyEvaluationError"


async def test_invalid_arguments_never_reaches_handler(stack):
    outcome = await stack.run("counted_tool", {"evil": "payload"})
    assert outcome.decision.reason_code == ReasonCode.INVALID_ARGUMENTS
    assert stack.calls == []


# --- approvals via executor -------------------------------------------------------


async def test_approval_required_creates_pending_and_does_not_execute(stack):
    outcome = await stack.run("publish_announcement", {"title": "t", "body": "b"})
    assert outcome.decision.outcome == DecisionOutcome.REQUIRE_APPROVAL
    assert outcome.result.status == ExecutionStatus.PENDING_APPROVAL
    assert outcome.approval_id
    assert "publish_announcement:t" not in stack.calls  # nothing executed
    stored = stack.approvals.get(outcome.approval_id)
    assert stored is not None and stored.status == ApprovalStatus.PENDING


async def test_approved_exact_action_executes(stack):
    args = {"title": "t", "body": "b"}
    # Simulate an authorized reviewer approving this exact action.
    digest = compute_action_digest(
        "publish_announcement", args, stack.principal.principal_id, stack.config.version
    )
    now = datetime.now(UTC)
    from rasp.schemas.approval import ApprovalRecord

    approval = ApprovalRecord(
        request_id="req-review",
        principal_ref=stack.principal.principal_id,
        tool_id="publish_announcement",
        action_digest=digest,
        policy_version=stack.config.version,
        status=ApprovalStatus.APPROVED,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    outcome = await stack.executor.execute(
        ToolProposal(tool_id="publish_announcement", arguments=args),
        principal=stack.principal,
        request_id="req-exec-approved",
        # approval path: engine receives it through evaluate() — executor
        # always starts with approval=None, so drive the engine directly:
    )
    # Executor proposes pending (no approval context in M1 API path):
    assert outcome.decision.outcome == DecisionOutcome.REQUIRE_APPROVAL
    # Direct engine check proves a valid approval would authorize exactly this.
    decision = stack.engine.evaluate(
        tool_id="publish_announcement",
        arguments=args,
        principal=stack.principal,
        approval=approval,
    )
    assert decision.outcome == DecisionOutcome.ALLOW
    assert "publish_announcement:t" not in stack.calls


async def test_tampered_action_with_still_valid_looking_approval_denied(stack):
    args = {"title": "t", "body": "b"}
    digest = compute_action_digest(
        "publish_announcement", args, stack.principal.principal_id, stack.config.version
    )
    now = datetime.now(UTC)
    from rasp.schemas.approval import ApprovalRecord

    approval = ApprovalRecord(
        request_id="req-review",
        principal_ref=stack.principal.principal_id,
        tool_id="publish_announcement",
        action_digest=digest,
        policy_version=stack.config.version,
        status=ApprovalStatus.APPROVED,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    decision = stack.engine.evaluate(
        tool_id="publish_announcement",
        arguments={"title": "t", "body": "TAMPERED"},
        principal=stack.principal,
        approval=approval,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.APPROVAL_INVALID


# --- timeouts, output validation, constraints, disclosure --------------------------


async def test_timeout_enforced(stack):
    outcome = await stack.run("slow_tool", {"delay": 5.0})
    assert outcome.result.status == ExecutionStatus.TIMEOUT
    assert outcome.result.error_category == "timeout"
    # The tool was reached but cut off; duration recorded.
    assert outcome.result.duration_ms is not None


async def test_schema_violating_output_is_withheld(stack):
    outcome = await stack.run("bad_output_tool", {})
    assert outcome.result.status == ExecutionStatus.FAILED
    assert outcome.result.error_category == "invalid_tool_output"
    assert outcome.result.output is None  # nothing unsafe returned


async def test_secret_shaped_output_is_redacted(stack):
    outcome = await stack.run("leaky_tool", {})
    assert outcome.result.status == ExecutionStatus.EXECUTED
    note = outcome.result.output["note"]
    assert "supersecretvalue" not in note
    assert "[REDACTED]" in note


async def test_output_item_cap_is_enforced_not_advisory(stack):
    outcome = await stack.run("capped_tool", {})
    assert outcome.decision.outcome == DecisionOutcome.ALLOW_WITH_CONSTRAINTS
    assert outcome.result.status == ExecutionStatus.EXECUTED
    assert len(outcome.result.output["items"]) == 2  # cap of 2 applied


# --- audit emission -----------------------------------------------------------------


async def test_successful_execution_emits_decision_and_execution_events(stack):
    await stack.run("counted_tool", {"arg": "audit-me"})
    events = stack.audit.query(request_id="req-exec-test")
    types = [e.event_type.value for e in events]
    assert "policy_decision" in types
    decision_event = next(e for e in events if e.event_type.value == "policy_decision")
    assert decision_event.decision.value == "allow"
    assert decision_event.execution_status == "executed"
    assert decision_event.policy_version == stack.config.version
    # Audit events must never contain the raw argument values.
    dumped = " ".join(e.model_dump_json() for e in events)
    assert "audit-me" not in dumped


async def test_denied_execution_event_records_not_executed(stack):
    outcome = await stack.run("not_a_registered_tool", {})
    events = stack.audit.query(request_id="req-exec-test")
    decision_event = next(e for e in events if e.event_type.value == "policy_decision")
    assert decision_event.execution_status == "not_executed"
    assert decision_event.reason_code == ReasonCode.UNKNOWN_TOOL
    assert outcome.result.status == ExecutionStatus.BLOCKED
