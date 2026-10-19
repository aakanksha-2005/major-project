"""Policy engine decision tests (spec §11: policy tests).

Covered: default deny, disabled tools, missing permissions, invalid
arguments, argument caps, approval binding (absence, tampering, expiry),
precedence, missing policy entries, and fail-closed evaluation errors.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from rasp.auth.dev_identity import Principal
from rasp.container import builtin_tool_definitions
from rasp.policy.config import load_policy_file
from rasp.policy.engine import PolicyEngine, PolicyEvaluationError
from rasp.schemas.approval import (
    ApprovalRecord,
    ApprovalStatus,
    compute_action_digest,
)
from rasp.schemas.policy import DecisionOutcome, ReasonCode
from rasp.tools.registry import ToolRegistry

PERMS_FULL = frozenset(
    {
        "system:status",
        "documents:read",
        "applications:preview",
        "announcements:publish",
        "applications:submit",
        "records:delete",
    }
)


@pytest.fixture
def registry() -> ToolRegistry:
    registry = ToolRegistry()
    for definition in builtin_tool_definitions():
        registry.register(definition)
    return registry


@pytest.fixture
def engine(registry: ToolRegistry) -> PolicyEngine:
    config = load_policy_file("config/policies.example.yaml")
    return PolicyEngine(config, registry)


@pytest.fixture
def principal() -> Principal:
    return Principal(principal_id="tester", permissions=PERMS_FULL)


def _approval_for(
    engine: PolicyEngine,
    tool_id: str,
    arguments: dict,
    principal_id: str,
    status: ApprovalStatus = ApprovalStatus.APPROVED,
    policy_version: str | None = None,
    expires_in: timedelta = timedelta(minutes=10),
) -> ApprovalRecord:
    version = policy_version or engine.policy_version
    now = datetime.now(UTC)
    return ApprovalRecord(
        request_id="req-test",
        principal_ref=principal_id,
        tool_id=tool_id,
        action_digest=compute_action_digest(tool_id, arguments, principal_id, version),
        policy_version=version,
        status=status,
        created_at=now,
        expires_at=now + expires_in,
    )


# --- default deny and disabled tools -----------------------------------------


def test_unknown_tool_is_denied(engine, principal):
    decision = engine.evaluate(tool_id="exfiltrate_credentials", arguments={}, principal=principal)
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.UNKNOWN_TOOL


def test_disabled_tool_cannot_execute(engine, principal):
    """Even a principal holding the exact permission cannot run a disabled tool."""
    decision = engine.evaluate(
        tool_id="record_delete",
        arguments={"record_id": "syn-rec-001"},
        principal=principal,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.TOOL_DISABLED


def test_missing_principal_denies(engine):
    decision = engine.evaluate(tool_id="system_status", arguments={}, principal=None)
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.AUTHENTICATION_REQUIRED


# --- permissions --------------------------------------------------------------


def test_missing_permission_denies(engine):
    weak = Principal(principal_id="weak", permissions=frozenset())
    decision = engine.evaluate(tool_id="system_status", arguments={}, principal=weak)
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.PERMISSION_DENIED
    assert decision.required_permission == "system:status"


def test_permission_held_allows(engine, principal):
    decision = engine.evaluate(tool_id="system_status", arguments={}, principal=principal)
    assert decision.outcome == DecisionOutcome.ALLOW
    assert decision.reason_code == ReasonCode.ALLOWED


# --- argument validation and caps ---------------------------------------------


def test_invalid_arguments_denied(engine, principal):
    decision = engine.evaluate(
        tool_id="document_search",
        arguments={"max_results": "three"},  # missing query, wrong type
        principal=principal,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.INVALID_ARGUMENTS


def test_unexpected_argument_keys_denied(engine, principal):
    decision = engine.evaluate(
        tool_id="document_search",
        arguments={"query": "x", "extra": "evil"},
        principal=principal,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.INVALID_ARGUMENTS


def test_policy_argument_cap_denied(engine, principal):
    """Schema-valid arguments above the policy cap are still denied.

    The schema allows up to 100; the policy cap is 5 — 50 is schema-valid
    yet must be denied by the stricter policy constraint.
    """
    decision = engine.evaluate(
        tool_id="document_search",
        arguments={"query": "index", "max_results": 50},
        principal=principal,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.CONSTRAINT_VIOLATION


def test_constrained_allow_reports_constraints(engine, principal):
    decision = engine.evaluate(
        tool_id="document_search",
        arguments={"query": "index", "max_results": 3},
        principal=principal,
    )
    assert decision.outcome == DecisionOutcome.ALLOW_WITH_CONSTRAINTS
    assert decision.constraints["output_max_items"] == 5
    assert decision.constraints["argument_caps"]["max_results"] == 5


# --- approvals ----------------------------------------------------------------


def test_approval_required_when_absent(engine, principal):
    decision = engine.evaluate(
        tool_id="publish_announcement",
        arguments={"title": "t", "body": "b"},
        principal=principal,
    )
    assert decision.outcome == DecisionOutcome.REQUIRE_APPROVAL
    assert decision.reason_code == ReasonCode.APPROVAL_REQUIRED
    assert decision.approval_required is True


def test_valid_approval_allows(engine, principal):
    args = {"title": "t", "body": "b"}
    approval = _approval_for(engine, "publish_announcement", args, principal.principal_id)
    decision = engine.evaluate(
        tool_id="publish_announcement",
        arguments=args,
        principal=principal,
        approval=approval,
    )
    assert decision.outcome == DecisionOutcome.ALLOW
    assert decision.approval_id == approval.approval_id


def test_tampered_arguments_invalidate_approval(engine, principal):
    """Approval bound to exact args: any modification invalidates it."""
    approved_args = {"title": "t", "body": "original"}
    approval = _approval_for(engine, "publish_announcement", approved_args, principal.principal_id)
    tampered_args = {"title": "t", "body": "TAMPERED"}
    decision = engine.evaluate(
        tool_id="publish_announcement",
        arguments=tampered_args,
        principal=principal,
        approval=approval,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.APPROVAL_INVALID


def test_approval_bound_to_principal_not_transferable(engine, principal):
    args = {"title": "t", "body": "b"}
    approval = _approval_for(engine, "publish_announcement", args, "someone-else")
    decision = engine.evaluate(
        tool_id="publish_announcement",
        arguments=args,
        principal=principal,
        approval=approval,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.APPROVAL_INVALID


def test_expired_approval_denied(engine, principal):
    args = {"title": "t", "body": "b"}
    approval = _approval_for(
        engine,
        "publish_announcement",
        args,
        principal.principal_id,
        expires_in=timedelta(seconds=-1),
    )
    decision = engine.evaluate(
        tool_id="publish_announcement",
        arguments=args,
        principal=principal,
        approval=approval,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.APPROVAL_INVALID


def test_rejected_approval_denied(engine, principal):
    args = {"title": "t", "body": "b"}
    approval = _approval_for(
        engine,
        "publish_announcement",
        args,
        principal.principal_id,
        status=ApprovalStatus.REJECTED,
    )
    decision = engine.evaluate(
        tool_id="publish_announcement",
        arguments=args,
        principal=principal,
        approval=approval,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.APPROVAL_INVALID


def test_pending_approval_yields_require_not_allow(engine, principal):
    args = {"title": "t", "body": "b"}
    approval = _approval_for(
        engine,
        "publish_announcement",
        args,
        principal.principal_id,
        status=ApprovalStatus.PENDING,
    )
    decision = engine.evaluate(
        tool_id="publish_announcement",
        arguments=args,
        principal=principal,
        approval=approval,
    )
    assert decision.outcome == DecisionOutcome.REQUIRE_APPROVAL


def test_policy_version_change_invalidates_approval(engine, principal):
    """An approval issued under an older policy version needs re-approval."""
    args = {"title": "t", "body": "b"}
    approval = _approval_for(
        engine,
        "publish_announcement",
        args,
        principal.principal_id,
        policy_version="0.9-old",
    )
    decision = engine.evaluate(
        tool_id="publish_announcement",
        arguments=args,
        principal=principal,
        approval=approval,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.APPROVAL_INVALID


# --- policy entry and precedence ----------------------------------------------


def test_missing_policy_entry_denies(engine, principal):
    """A registered tool with no policy entry fails closed."""
    config = engine._config.model_copy(deep=True)
    del config.tools["application_preview"]
    engine._config = config  # simulate a config/registry gap
    decision = engine.evaluate(
        tool_id="application_preview",
        arguments={"application_id": "syn-app-001"},
        principal=principal,
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason_code == ReasonCode.POLICY_ENTRY_MISSING


def test_internal_evaluation_error_raises(engine, principal, monkeypatch):
    """Policy evaluation failure surfaces as PolicyEvaluationError (fail closed)."""

    def boom(*args, **kwargs):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(engine._registry, "validate_arguments", boom)
    with pytest.raises(PolicyEvaluationError):
        engine.evaluate(tool_id="system_status", arguments={}, principal=principal)


def test_decision_carries_policy_version_and_reason(engine, principal):
    decision = engine.evaluate(tool_id="system_status", arguments={}, principal=principal)
    assert decision.policy_version == engine.policy_version
    assert decision.decision_id
    assert decision.message
    assert decision.decided_at is not None
