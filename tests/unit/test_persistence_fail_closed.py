"""Fail-closed persistence tests (Milestone 2 acceptance, no DB required).

Core guarantee under test: **database failure prevents sensitive actions
from executing.** Handlers here are counters, so "never reached" is
directly observable. These tests use failing store doubles — they run in
the default suite without PostgreSQL.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from rasp.approvals.store import ApprovalBackend, ApprovalStore, InvalidApprovalTransition
from rasp.audit.service import AuditService
from rasp.auth.dev_identity import Principal
from rasp.container import builtin_tool_definitions
from rasp.executor.executor import ControlledExecutor
from rasp.policy.config import ToolPolicy, load_policy_file
from rasp.policy.engine import PolicyEngine
from rasp.schemas.approval import ApprovalRecord, ApprovalStatus, compute_action_digest
from rasp.schemas.audit import AuditEvent, AuditEventType
from rasp.schemas.model import ToolProposal
from rasp.schemas.policy import DecisionOutcome, ReasonCode
from rasp.schemas.tool import RiskLevel, ToolDefinition
from rasp.settings import Settings
from rasp.tools import builtin
from rasp.tools.registry import ToolRegistry

PERMS = frozenset({"system:status", "documents:read", "announcements:publish", "test:mutating"})


class FailingAuditStore:
    """Persistence down: every audit write raises."""

    async def record(self, event: AuditEvent) -> AuditEvent:
        raise ConnectionError("database unavailable (test double)")

    async def query(self, **kwargs):  # noqa: ANN003, ANN201
        raise ConnectionError("database unavailable (test double)")

    async def count(self) -> int:
        raise ConnectionError("database unavailable (test double)")


class FailingApprovalBackend(ApprovalBackend):
    async def create(self, record):  # noqa: ANN201
        raise ConnectionError("database unavailable (test double)")

    async def get_or_expire(self, approval_id, now):  # noqa: ANN001, ANN201
        raise ConnectionError("database unavailable (test double)")

    async def find_for_action(self, action_digest, principal_ref, tool_id, now):  # noqa: ANN001, ANN201
        raise ConnectionError("database unavailable (test double)")

    async def all(self):  # noqa: ANN201
        raise ConnectionError("database unavailable (test double)")

    async def save_status(self, record, *, expected_status):  # noqa: ANN201
        raise ConnectionError("database unavailable (test double)")

    async def claim(self, approval_id, now):  # noqa: ANN001, ANN201
        raise ConnectionError("database unavailable (test double)")


class _Stack:
    """Executor stack with a MUTATING allow tool and failing persistence."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.registry = ToolRegistry()
        for definition in builtin_tool_definitions():
            self.registry.register(definition)
        self.registry.register(self._mutating_tool())

        config = load_policy_file("config/policies.example.yaml").model_copy(deep=True)
        config.tools["mutating_tool"] = ToolPolicy(
            enabled=True, risk=RiskLevel.MEDIUM, permission="test:mutating"
        )
        self.engine = PolicyEngine(config, self.registry)

        self.settings = Settings(persistence="in_memory")
        self.audit = AuditService(self.settings, store=FailingAuditStore())
        self.approvals = ApprovalStore(ttl_seconds=60, backend=FailingApprovalBackend())
        self.executor = ControlledExecutor(
            registry=self.registry,
            engine=self.engine,
            approvals=self.approvals,
            audit=self.audit,
        )
        self.principal = Principal(principal_id="fail-closed-tester", permissions=PERMS)

    def _mutating_tool(self) -> ToolDefinition:
        def mutating() -> dict:
            self.calls.append("mutated")
            return {"ok": True}

        return ToolDefinition(
            tool_id="mutating_tool",
            version="1.0.0",
            description="Mutating test tool (test-only).",
            input_schema={"type": "object", "additionalProperties": False},
            output_schema={"type": "object", "properties": {"ok": {"type": "boolean"}}},
            permission="test:mutating",
            risk=RiskLevel.MEDIUM,
            read_only=False,  # the property under test
            requires_approval=False,
            timeout_seconds=5.0,
            handler=mutating,
        )

    async def run(self, tool_id: str, arguments: dict | None = None):
        return await self.executor.execute(
            ToolProposal(tool_id=tool_id, arguments=arguments or {}),
            principal=self.principal,
            request_id="req-fail-closed",
        )


@pytest.fixture
def stack() -> _Stack:
    return _Stack()


async def test_mutating_action_denied_when_audit_persistence_fails(stack):
    """DB down + mutating tool -> persistence_error deny, handler never runs."""
    outcome = await stack.run("mutating_tool")
    assert outcome.decision.outcome == DecisionOutcome.DENY
    assert outcome.decision.reason_code == ReasonCode.PERSISTENCE_ERROR
    assert outcome.result.status.value == "blocked"
    assert stack.calls == []  # the handler was never reached
    assert "audit_persistence_failed" in outcome.security_flags


async def test_read_only_action_executes_with_documented_fallback(stack):
    """DB down + read-only tool -> executes (spec-permitted fallback) + flag."""
    outcome = await stack.run("system_status")
    assert outcome.decision.outcome == DecisionOutcome.ALLOW
    assert outcome.result.status.value == "executed"
    assert outcome.result.output["status"] == "ok"
    assert "audit_persistence_failed" in outcome.security_flags


async def test_approval_creation_failure_denies_instead_of_parking(stack):
    """A pending approval that cannot be persisted must deny, not 'succeed'."""
    outcome = await stack.run("publish_announcement", {"title": "t", "body": "b"})
    assert outcome.decision.outcome == DecisionOutcome.DENY
    assert outcome.decision.reason_code == ReasonCode.PERSISTENCE_ERROR
    assert outcome.approval_id is None
    assert stack.calls == []


async def test_approval_lookup_failure_denies_instead_of_parking(stack):
    """If the approval state cannot be read, the action is denied (fail closed).

    The lookup happens before parking: an unknowable approval state must never
    be treated as 'no approval exists'.
    """
    outcome = await stack.run("publish_announcement", {"title": "t", "body": "b"})
    assert outcome.decision.outcome == DecisionOutcome.DENY
    assert outcome.decision.reason_code == ReasonCode.PERSISTENCE_ERROR
    assert stack.calls == []


class _ClaimFailBackend(ApprovalBackend):
    """Reads succeed (so an approved record is found) but the atomic claim
    fails as if the database dropped between lookup and consumption."""

    def __init__(self) -> None:
        self.inner = ApprovalStore(ttl_seconds=60).backend

    async def create(self, record):
        return await self.inner.create(record)

    async def get_or_expire(self, approval_id, now):
        return await self.inner.get_or_expire(approval_id, now)

    async def find_for_action(self, action_digest, principal_ref, tool_id, now):
        return await self.inner.find_for_action(action_digest, principal_ref, tool_id, now)

    async def all(self):
        return await self.inner.all()

    async def save_status(self, record, *, expected_status):
        return await self.inner.save_status(record, expected_status=expected_status)

    async def claim(self, approval_id, now):
        raise ConnectionError("database unavailable at claim time (test double)")


async def test_claim_failure_after_approval_denies_without_executing():
    """A DB outage at claim time denies and never reaches the handler."""
    registry = ToolRegistry()
    for definition in builtin_tool_definitions():
        registry.register(definition)
    config = load_policy_file("config/policies.example.yaml")
    engine = PolicyEngine(config, registry)
    approvals = ApprovalStore(ttl_seconds=60, backend=_ClaimFailBackend())
    # A WORKING audit store: this test isolates the claim-time failure.
    audit = AuditService(Settings(persistence="in_memory"))
    executor = ControlledExecutor(
        registry=registry, engine=engine, approvals=approvals, audit=audit
    )
    principal = Principal(principal_id="claim-fail", permissions=PERMS)

    # Seed an approved record through the real in-memory backend.
    digest = compute_action_digest(
        "publish_announcement", {"title": "t", "body": "b"}, "claim-fail", "1.0"
    )
    record = await approvals.backend.inner.create(
        ApprovalRecord(
            request_id="r",
            principal_ref=audit.principal_ref("claim-fail"),
            tool_id="publish_announcement",
            action_digest=digest,
            policy_version="1.0",
            status=ApprovalStatus.APPROVED,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )

    outcome = await executor.execute(
        ToolProposal(tool_id="publish_announcement", arguments={"title": "t", "body": "b"}),
        principal=principal,
        request_id="req-claim-fail",
    )
    assert outcome.decision.outcome == DecisionOutcome.DENY
    assert outcome.decision.reason_code == ReasonCode.PERSISTENCE_ERROR
    assert builtin.EXECUTION_LOG == []  # handler never reached
    assert record.approval_id  # the approved record existed


async def test_deny_still_denies_when_persistence_is_down(stack):
    """Even with persistence down, ordinary denies keep denying (never allow)."""
    outcome = await stack.run("not_a_registered_tool")
    assert outcome.decision.outcome == DecisionOutcome.DENY
    assert outcome.decision.reason_code == ReasonCode.UNKNOWN_TOOL
    assert stack.calls == []


async def test_postgres_store_raises_through_failing_database():
    """The real Postgres store surfaces DB failures (no silent swallowing)."""
    from rasp.persistence.db import FailingDatabase
    from rasp.persistence.repositories import PolicyRepository, PostgresAuditStore

    settings = Settings(persistence="postgres")
    config = load_policy_file("config/policies.example.yaml")
    failing_db = FailingDatabase(settings)
    store = PostgresAuditStore(failing_db, PolicyRepository(failing_db, config))
    service = AuditService(settings, store=store)
    with pytest.raises(ConnectionError):
        await service.record(
            AuditEvent(
                request_id="r",
                correlation_id="r",
                timestamp=datetime.now(UTC),
                principal_ref="pid_x",
                event_type=AuditEventType.REQUEST_RECEIVED,
            )
        )


def test_unknown_persistence_mode_refuses_startup():
    """No silent fallback: a typo in RASP_PERSISTENCE must fail loudly."""
    from rasp.container import build_container

    with pytest.raises(ValueError, match="no silent fallback"):
        build_container(Settings(policy_path="config/policies.example.yaml", persistence="sqlite"))


async def test_transition_guards_reject_races():
    """Backend-level optimistic guard: stale expected status -> rejected."""
    from rasp.schemas.approval import ApprovalStatus

    store = ApprovalStore(ttl_seconds=60)
    record = await store.create_pending(
        request_id="r",
        principal_ref="p",
        tool_id="t",
        action_digest="d" * 64,
        policy_version="1.0",
    )
    # Simulate a concurrent writer flipping the status first.
    store.backend._records[record.approval_id] = record.model_copy(
        update={"status": ApprovalStatus.REJECTED}
    )
    stale = record.model_copy(update={"status": ApprovalStatus.APPROVED})
    with pytest.raises(InvalidApprovalTransition):
        await store.backend.save_status(stale, expected_status=ApprovalStatus.PENDING)
