"""Controlled executor (spec §3.G, §8).

This is THE trusted execution boundary. Every model-proposed tool call is
routed here; the tool implementation is only reached after a fresh policy
decision. Denied actions never call the handler.

Order of operations (per spec §8):
  1. Accept proposed call           6. Enforce constraints
  2. Validate tool identifier       7. Apply timeout
  3. Validate arguments             8. Execute registered handler only
  4. Fresh policy evaluation        9. Validate + screen result
  5. Deny / require approval       10. Emit audit events

Milestone 2 persistence rules (fail closed):
  - A MUTATING tool must be durably audited (pre-execution authorization
    event) before its handler runs. If persistence is unavailable the
    action is denied with reason `persistence_error` — the handler is
    never reached.
  - Approval creation requires persistence; failure denies with
    `persistence_error`.
  - READ-ONLY tools may execute when post-hoc audit persistence fails
    (documented fallback, docs/LIMITATIONS.md); the outcome carries an
    `audit_persistence_failed` security flag.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from datetime import UTC, datetime
from typing import Any

import jsonschema

from rasp.approvals.store import ApprovalStore
from rasp.audit.service import AuditService
from rasp.auth.dev_identity import Principal
from rasp.policy.engine import PolicyEngine, PolicyEvaluationError
from rasp.privacy.redaction import screen_output_payload, truncate_items
from rasp.schemas.approval import compute_action_digest
from rasp.schemas.audit import AuditEvent, AuditEventType
from rasp.schemas.chat import DecisionSummary
from rasp.schemas.execution import (
    ExecutionOutcome,
    ExecutionResult,
    ExecutionStatus,
)
from rasp.schemas.model import ToolProposal
from rasp.schemas.policy import DecisionOutcome, PolicyDecision, ReasonCode
from rasp.tools.registry import ToolRegistry

logger = logging.getLogger("rasp.executor")

AUDIT_PERSISTENCE_FLAG = "audit_persistence_failed"


class ControlledExecutor:
    def __init__(
        self,
        *,
        registry: ToolRegistry,
        engine: PolicyEngine,
        approvals: ApprovalStore,
        audit: AuditService,
    ) -> None:
        self._registry = registry
        self._engine = engine
        self._approvals = approvals
        self._audit = audit

    async def execute(
        self,
        proposal: ToolProposal,
        *,
        principal: Principal | None,
        request_id: str,
        correlation_id: str | None = None,
        risk_flags: list[str] | None = None,
    ) -> ExecutionOutcome:
        correlation = correlation_id or request_id
        flags = list(risk_flags or [])
        principal_ref = self._audit.principal_ref(
            principal.principal_id if principal else "unauthenticated"
        )

        # 1-4. Fresh policy evaluation (validates id, schema, permission,
        # approval, constraints). Policy failure -> fail closed.
        try:
            decision = self._engine.evaluate(
                tool_id=proposal.tool_id,
                arguments=proposal.arguments,
                principal=principal,
            )
        except PolicyEvaluationError as exc:
            decision = PolicyDecision(
                outcome=DecisionOutcome.DENY,
                reason_code=ReasonCode.POLICY_ERROR,
                message="Policy evaluation failed; the action was denied.",
                policy_version=self._engine.policy_version,
                tool_id=proposal.tool_id,
            )
            await self._emit_decision(
                decision,
                principal_ref=principal_ref,
                request_id=request_id,
                correlation_id=correlation,
                execution_status="not_executed",
                error_category=type(exc).__name__,
                flags=flags,
            )
            return ExecutionOutcome(
                decision=decision,
                result=ExecutionResult(
                    tool_id=proposal.tool_id,
                    status=ExecutionStatus.BLOCKED,
                    error_category=ReasonCode.POLICY_ERROR.value,
                ),
                security_flags=flags,
            )

        # 5a. Deny: record and return — the handler is never invoked.
        if decision.outcome == DecisionOutcome.DENY:
            await self._emit_decision(
                decision,
                principal_ref=principal_ref,
                request_id=request_id,
                correlation_id=correlation,
                execution_status="not_executed",
                flags=flags,
            )
            return ExecutionOutcome(
                decision=decision,
                result=ExecutionResult(
                    tool_id=proposal.tool_id,
                    status=ExecutionStatus.BLOCKED,
                    error_category=decision.reason_code.value,
                ),
                security_flags=flags,
            )

        # 5b. Approval required: create a persistent pending record. If the
        # record cannot be persisted, fail closed (deny) — an unpersistable
        # approval could never be honored later anyway.
        if decision.outcome == DecisionOutcome.REQUIRE_APPROVAL:
            digest = compute_action_digest(
                proposal.tool_id,
                proposal.arguments,
                principal.principal_id if principal else "unauthenticated",
                decision.policy_version,
            )
            try:
                approval = await self._approvals.create_pending(
                    request_id=request_id,
                    principal_ref=principal_ref,
                    tool_id=proposal.tool_id,
                    action_digest=digest,
                    policy_version=decision.policy_version,
                )
            except Exception:
                logger.exception(
                    "approval persistence failed for %s — failing closed",
                    proposal.tool_id,
                )
                return await self._deny_persistence(
                    proposal,
                    policy_version=decision.policy_version,
                    principal_ref=principal_ref,
                    request_id=request_id,
                    correlation_id=correlation,
                    flags=flags,
                )
            decision = decision.model_copy(update={"approval_id": approval.approval_id})
            await self._emit_decision(
                decision,
                principal_ref=principal_ref,
                request_id=request_id,
                correlation_id=correlation,
                execution_status="pending_approval",
                approval_id=approval.approval_id,
                flags=flags,
            )
            await self._safe_record(
                AuditEvent(
                    request_id=request_id,
                    correlation_id=correlation,
                    timestamp=datetime.now(UTC),
                    principal_ref=principal_ref,
                    event_type=AuditEventType.APPROVAL_CREATED,
                    tool_id=proposal.tool_id,
                    policy_version=decision.policy_version,
                    decision=decision.outcome,
                    reason_code=decision.reason_code,
                    approval_id=approval.approval_id,
                    execution_status="pending_approval",
                    action_digest=digest,
                    security_flags=flags,
                ),
                flags=flags,
            )
            return ExecutionOutcome(
                decision=decision,
                result=ExecutionResult(
                    tool_id=proposal.tool_id,
                    status=ExecutionStatus.PENDING_APPROVAL,
                ),
                approval_id=approval.approval_id,
                security_flags=flags,
            )

        # 6. ALLOW / ALLOW_WITH_CONSTRAINTS: reach the registered handler.
        definition = self._registry.require(proposal.tool_id)

        # Mutating tools must be durably audited BEFORE execution. If the
        # authorization event cannot be written, the handler never runs.
        if not definition.read_only:
            persisted = await self._safe_record(
                AuditEvent(
                    request_id=request_id,
                    correlation_id=correlation,
                    timestamp=datetime.now(UTC),
                    principal_ref=principal_ref,
                    event_type=AuditEventType.TOOL_EXECUTION,
                    tool_id=proposal.tool_id,
                    policy_version=decision.policy_version,
                    decision=decision.outcome,
                    reason_code=decision.reason_code,
                    execution_status="authorized",
                    security_flags=flags,
                ),
                flags=flags,
            )
            if not persisted:
                return await self._deny_persistence(
                    proposal,
                    policy_version=decision.policy_version,
                    principal_ref=principal_ref,
                    request_id=request_id,
                    correlation_id=correlation,
                    flags=flags,
                )

        started = time.perf_counter()
        status = ExecutionStatus.EXECUTED
        error_category: str | None = None
        raw_output: Any = None
        try:
            call_result = definition.handler(**proposal.arguments)
            if inspect.isawaitable(call_result):
                call_result = await asyncio.wait_for(
                    call_result, timeout=definition.timeout_seconds
                )
            raw_output = call_result
        except TimeoutError:
            status = ExecutionStatus.TIMEOUT
            error_category = "timeout"
        except Exception as exc:  # sanitized category only — never raw messages
            status = ExecutionStatus.FAILED
            error_category = type(exc).__name__
        duration_ms = (time.perf_counter() - started) * 1000.0

        # 9a. Validate the result against the registered output schema.
        if status == ExecutionStatus.EXECUTED:
            try:
                jsonschema.validate(raw_output, definition.output_schema)
            except jsonschema.ValidationError:
                status = ExecutionStatus.FAILED
                error_category = "invalid_tool_output"
                raw_output = None

        # 9b. Enforce output constraints (truncation, redaction) and
        # disclosure screening — enforced here, not merely advisory.
        constraints = decision.constraints or {}
        if status == ExecutionStatus.EXECUTED and isinstance(raw_output, dict):
            max_items = constraints.get("output_max_items")
            if max_items is not None:
                for key, value in list(raw_output.items()):
                    if isinstance(value, list):
                        raw_output[key], _ = truncate_items(value, int(max_items))
            if constraints.get("redact"):
                raw_output = screen_output_payload(raw_output)
            else:
                # Always apply best-effort secret-shape screening.
                raw_output = screen_output_payload(raw_output)

        if status == ExecutionStatus.EXECUTED:
            result = ExecutionResult(
                tool_id=proposal.tool_id,
                status=status,
                output=raw_output,
                duration_ms=duration_ms,
            )
        else:
            result = ExecutionResult(
                tool_id=proposal.tool_id,
                status=status,
                output=None,
                error_category=error_category,
                duration_ms=duration_ms,
            )

        # 10. Audit: decision event + execution event. Persistence failures
        # here are post-hoc (the action already ran); they surface as the
        # documented `audit_persistence_failed` flag.
        audit_status = {
            ExecutionStatus.EXECUTED: "executed",
            ExecutionStatus.FAILED: "failed",
            ExecutionStatus.TIMEOUT: "timeout",
        }[status]
        await self._emit_decision(
            decision,
            principal_ref=principal_ref,
            request_id=request_id,
            correlation_id=correlation,
            execution_status=audit_status,
            duration_ms=duration_ms,
            error_category=error_category,
            flags=flags,
        )
        if status != ExecutionStatus.EXECUTED:
            # Execution attempts that failed/timed out also get an execution
            # event so reviewers see the attempt outcome with duration.
            await self._safe_record(
                AuditEvent(
                    request_id=request_id,
                    correlation_id=correlation,
                    timestamp=datetime.now(UTC),
                    principal_ref=principal_ref,
                    event_type=AuditEventType.TOOL_EXECUTION,
                    tool_id=proposal.tool_id,
                    policy_version=decision.policy_version,
                    decision=decision.outcome,
                    reason_code=decision.reason_code,
                    execution_status=audit_status,
                    duration_ms=duration_ms,
                    error_category=error_category,
                    security_flags=flags,
                ),
                flags=flags,
            )

        return ExecutionOutcome(
            decision=decision,
            result=result,
            approval_id=decision.approval_id,
            security_flags=flags,
        )

    async def _deny_persistence(
        self,
        proposal: ToolProposal,
        *,
        policy_version: str,
        principal_ref: str,
        request_id: str,
        correlation_id: str,
        flags: list[str],
    ) -> ExecutionOutcome:
        """Fail closed when the action cannot be durably recorded first."""
        decision = PolicyDecision(
            outcome=DecisionOutcome.DENY,
            reason_code=ReasonCode.PERSISTENCE_ERROR,
            message=(
                "Persistence is unavailable; the action was denied. "
                "Try again after the service is restored."
            ),
            policy_version=policy_version,
            tool_id=proposal.tool_id,
        )
        await self._emit_decision(
            decision,
            principal_ref=principal_ref,
            request_id=request_id,
            correlation_id=correlation_id,
            execution_status="not_executed",
            flags=flags,
        )
        return ExecutionOutcome(
            decision=decision,
            result=ExecutionResult(
                tool_id=proposal.tool_id,
                status=ExecutionStatus.BLOCKED,
                error_category=ReasonCode.PERSISTENCE_ERROR.value,
            ),
            security_flags=flags,
        )

    async def _safe_record(self, event: AuditEvent, *, flags: list[str]) -> bool:
        """Record an event; never let persistence failure crash enforcement.

        Returns False when the write failed (also flagging the outcome).
        """
        try:
            await self._audit.record(event)
            return True
        except Exception:
            logger.exception("audit persistence failed for %s", event.event_type.value)
            if AUDIT_PERSISTENCE_FLAG not in flags:
                flags.append(AUDIT_PERSISTENCE_FLAG)
            return False

    async def _emit_decision(
        self,
        decision: PolicyDecision,
        *,
        principal_ref: str,
        request_id: str,
        correlation_id: str,
        execution_status: str,
        duration_ms: float | None = None,
        error_category: str | None = None,
        approval_id: str | None = None,
        flags: list[str] | None = None,
    ) -> None:
        await self._safe_record(
            AuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=datetime.now(UTC),
                principal_ref=principal_ref,
                event_type=AuditEventType.POLICY_DECISION,
                tool_id=decision.tool_id,
                policy_version=decision.policy_version,
                decision=decision.outcome,
                reason_code=decision.reason_code,
                approval_id=approval_id or decision.approval_id,
                execution_status=execution_status,
                duration_ms=duration_ms,
                error_category=error_category,
                security_flags=list(flags or []),
            ),
            flags=flags if flags is not None else [],
        )


def decision_summary(decision: PolicyDecision) -> DecisionSummary:
    return DecisionSummary(
        tool_id=decision.tool_id,
        outcome=decision.outcome,
        reason_code=decision.reason_code,
    )
