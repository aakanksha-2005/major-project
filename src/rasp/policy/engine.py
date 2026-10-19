"""Deterministic policy engine (spec §3.D, §7).

Precedence is fixed and documented (evaluation order below). A deny at any
step is final — model output, risk scores, or weaker allow rules can never
override it. Any internal error is surfaced as PolicyEvaluationError so the
caller can fail closed.

Evaluation order (documented precedence, most authoritative first):
  1. Authentication context present                -> else DENY
  2. Tool registered (registry lookup)             -> else DENY unknown
  3. Policy entry exists                           -> else DENY missing
  4. Tool enabled                                  -> else DENY disabled
  5. Argument schema valid (JSON Schema)           -> else DENY invalid
  6. Argument policy caps respected                -> else DENY constraint
  7. Principal holds required permission           -> else DENY permission
  8. Approval state (if required)                  -> REQUIRE_APPROVAL /
                                                     DENY invalid
  9. ALLOW or ALLOW_WITH_CONSTRAINTS
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from rasp.auth.dev_identity import Principal
from rasp.policy.config import PolicyConfig, ToolPolicy
from rasp.schemas.approval import ApprovalRecord, ApprovalStatus, compute_action_digest
from rasp.schemas.policy import DecisionOutcome, PolicyDecision, ReasonCode
from rasp.tools.registry import ToolArgumentError, ToolRegistry, UnknownToolError


class PolicyEvaluationError(Exception):
    """Policy evaluation failed; callers MUST fail closed (deny)."""


class PolicyEngine:
    def __init__(self, config: PolicyConfig, registry: ToolRegistry) -> None:
        self._config = config
        self._registry = registry

    @property
    def policy_version(self) -> str:
        return self._config.version

    def evaluate(
        self,
        *,
        tool_id: str,
        arguments: dict[str, Any],
        principal: Principal | None,
        approval: ApprovalRecord | None = None,
    ) -> PolicyDecision:
        """Evaluate one proposed action.

        Returns deny outcomes normally; raises PolicyEvaluationError only on
        internal failure so callers can fail closed.
        """
        try:
            return self._evaluate(tool_id, arguments, principal, approval)
        except PolicyEvaluationError:
            raise
        except Exception as exc:  # unexpected error -> fail closed upstream
            raise PolicyEvaluationError(
                f"policy evaluation failed for tool '{tool_id}': {type(exc).__name__}"
            ) from exc

    def _deny(
        self,
        reason: ReasonCode,
        message: str,
        *,
        tool_id: str | None = None,
        required_permission: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            outcome=DecisionOutcome.DENY,
            reason_code=reason,
            message=message,
            policy_version=self._config.version,
            tool_id=tool_id,
            required_permission=required_permission,
        )

    def _evaluate(
        self,
        tool_id: str,
        arguments: dict[str, Any],
        principal: Principal | None,
        approval: ApprovalRecord | None,
    ) -> PolicyDecision:
        # 1. Authentication context.
        if principal is None:
            return self._deny(
                ReasonCode.AUTHENTICATION_REQUIRED,
                "Authentication context is required for this action.",
                tool_id=tool_id,
            )

        # 2. Registered tool? (default deny for unknown identifiers)
        definition = self._registry.get(tool_id)
        if definition is None:
            return self._deny(
                ReasonCode.UNKNOWN_TOOL,
                "The requested tool is not registered.",
                tool_id=tool_id,
            )

        # 3. Policy entry exists?
        entry: ToolPolicy | None = self._config.tools.get(tool_id)
        if entry is None:
            return self._deny(
                ReasonCode.POLICY_ENTRY_MISSING,
                "No policy entry exists for the requested tool.",
                tool_id=tool_id,
                required_permission=definition.permission,
            )

        # 4. Enabled?
        if not entry.enabled:
            return self._deny(
                ReasonCode.TOOL_DISABLED,
                "The requested tool is disabled by policy.",
                tool_id=tool_id,
                required_permission=entry.permission,
            )

        # 5. Valid arguments? (schema validation before anything executes)
        try:
            self._registry.validate_arguments(tool_id, arguments)
        except UnknownToolError:
            return self._deny(
                ReasonCode.UNKNOWN_TOOL,
                "The requested tool is not registered.",
                tool_id=tool_id,
            )
        except ToolArgumentError:
            return self._deny(
                ReasonCode.INVALID_ARGUMENTS,
                "The provided arguments are invalid for this tool.",
                tool_id=tool_id,
                required_permission=entry.permission,
            )

        # 6. Policy argument caps (deterministic, potentially stricter than schema).
        for key, cap in entry.constraints.argument_caps.items():
            value = arguments.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            if value > cap:
                return self._deny(
                    ReasonCode.CONSTRAINT_VIOLATION,
                    f"Argument '{key}' exceeds the policy limit for this tool.",
                    tool_id=tool_id,
                    required_permission=entry.permission,
                )

        # 7. Permission check (independent of any textual content).
        if not principal.has_permission(entry.permission):
            return self._deny(
                ReasonCode.PERMISSION_DENIED,
                "The caller lacks the required permission for this action.",
                tool_id=tool_id,
                required_permission=entry.permission,
            )

        # 8. Approval requirements.
        if entry.requires_approval:
            decision = self._approval_decision(tool_id, entry, arguments, principal, approval)
            if decision is not None:
                return decision

        # 9. Allow.
        constraints = entry.constraints.model_dump(exclude_none=True)
        has_executor_constraints = (
            entry.constraints.output_max_items is not None or entry.constraints.redact
        )
        if has_executor_constraints:
            return PolicyDecision(
                outcome=DecisionOutcome.ALLOW_WITH_CONSTRAINTS,
                reason_code=ReasonCode.ALLOWED_WITH_CONSTRAINTS,
                message="Action allowed subject to enforced output constraints.",
                policy_version=self._config.version,
                tool_id=tool_id,
                required_permission=entry.permission,
                constraints=constraints,
                approval_id=approval.approval_id if approval else None,
            )
        return PolicyDecision(
            outcome=DecisionOutcome.ALLOW,
            reason_code=ReasonCode.ALLOWED,
            message="Action allowed by policy.",
            policy_version=self._config.version,
            tool_id=tool_id,
            required_permission=entry.permission,
            approval_id=approval.approval_id if approval else None,
        )

    def _approval_decision(
        self,
        tool_id: str,
        entry: ToolPolicy,
        arguments: dict[str, Any],
        principal: Principal,
        approval: ApprovalRecord | None,
    ) -> PolicyDecision | None:
        """Return a decision when approval blocks the action, else None."""
        if approval is None or approval.status == ApprovalStatus.PENDING:
            return PolicyDecision(
                outcome=DecisionOutcome.REQUIRE_APPROVAL,
                reason_code=ReasonCode.APPROVAL_REQUIRED,
                message="This action requires an authorized human approval.",
                policy_version=self._config.version,
                tool_id=tool_id,
                required_permission=entry.permission,
                approval_required=True,
            )
        if approval.status in (
            ApprovalStatus.REJECTED,
            ApprovalStatus.EXPIRED,
            ApprovalStatus.INVALIDATED,
        ):
            return self._deny(
                ReasonCode.APPROVAL_INVALID,
                "The approval for this action is not valid.",
                tool_id=tool_id,
                required_permission=entry.permission,
            )
        # APPROVED: verify binding to this exact action and policy version.
        # Recomputed from the *current* request — never from stored claims.
        current_digest = compute_action_digest(
            tool_id, arguments, principal.principal_id, approval.policy_version
        )
        policy_changed = approval.policy_version != self._config.version
        if policy_changed or not approval.is_valid_for(
            action_digest=current_digest,
            principal_ref=principal.principal_id,
            now=datetime.now(UTC),
        ):
            return self._deny(
                ReasonCode.APPROVAL_INVALID,
                "The approval does not authorize this exact action.",
                tool_id=tool_id,
                required_permission=entry.permission,
            )
        return None
