"""Execution contracts (spec §3.G, §8).

ToolExecutionRequest deliberately has NO field that asserts authorization,
approval, or identity. Authorization always comes from trusted context and
is re-evaluated at execution time.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from rasp.schemas.policy import DecisionOutcome, PolicyDecision


class ToolExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    # No "authorized", "approved", "role", or "permissions" fields exist and
    # extra fields are rejected: caller-supplied authorization claims are
    # never trusted (spec §8, §12).


class ExecutionStatus(StrEnum):
    NOT_EXECUTED = "not_executed"
    EXECUTED = "executed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    PENDING_APPROVAL = "pending_approval"
    BLOCKED = "blocked"


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str
    status: ExecutionStatus
    output: Any | None = None
    error_category: str | None = None  # sanitized category only
    duration_ms: float | None = None


class ExecutionOutcome(BaseModel):
    """Result of routing one proposed tool call through enforcement."""

    model_config = ConfigDict(extra="forbid")

    decision: PolicyDecision
    result: ExecutionResult | None = None
    approval_id: str | None = None
    # Enforcement-time flags (e.g. `audit_persistence_failed` for the
    # documented read-only fallback). Merged into chat responses.
    security_flags: list[str] = Field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision.outcome in (
            DecisionOutcome.ALLOW,
            DecisionOutcome.ALLOW_WITH_CONSTRAINTS,
        )
