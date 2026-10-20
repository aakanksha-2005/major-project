"""Policy decision contracts (spec §3.D, §6.2)."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from rasp.schemas.common import new_id


class DecisionOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    ALLOW_WITH_CONSTRAINTS = "allow_with_constraints"


class ReasonCode(StrEnum):
    """Stable machine-readable reason codes. Safe to return to clients.

    They describe *why* a decision was made without disclosing the full
    policy document or hidden detection rules.
    """

    ALLOWED = "allowed"
    ALLOWED_WITH_CONSTRAINTS = "allowed_with_constraints"
    UNKNOWN_TOOL = "unknown_tool"
    POLICY_ENTRY_MISSING = "policy_entry_missing"
    TOOL_DISABLED = "tool_disabled"
    PERMISSION_DENIED = "permission_denied"
    AUTHENTICATION_REQUIRED = "authentication_required"
    INVALID_ARGUMENTS = "invalid_arguments"
    CONSTRAINT_VIOLATION = "constraint_violation"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    POLICY_ERROR = "policy_error"
    # Milestone 2: persistence unavailable — the executor fails closed for
    # actions that cannot be durably audited first (mutating tools).
    PERSISTENCE_ERROR = "persistence_error"
    # Milestone 3: reviewer decision outcomes on approval records.
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_REVOKED = "approval_revoked"


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(default_factory=new_id)
    outcome: DecisionOutcome
    reason_code: ReasonCode
    # Client-safe explanation; never contains raw policy internals.
    message: str = Field(min_length=1, max_length=500)
    policy_version: str
    tool_id: str | None = None
    required_permission: str | None = None
    constraints: dict[str, Any] = Field(default_factory=dict)
    approval_required: bool = False
    approval_id: str | None = None
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
