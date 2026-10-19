"""Audit event contract (spec §3.I).

STRUCTURAL PRIVACY GUARANTEE: this model has no field for raw prompts,
message content, tool arguments, tool outputs, credentials, or private
records. Traceability is provided through request/correlation identifiers
and an action digest (a hash), not by storing content.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from rasp.schemas.common import new_id
from rasp.schemas.policy import DecisionOutcome, ReasonCode


class AuditEventType(StrEnum):
    REQUEST_RECEIVED = "request_received"
    POLICY_DECISION = "policy_decision"
    TOOL_EXECUTION = "tool_execution"
    APPROVAL_CREATED = "approval_created"
    RESPONSE_SCREENED = "response_screened"


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=new_id)
    request_id: str
    correlation_id: str
    timestamp: datetime
    principal_ref: str  # pseudonymized unless explicitly configured otherwise
    event_type: AuditEventType

    tool_id: str | None = None
    policy_version: str | None = None
    decision: DecisionOutcome | None = None
    reason_code: ReasonCode | None = None
    approval_id: str | None = None

    # execution_status values: not_applicable | not_executed | executed |
    # failed | timeout | pending_approval | blocked
    execution_status: str = "not_applicable"
    duration_ms: float | None = None
    error_category: str | None = None  # sanitized category, never raw messages
    action_digest: str | None = None  # sha256 of canonical action, no content
    security_flags: list[str] = Field(default_factory=list)
