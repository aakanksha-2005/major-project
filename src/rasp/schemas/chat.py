"""Chat API contracts (spec §8, POST /v1/chat)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from rasp.schemas.policy import DecisionOutcome, ReasonCode


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=8000)
    session_id: str | None = Field(default=None, max_length=128)
    # Deterministic mock-model scenario selector (demos and tests only).
    scenario: str | None = Field(default=None, max_length=64)


class ActionStatus(StrEnum):
    NONE = "none"
    EXECUTED = "executed"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    ERROR = "error"


class DecisionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str | None
    outcome: DecisionOutcome
    reason_code: ReasonCode


class ChatResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    text: str
    action_status: ActionStatus
    decisions: list[DecisionSummary] = Field(default_factory=list)
    approval_ids: list[str] = Field(default_factory=list)
    security_flags: list[str] = Field(default_factory=list)
    model_id: str
    prototype_notice: str
