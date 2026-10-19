"""Model-adapter contracts (provider-neutral).

CORE INVARIANT: a ModelResponse is an untrusted proposal. It is never an
authorization decision (spec §1, "Core invariant").
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from rasp.schemas.common import TrustCategory


class ModelMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant", "tool"]
    content: str
    # Trust metadata: system policy is trusted; everything else is not.
    source: TrustCategory = TrustCategory.USER
    tool_id: str | None = None  # set for tool-result messages


class ToolProposal(BaseModel):
    """A model-proposed tool call. Untrusted until validated and authorized."""

    model_config = ConfigDict(extra="forbid")

    tool_id: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)


class FinishReason(StrEnum):
    STOP = "stop"
    TOOL_CALL = "tool_call"
    ERROR = "error"


class ModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_id: str
    text: str | None = None
    tool_calls: list[ToolProposal] = Field(default_factory=list)
    finish_reason: FinishReason


class ModelOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Deterministic scenario selector for demos/tests (mock adapter only).
    scenario: str | None = None
    max_output_chars: int = Field(default=4000, ge=64)


class ProviderHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    provider: str
    # Safe detail only: never credentials, endpoints, or model secrets.
    detail: str = "ok"


class ProviderCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    supports_tool_calls: bool = True
    deterministic: bool = False
    requires_credentials: bool = False
