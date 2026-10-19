"""Tool definition contracts (spec §3.C, §6.3)."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolDefinition(BaseModel):
    """A registered tool.

    The handler is a trusted, application-registered callable. Model output
    can only ever reference tools by identifier — it can never register or
    modify a tool, permission, or policy entry.
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    tool_id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    version: str = Field(min_length=1, max_length=32)
    description: str = Field(min_length=1, max_length=500)
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    permission: str = Field(min_length=1, max_length=128)
    risk: RiskLevel
    read_only: bool
    requires_approval: bool
    timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    handler: Callable[..., Any]

    def public_metadata(self) -> dict[str, Any]:
        """Metadata safe to expose via the API (no handler reference)."""
        return {
            "tool_id": self.tool_id,
            "version": self.version,
            "description": self.description,
            "permission": self.permission,
            "risk": self.risk.value,
            "read_only": self.read_only,
            "requires_approval": self.requires_approval,
        }
