"""Policy configuration loading and validation (spec §7, §12).

Startup MUST refuse to run when the security configuration is invalid or
contradictory:

- default-deny categories may not be weakened;
- a critical-risk tool must require approval;
- policy entries must match registered tool metadata (permission, risk,
  approval requirement) — mismatches are contradictory security settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from rasp.schemas.tool import RiskLevel, ToolDefinition


class PolicyConfigError(Exception):
    """Raised when the policy configuration is invalid or contradictory."""


class PolicyDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Fail-closed invariant: these categories are hard-wired to "deny".
    # Any attempt to weaken them refuses startup (spec §7, mandatory rule 1/9/12).
    unknown_tool: Literal["deny"] = "deny"
    authorization_failure: Literal["deny"] = "deny"
    policy_error: Literal["deny"] = "deny"
    sensitive_action_without_approval: Literal["deny"] = "deny"


class PolicyConstraints(BaseModel):
    """Constraints enforced by the executor, not merely displayed."""

    model_config = ConfigDict(extra="forbid")

    # Numeric caps checked by the policy engine before execution.
    argument_caps: dict[str, int | float] = Field(default_factory=dict)
    # Output constraints applied by the executor after execution.
    output_max_items: int | None = Field(default=None, ge=1)
    redact: bool = False


class ToolPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    risk: RiskLevel
    permission: str = Field(min_length=1, max_length=128)
    requires_approval: bool = False
    constraints: PolicyConstraints = Field(default_factory=PolicyConstraints)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1, max_length=32)
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    tools: dict[str, ToolPolicy]

    @model_validator(mode="after")
    def _check_contradictions(self) -> PolicyConfig:
        for tool_id, tool in self.tools.items():
            if tool.enabled and tool.risk == RiskLevel.CRITICAL and not tool.requires_approval:
                raise ValueError(
                    f"contradictory policy: enabled critical-risk tool "
                    f"'{tool_id}' must require approval"
                )
        return self


def load_policy_file(path: str | Path) -> PolicyConfig:
    """Load and validate the YAML policy file. Raises PolicyConfigError."""
    policy_path = Path(path)
    if not policy_path.is_file():
        raise PolicyConfigError(f"policy file not found: {policy_path}")
    try:
        raw: Any = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyConfigError(f"policy file is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyConfigError("policy file must contain a YAML mapping")
    try:
        return PolicyConfig.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError and ValueError above
        raise PolicyConfigError(f"invalid policy configuration: {exc}") from exc


def validate_policy_registry_consistency(
    config: PolicyConfig,
    registry_tools: list[ToolDefinition],
) -> None:
    """Refuse startup when policy and registry disagree (contradictory settings)."""
    for definition in registry_tools:
        entry = config.tools.get(definition.tool_id)
        if entry is None:
            raise PolicyConfigError(f"registered tool '{definition.tool_id}' has no policy entry")
        mismatches: list[str] = []
        if entry.permission != definition.permission:
            mismatches.append("permission")
        if entry.risk != definition.risk:
            mismatches.append("risk")
        if entry.requires_approval != definition.requires_approval:
            mismatches.append("requires_approval")
        if mismatches:
            raise PolicyConfigError(
                f"policy/registry mismatch for '{definition.tool_id}': " + ", ".join(mismatches)
            )
