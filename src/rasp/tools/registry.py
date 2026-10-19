"""Tool registry (spec §3.C).

Only application-registered tools exist. Unknown identifiers are rejected.
The model may *propose* a tool call but can never register a tool, modify
a definition, or change its own permission set.
"""

from __future__ import annotations

from typing import Any

import jsonschema
from jsonschema import Draft202012Validator

from rasp.schemas.tool import ToolDefinition


class ToolRegistrationError(Exception):
    """Raised when a tool definition is invalid or duplicated."""


class UnknownToolError(Exception):
    """Raised when a tool identifier is not registered."""


class ToolArgumentError(Exception):
    """Raised when arguments fail schema validation.

    Carries only safe category information; raw payloads are not embedded.
    """

    def __init__(self, message: str, error_count: int = 0) -> None:
        super().__init__(message)
        self.error_count = error_count


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> None:
        if definition.tool_id in self._tools:
            raise ToolRegistrationError(f"duplicate tool identifier: {definition.tool_id}")
        for name, schema in (
            ("input_schema", definition.input_schema),
            ("output_schema", definition.output_schema),
        ):
            if schema.get("type") != "object":
                raise ToolRegistrationError(
                    f"{definition.tool_id}.{name} must be an object JSON Schema"
                )
            try:
                Draft202012Validator.check_schema(schema)
            except jsonschema.SchemaError as exc:
                raise ToolRegistrationError(
                    f"{definition.tool_id}.{name} is not a valid JSON Schema"
                ) from exc
        if not callable(definition.handler):
            raise ToolRegistrationError(f"{definition.tool_id} handler must be callable")
        self._tools[definition.tool_id] = definition

    def get(self, tool_id: str) -> ToolDefinition | None:
        return self._tools.get(tool_id)

    def require(self, tool_id: str) -> ToolDefinition:
        definition = self._tools.get(tool_id)
        if definition is None:
            raise UnknownToolError(tool_id)
        return definition

    def list(self) -> list[ToolDefinition]:
        return [self._tools[key] for key in sorted(self._tools)]

    def validate_arguments(self, tool_id: str, arguments: dict[str, Any]) -> None:
        """Validate arguments against the registered input schema.

        Raises UnknownToolError for unregistered tools and ToolArgumentError
        for invalid arguments. Never executes anything.
        """
        definition = self.require(tool_id)
        validator = Draft202012Validator(definition.input_schema)
        errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.path))
        if errors:
            # Deliberately do not echo raw argument values back to clients.
            raise ToolArgumentError(
                f"arguments failed schema validation for '{tool_id}'",
                error_count=len(errors),
            )
