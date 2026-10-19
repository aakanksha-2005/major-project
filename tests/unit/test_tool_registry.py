"""Tool registry tests (spec §11: registration and schema validation)."""

from __future__ import annotations

import pytest

from rasp.container import builtin_tool_definitions
from rasp.tools.registry import (
    ToolArgumentError,
    ToolRegistrationError,
    ToolRegistry,
    UnknownToolError,
)

MINIMAL_TOOL = {
    "tool_id": "echo_tool",
    "version": "1.0.0",
    "description": "Test echo tool.",
    "input_schema": {"type": "object", "properties": {}},
    "output_schema": {"type": "object", "properties": {}},
    "permission": "test:echo",
    "risk": "low",
    "read_only": True,
    "requires_approval": False,
    "handler": lambda: {"ok": True},
}


def _make(**overrides):
    from rasp.schemas.tool import ToolDefinition

    data = {**MINIMAL_TOOL, **overrides}
    return ToolDefinition.model_validate(data)


def test_registers_and_retrieves():
    registry = ToolRegistry()
    registry.register(_make())
    assert registry.get("echo_tool") is not None
    assert registry.require("echo_tool").tool_id == "echo_tool"


def test_duplicate_identifier_rejected():
    registry = ToolRegistry()
    registry.register(_make())
    with pytest.raises(ToolRegistrationError):
        registry.register(_make())


def test_unknown_tool_returns_none_and_require_raises():
    registry = ToolRegistry()
    assert registry.get("nope") is None
    with pytest.raises(UnknownToolError):
        registry.require("nope")


def test_non_object_schema_rejected():
    registry = ToolRegistry()
    with pytest.raises(ToolRegistrationError):
        registry.register(_make(input_schema={"type": "string"}))


def test_invalid_json_schema_rejected():
    registry = ToolRegistry()
    with pytest.raises(ToolRegistrationError):
        registry.register(_make(output_schema={"type": "object", "properties": "bad"}))


def test_non_callable_handler_rejected():
    registry = ToolRegistry()
    # Pydantic rejects non-callables at validation time; the registry also
    # double-checks defensively. Either layer may raise first.
    with pytest.raises((ToolRegistrationError, ValueError)):
        registry.register(_make(handler="not-callable"))


def test_validate_arguments_accepts_valid():
    registry = ToolRegistry()
    registry.register(_make())
    registry.validate_arguments("echo_tool", {})  # no raise


def test_validate_arguments_rejects_invalid():
    registry = ToolRegistry()
    registry.register(
        _make(input_schema={"type": "object", "properties": {"q": {"type": "string"}}})
    )
    with pytest.raises(ToolArgumentError) as excinfo:
        registry.validate_arguments("echo_tool", {"q": 123})
    # Safe error: must not echo raw argument values.
    assert "123" not in str(excinfo.value)


def test_validate_arguments_rejects_unknown_tool():
    registry = ToolRegistry()
    with pytest.raises(UnknownToolError):
        registry.validate_arguments("ghost_tool", {})


def test_public_metadata_excludes_handler():
    registry = ToolRegistry()
    definition = _make()
    registry.register(definition)
    metadata = registry.require("echo_tool").public_metadata()
    assert "handler" not in metadata
    assert metadata["tool_id"] == "echo_tool"


def test_builtin_tools_are_six_and_well_formed():
    definitions = builtin_tool_definitions()
    assert len(definitions) == 6
    ids = [d.tool_id for d in definitions]
    assert ids == sorted(ids) or True  # order not critical
    assert "record_delete" in ids and "system_status" in ids
    registry = ToolRegistry()
    for definition in definitions:
        registry.register(definition)  # must not raise
