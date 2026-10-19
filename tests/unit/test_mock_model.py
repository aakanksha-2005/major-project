"""Deterministic mock model adapter tests (spec §11: utility tests)."""

from __future__ import annotations

import pytest

from rasp.models.mock import MockModelAdapter, encode_tool_result_content
from rasp.schemas.model import FinishReason, ModelMessage, ModelOptions, TrustCategory


@pytest.fixture
def model() -> MockModelAdapter:
    return MockModelAdapter()


async def _gen(model, messages, scenario=None):
    return await model.generate(messages, options=ModelOptions(scenario=scenario))


def _user(text: str) -> ModelMessage:
    return ModelMessage(role="user", content=text, source=TrustCategory.USER)


async def test_same_input_produces_identical_output(model):
    messages = [_user("explain binary search briefly")]
    first = await _gen(model, messages)
    second = await _gen(model, messages)
    assert first == second  # determinism: no randomness anywhere


async def test_plain_text_scenario(model):
    response = await _gen(model, [_user("hi")], scenario="text")
    assert response.finish_reason == FinishReason.STOP
    assert response.tool_calls == []
    assert response.text


async def test_unknown_scenario_never_proposes_tools(model):
    response = await _gen(model, [_user("hi")], scenario="does_not_exist")
    assert response.tool_calls == []
    assert response.finish_reason == FinishReason.STOP


async def test_scenario_proposes_registered_tool(model):
    response = await _gen(model, [_user("hi")], scenario="call_document_search")
    assert response.finish_reason == FinishReason.TOOL_CALL
    assert response.tool_calls[0].tool_id == "document_search"
    assert "query" in response.tool_calls[0].arguments


async def test_scenario_can_propose_unknown_tool(model):
    """The mock may propose garbage — RASP must deny it downstream."""
    response = await _gen(model, [_user("hi")], scenario="call_unknown_tool")
    assert response.tool_calls[0].tool_id == "exfiltrate_credentials"


async def test_keyword_routing_search(model):
    response = await _gen(model, [_user("search tcp handshake")])
    call = response.tool_calls[0]
    assert call.tool_id == "document_search"
    assert "tcp" in call.arguments["query"]


async def test_keyword_routing_status(model):
    response = await _gen(model, [_user("check the system status")])
    assert response.tool_calls[0].tool_id == "system_status"


async def test_keyword_routing_delete_proposes_disabled_tool(model):
    response = await _gen(model, [_user("delete record syn-rec-001")])
    assert response.tool_calls[0].tool_id == "record_delete"


async def test_denied_tool_result_produces_denial_text(model):
    content = encode_tool_result_content(
        "denied", {"tool_id": "record_delete", "reason": "tool_disabled"}
    )
    message = ModelMessage(
        role="tool", content=content, source=TrustCategory.TOOL_OUTPUT, tool_id="record_delete"
    )
    response = await _gen(model, [_user("x"), message])
    assert "not permitted" in response.text.lower()
    assert response.tool_calls == []


async def test_pending_tool_result_produces_approval_text(model):
    content = encode_tool_result_content(
        "pending_approval", {"tool_id": "publish_announcement", "approval_id": "abc"}
    )
    message = ModelMessage(
        role="tool",
        content=content,
        source=TrustCategory.TOOL_OUTPUT,
        tool_id="publish_announcement",
    )
    response = await _gen(model, [_user("x"), message])
    assert "approval" in response.text.lower()


async def test_executed_tool_result_summarized_deterministically(model):
    content = encode_tool_result_content(
        "executed", {"tool_id": "system_status", "output": {"status": "ok"}}
    )
    message = ModelMessage(
        role="tool", content=content, source=TrustCategory.TOOL_OUTPUT, tool_id="system_status"
    )
    first = await _gen(model, [_user("x"), message])
    second = await _gen(model, [_user("x"), message])
    assert first == second
    assert "system_status" in first.text


async def test_health_and_capabilities(model):
    health = await model.health_check()
    assert health.ok and health.provider == "mock"
    caps = model.capabilities()
    assert caps.deterministic is True
    assert caps.requires_credentials is False


async def test_empty_message_list_is_safe(model):
    response = await model.generate([])
    assert response.finish_reason == FinishReason.STOP
    assert response.tool_calls == []
