"""Local LLM adapter tests (Milestone 4).

Deterministic and offline: every test injects an ``httpx.MockTransport`` so
no network or running model is required, and no real endpoint is contacted.
These tests exercise request building, OpenAI/Ollama response parsing, and
the fail-closed error policy (transport errors, non-2xx, malformed JSON,
missing fields must all raise ``ModelAdapterError`` — never fabricate a tool
call and never act as an authorization decision).
"""

from __future__ import annotations

import json

import httpx
import pytest

from rasp.container import build_model_adapter
from rasp.models.base import ModelAdapterError
from rasp.models.local import LocalOpenAICompatibleAdapter, OllamaModelAdapter
from rasp.schemas.model import FinishReason, ModelMessage, ModelOptions, TrustCategory
from rasp.settings import Settings


def _user(text: str) -> ModelMessage:
    return ModelMessage(role="user", content=text, source=TrustCategory.USER)


def _handler(status: int, body: object):
    def handler(request: httpx.Request) -> httpx.Response:
        if isinstance(body, (dict, list)):
            return httpx.Response(status, json=body)
        return httpx.Response(status, text=str(body))

    return handler


def _adapter(handler, **kwargs) -> LocalOpenAICompatibleAdapter:
    transport = httpx.MockTransport(handler)
    return LocalOpenAICompatibleAdapter(
        base_url="http://127.0.0.1:11434",
        model_name="llama3.2",
        transport=transport,
        **kwargs,
    )


def _openai_text(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


# --- happy paths ---------------------------------------------------------------


async def test_text_response_parsed():
    model = _adapter(_handler(200, _openai_text("Hello there.")))
    response = await model.generate([_user("hi")])
    assert response.finish_reason == FinishReason.STOP
    assert response.tool_calls == []
    assert response.text == "Hello there."
    assert response.model_id == "local:llama3.2"


async def test_tool_call_parsed_with_json_string_arguments():
    body = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "document_search",
                                "arguments": json.dumps({"query": "tcp", "max_results": 3}),
                            },
                        }
                    ],
                }
            }
        ]
    }
    model = _adapter(_handler(200, body))
    response = await model.generate([_user("search tcp")])
    assert response.finish_reason == FinishReason.TOOL_CALL
    assert response.tool_calls[0].tool_id == "document_search"
    assert response.tool_calls[0].arguments == {"query": "tcp", "max_results": 3}


async def test_tool_call_arguments_as_object_also_accepted():
    body = {
        "choices": [
            {"message": {"tool_calls": [{"function": {"name": "system_status", "arguments": {}}}]}}
        ]
    }
    model = _adapter(_handler(200, body))
    response = await model.generate([_user("status")])
    assert response.tool_calls[0].tool_id == "system_status"
    assert response.tool_calls[0].arguments == {}


async def test_malformed_tool_arguments_do_not_raise_but_empty():
    """A bad proposal is a normal, deny-able event — not a transport failure."""
    body = {
        "choices": [
            {"message": {"tool_calls": [{"function": {"name": "x", "arguments": "not json"}}]}}
        ]
    }
    model = _adapter(_handler(200, body))
    response = await model.generate([_user("x")])
    assert response.tool_calls[0].tool_id == "x"
    assert response.tool_calls[0].arguments == {}


async def test_tool_calls_without_name_are_skipped():
    body = {
        "choices": [
            {"message": {"content": "text", "tool_calls": [{"function": {"arguments": "{}"}}]}}
        ]
    }
    model = _adapter(_handler(200, body))
    response = await model.generate([_user("x")])
    assert response.tool_calls == []
    assert response.text == "text"


async def test_output_is_truncated_to_max_chars():
    model = _adapter(_handler(200, _openai_text("x" * 5000)), max_output_chars=64)
    response = await model.generate([_user("x")])
    assert len(response.text) == 64


async def test_roles_are_preserved_and_tool_results_passed_through():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        captured["path"] = request.url.path
        return httpx.Response(200, json=_openai_text("ok"))

    model = _adapter(handler)
    messages = [
        ModelMessage(role="system", content="policy", source=TrustCategory.SYSTEM_POLICY),
        _user("hello"),
        ModelMessage(
            role="tool", content='{"status":"executed"}', source=TrustCategory.TOOL_OUTPUT
        ),
    ]
    await model.generate(messages)
    roles = [m["role"] for m in captured["messages"]]
    assert roles == ["system", "user", "tool"]
    assert captured["model"] == "llama3.2"
    assert captured["stream"] is False
    # The OpenAI-compatible API lives under /v1.
    assert captured["path"] == "/v1/chat/completions"


async def test_base_url_with_v1_suffix_is_not_doubled():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json=_openai_text("ok"))

    model = LocalOpenAICompatibleAdapter(
        base_url="http://127.0.0.1:8123/v1",
        model_name="m",
        transport=httpx.MockTransport(handler),
    )
    await model.generate([_user("hi")])
    assert seen["path"] == "/v1/chat/completions"


async def test_scenario_options_are_ignored_by_local_adapter():
    """ModelOptions.scenario is a mock-only concern; local ignores it safely."""
    model = _adapter(_handler(200, _openai_text("real answer")))
    response = await model.generate([_user("hi")], options=ModelOptions(scenario="text"))
    assert response.text == "real answer"


async def test_api_key_sent_as_bearer_but_not_in_model_id():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_openai_text("ok"))

    model = _adapter(handler, api_key="secret-token")
    await model.generate([_user("hi")])
    assert seen["auth"] == "Bearer secret-token"
    assert "secret-token" not in model.model_id


# --- fail-closed error paths ---------------------------------------------------


async def test_transport_error_raises_model_adapter_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    model = _adapter(handler)
    with pytest.raises(ModelAdapterError):
        await model.generate([_user("hi")])


async def test_non_2xx_raises_model_adapter_error():
    model = _adapter(_handler(500, "boom"))
    with pytest.raises(ModelAdapterError):
        await model.generate([_user("hi")])


async def test_malformed_json_raises_model_adapter_error():
    model = _adapter(_handler(200, "this is not json"))
    with pytest.raises(ModelAdapterError):
        await model.generate([_user("hi")])


async def test_missing_choices_raises():
    model = _adapter(_handler(200, {"unexpected": True}))
    with pytest.raises(ModelAdapterError):
        await model.generate([_user("hi")])


async def test_empty_choices_raises():
    model = _adapter(_handler(200, {"choices": []}))
    with pytest.raises(ModelAdapterError):
        await model.generate([_user("hi")])


async def test_missing_message_raises():
    model = _adapter(_handler(200, {"choices": [{}]}))
    with pytest.raises(ModelAdapterError):
        await model.generate([_user("hi")])


async def test_non_object_payload_raises():
    model = _adapter(_handler(200, [1, 2, 3]))
    with pytest.raises(ModelAdapterError):
        await model.generate([_user("hi")])


async def test_health_check_reports_unreachable_without_raising():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope", request=request)

    model = _adapter(handler)
    health = await model.health_check()
    assert health.ok is False
    assert health.provider == "local"
    # Detail must not leak the endpoint or credentials.
    assert "127.0.0.1" not in health.detail


async def test_health_check_reports_reachable():
    model = _adapter(_handler(200, {"data": []}))
    health = await model.health_check()
    assert health.ok is True
    assert health.provider == "local"


# --- Ollama-native adapter -----------------------------------------------------


def _ollama(handler, **kwargs) -> OllamaModelAdapter:
    return OllamaModelAdapter(
        base_url="http://127.0.0.1:11434",
        model_name="llama3.2",
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


async def test_ollama_text_response():
    body = {"message": {"role": "assistant", "content": "hi from ollama"}}
    model = _ollama(_handler(200, body))
    response = await model.generate([_user("hi")])
    assert response.model_id == "ollama:llama3.2"
    assert response.text == "hi from ollama"
    assert response.finish_reason == FinishReason.STOP


async def test_ollama_tool_call_object_arguments():
    body = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": "document_search", "arguments": {"query": "a"}}}],
        }
    }
    model = _ollama(_handler(200, body))
    response = await model.generate([_user("search a")])
    assert response.finish_reason == FinishReason.TOOL_CALL
    assert response.tool_calls[0].arguments == {"query": "a"}


async def test_ollama_health_uses_native_tags_endpoint():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json={"models": []})

    model = _ollama(handler)
    health = await model.health_check()
    assert health.ok is True
    assert health.provider == "ollama"
    assert seen["path"] == "/api/tags"


async def test_ollama_transport_error_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    model = _ollama(handler)
    with pytest.raises(ModelAdapterError):
        await model.generate([_user("hi")])


# --- wiring / startup ----------------------------------------------------------


def test_provider_local_builds_openai_compatible_adapter():
    settings = Settings(
        persistence="in_memory",
        model_provider="local",
        local_model_name="qwen2.5",
    )
    adapter = build_model_adapter(settings)
    assert isinstance(adapter, LocalOpenAICompatibleAdapter)
    assert adapter.model_id == "local:qwen2.5"
    assert adapter.capabilities().provider == "local"
    assert adapter.capabilities().deterministic is False


def test_provider_ollama_builds_ollama_adapter():
    settings = Settings(persistence="in_memory", model_provider="ollama")
    adapter = build_model_adapter(settings)
    assert isinstance(adapter, OllamaModelAdapter)
    assert adapter.capabilities().provider == "ollama"


def test_unknown_provider_refuses_startup():
    settings = Settings(persistence="in_memory", model_provider="openai-cloud")
    with pytest.raises(ValueError, match="not implemented"):
        build_model_adapter(settings)


def test_empty_base_url_rejected():
    with pytest.raises(ValueError):
        LocalOpenAICompatibleAdapter(base_url="  ", model_name="x")
