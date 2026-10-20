"""Local LLM adapter integration through the full ASGI pipeline (Milestone 4).

Proves the M4 adapter plugs into the mediated chat lifecycle, and — most
importantly — that a model/provider failure is handled **fail closed**: the
request returns a safe message with no tool execution and no fabricated
authorization. Uses ``httpx.MockTransport`` so no network or model is needed.
"""

from __future__ import annotations

import dataclasses
import json

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from rasp.gateway.lifecycle import ChatOrchestrator
from rasp.main import create_app
from rasp.models.local import LocalOpenAICompatibleAdapter
from rasp.settings import Settings
from rasp.tools import builtin
from tests.conftest import PERMS_ALL_DEMO, headers_for


def _app_with_transport(handler, **model_kwargs):
    settings = Settings(
        persistence="in_memory",
        model_provider="local",
        local_model_name="test-model",
        policy_path="config/policies.example.yaml",
    )
    app = create_app(settings)
    container = app.state.container
    model = LocalOpenAICompatibleAdapter(
        base_url="http://127.0.0.1:11434",
        model_name="test-model",
        transport=httpx.MockTransport(handler),
        **model_kwargs,
    )
    orchestrator = ChatOrchestrator(
        settings=container.settings,
        model=model,
        executor=container.executor,
        audit=container.audit,
    )
    app.state.container = dataclasses.replace(container, model=model, orchestrator=orchestrator)
    return app


@pytest.fixture(autouse=True)
def _clean_log():
    builtin.EXECUTION_LOG.clear()
    yield
    builtin.EXECUTION_LOG.clear()


async def test_local_tool_call_flows_through_enforcement():
    """A tool proposal from the local adapter is still mediated by policy."""
    body = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "document_search",
                                "arguments": json.dumps({"query": "tcp", "max_results": 2}),
                            }
                        }
                    ]
                }
            }
        ]
    }
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        # First turn proposes a tool; the follow-up turn returns text.
        if calls["n"] == 1:
            return httpx.Response(200, json=body)
        return httpx.Response(200, json={"choices": [{"message": {"content": "Done searching."}}]})

    app = _app_with_transport(handler)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "search tcp"},
            headers=headers_for("alice", PERMS_ALL_DEMO),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["model_id"] == "local:test-model"
    assert data["action_status"] == "executed"
    assert data["decisions"][0]["tool_id"] == "document_search"
    assert data["decisions"][0]["outcome"] in {"allow", "allow_with_constraints"}


async def test_local_denied_tool_never_executes():
    """A local model proposing a disabled mutating tool is still denied."""
    body = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {"function": {"name": "record_delete", "arguments": {"record_id": "r1"}}}
                    ]
                }
            }
        ]
    }
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=body)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    app = _app_with_transport(handler)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "delete everything"},
            headers=headers_for("alice", PERMS_ALL_DEMO),
        )
    data = resp.json()
    assert data["action_status"] == "denied"
    # The mutating handler was NEVER reached despite the model proposing it.
    assert not any(entry.startswith("record_delete") for entry in builtin.EXECUTION_LOG)


async def test_model_transport_failure_fails_closed():
    """Provider failure => safe message, no execution, model_unavailable flag."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    app = _app_with_transport(handler)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "do something sensitive"},
            headers=headers_for("alice", PERMS_ALL_DEMO),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "model_unavailable" in data["security_flags"]
    assert data["action_status"] == "none"
    assert data["decisions"] == []
    # Nothing executed on a provider failure.
    assert builtin.EXECUTION_LOG == []
    # The error message must not leak the endpoint or the model name.
    assert "127.0.0.1" not in data["text"]


async def test_model_http_error_fails_closed():
    app = _app_with_transport(lambda request: httpx.Response(503, text="unavailable"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "hello"},
            headers=headers_for("alice", PERMS_ALL_DEMO),
        )
    data = resp.json()
    assert "model_unavailable" in data["security_flags"]
    assert builtin.EXECUTION_LOG == []
