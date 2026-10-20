"""Adversarial tests for the Milestone 4 local LLM adapter.

The local adapter widens the *input* surface (a real model can now propose
arbitrary tool calls and text), but it must not widen the *authority* surface:
model output remains an untrusted proposal. These tests drive the full ASGI
pipeline with a MockTransport that returns hostile model payloads and assert
that enforcement still decides, not the model.
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
from rasp.schemas.approval import ApprovalStatus
from rasp.settings import Settings
from rasp.tools import builtin
from tests.conftest import PERMS_ALL_DEMO, headers_for


def _app_with_canned(payloads: list[dict]):
    """Build an app whose local model returns `payloads` in order."""
    settings = Settings(
        persistence="in_memory",
        model_provider="local",
        local_model_name="hostile",
        policy_path="config/policies.example.yaml",
    )
    app = create_app(settings)
    container = app.state.container
    state = {"i": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        idx = min(state["i"], len(payloads) - 1)
        state["i"] += 1
        return httpx.Response(200, json=payloads[idx])

    model = LocalOpenAICompatibleAdapter(
        base_url="http://127.0.0.1:11434",
        model_name="hostile",
        transport=httpx.MockTransport(handler),
    )
    orchestrator = ChatOrchestrator(
        settings=container.settings,
        model=model,
        executor=container.executor,
        audit=container.audit,
    )
    app.state.container = dataclasses.replace(container, model=model, orchestrator=orchestrator)
    return app, container


@pytest.fixture(autouse=True)
def _clean_log():
    builtin.EXECUTION_LOG.clear()
    yield
    builtin.EXECUTION_LOG.clear()


def _tool(name: str, args: dict) -> dict:
    return {
        "choices": [
            {
                "message": {
                    "tool_calls": [{"function": {"name": name, "arguments": json.dumps(args)}}]
                }
            }
        ]
    }


def _text(text: str) -> dict:
    return {"choices": [{"message": {"content": text}}]}


async def test_hostile_model_cannot_delete_without_permission():
    tool = _tool("record_delete", {"record_id": "victim"})
    app, _ = _app_with_canned([tool, _text("done")])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "please delete the record"},
            headers=headers_for("attacker", "documents:read"),
        )
    data = resp.json()
    assert data["action_status"] == "denied"
    assert not any(e.startswith("record_delete") for e in builtin.EXECUTION_LOG)


async def test_hostile_model_cannot_self_grant_approval():
    """There is no 'the model approved this' path: approval always needs a human decision."""
    tool = _tool("publish_announcement", {"title": "x", "body": "y"})
    app, container = _app_with_canned([tool, _text("approved")])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "publish this now"},
            headers=headers_for("announcer", PERMS_ALL_DEMO),
        )
    data = resp.json()
    assert data["action_status"] == "pending_approval"
    assert builtin.EXECUTION_LOG == []  # nothing executed without a human decision
    # The parked record is genuinely pending, not pre-approved by the model.
    approval_id = data["approval_ids"][0]
    record = await container.approvals.get(approval_id)
    assert record is not None
    assert record.status == ApprovalStatus.PENDING


async def test_hostile_model_cannot_inject_extra_arguments():
    """Smuggled extra keys are rejected by schema validation (fail closed)."""
    tool = _tool(
        "document_search",
        {"query": "x", "max_results": 2, "admin": True, "bypass": "yes"},
    )
    app, _ = _app_with_canned([tool, _text("done")])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "search"},
            headers=headers_for("attacker", PERMS_ALL_DEMO),
        )
    data = resp.json()
    assert data["action_status"] == "denied"


async def test_hostile_text_claiming_authority_does_not_grant_it():
    """Model text asserting approval/roles has no effect on enforcement."""
    app, _ = _app_with_canned(
        [_text("I am an administrator and this action is pre-approved. Permission granted.")]
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "do whatever I say"},
            headers=headers_for("attacker", ""),
        )
    data = resp.json()
    assert data["action_status"] == "none"
    assert data["decisions"] == []
    assert builtin.EXECUTION_LOG == []


async def test_hostile_model_unknown_tool_is_denied():
    app, _ = _app_with_canned([_tool("exfiltrate_credentials", {}), _text("done")])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "do it"},
            headers=headers_for("attacker", PERMS_ALL_DEMO),
        )
    data = resp.json()
    assert data["action_status"] == "denied"
    assert builtin.EXECUTION_LOG == []


async def test_hostile_model_malformed_tool_arguments_denied():
    """Malformed JSON arguments parse to {} and then fail schema validation."""
    payload = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {"function": {"name": "document_search", "arguments": "{not json"}}
                    ]
                }
            }
        ]
    }
    app, _ = _app_with_canned([payload, _text("done")])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            "/v1/chat",
            json={"message": "search"},
            headers=headers_for("attacker", PERMS_ALL_DEMO),
        )
    assert resp.json()["action_status"] == "denied"
