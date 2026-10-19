"""App-level failover tests: postgres mode with an UNREACHABLE database.

Runs in the default suite (no PostgreSQL required): the configured URL
points at a closed port, so every store call fails fast. What is proven:

- mutating/approval-gated actions are denied (`persistence_error`), and
  synthetic handlers never run (spec M2: "database failure prevents
  sensitive actions from executing");
- read-only chat still works, carrying the documented
  `audit_persistence_failed` flag;
- the app starts and answers — failures surface at the enforcement
  decision, not as an unhandled 500.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from rasp.main import create_app
from rasp.settings import Settings
from rasp.tools import builtin
from tests.conftest import PERMS_ALL_DEMO, headers_for

# A port with nothing listening: connection refused, fail fast.
DEAD_DB_URL = "postgresql+asyncpg://rasp:rasp@127.0.0.1:59999/rasp"


def _app():
    return create_app(
        Settings(
            policy_path="config/policies.example.yaml",
            persistence="postgres",
            database_url=DEAD_DB_URL,
        )
    )


async def test_making_mutating_action_denied_when_database_down():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        response = await client.post(
            "/v1/tools/execute",
            json={
                "tool_id": "publish_announcement",
                "arguments": {"title": "t", "body": "b"},
            },
            headers=headers_for("failover", PERMS_ALL_DEMO),
        )
    # Deny (403), NOT a pending approval (202): nothing could be persisted.
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "persistence_error"
    assert builtin.EXECUTION_LOG == []  # nothing executed
    await app.state.container.close()


async def test_read_only_chat_survives_database_outage_with_flag():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        response = await client.post(
            "/v1/chat",
            json={"message": "status", "scenario": "call_system_status"},
            headers=headers_for("failover", PERMS_ALL_DEMO),
        )
    assert response.status_code == 200
    data = response.json()
    # Documented read-only fallback: the action ran...
    assert data["action_status"] == "executed"
    # ...but the response discloses that persistence failed.
    assert "audit_persistence_failed" in data["security_flags"]
    await app.state.container.close()


async def test_deny_paths_still_deny_with_database_down():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        response = await client.post(
            "/v1/tools/execute",
            json={"tool_id": "record_delete", "arguments": {"record_id": "syn-rec-001"}},
            headers=headers_for("failover", "records:delete"),
        )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "tool_disabled"  # denied by policy, as usual
    assert builtin.EXECUTION_LOG == []
    await app.state.container.close()


async def test_audit_endpoint_reports_unavailable_instead_of_500():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        response = await client.get("/v1/audit", headers=headers_for("failover", "audit:read"))
    # A down database must not crash the route with an unhandled error:
    # the client gets an explicit, structured 503.
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "persistence_unavailable"
    await app.state.container.close()
