"""PostgreSQL lifecycle tests (Milestone 2 acceptance).

Proves against the real target database:
- a clean database initializes from migrations;
- audit events and approval records survive application restarts;
- approval state transitions are validated and durable;
- unauthorized callers cannot read audit records (approval records have no
  API surface at all in M2 — nothing to read);
- audit rows in the DATABASE contain no chat content (canary check).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from rasp.main import create_app
from rasp.schemas.approval import ApprovalStatus
from tests.conftest import PERMS_ALL_DEMO, PERMS_AUDIT_ADMIN, headers_for

pytestmark = pytest.mark.postgres

CANARY = "CANARY_DB_CONTENT_7c1e must never reach any column"


# --- schema from migrations ------------------------------------------------------


async def test_clean_database_initialized_from_migrations(pg_engine):
    """After `alembic upgrade head`: tables exist and version is recorded."""
    async with pg_engine.connect() as conn:
        tables = {
            row[0]
            for row in await conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
                )
            )
        }
        version = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
    assert {"policies", "approval_requests", "audit_events"} <= tables
    assert version == "0001_initial"


async def test_audit_table_has_no_content_columns(pg_engine):
    """Structural privacy guarantee enforced at the DATABASE level."""
    async with pg_engine.connect() as conn:
        columns = {
            row[0]
            for row in await conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'audit_events'"
                )
            )
        }
    forbidden = {
        "prompt",
        "message_text",
        "content",
        "arguments",
        "raw_output",
        "output",
        "record",
        "credentials",
    }
    assert not (columns & forbidden), columns & forbidden


# --- persistence across restart ---------------------------------------------------


async def test_audit_events_persist_across_application_restart(pg_settings):
    app1 = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app1), base_url="http://t") as c1:
            response = await c1.post(
                "/v1/chat",
                json={"message": "restart persistence check"},
                headers=headers_for("restart-principal", PERMS_ALL_DEMO),
            )
        assert response.status_code == 200
        request_id = response.json()["request_id"]
    finally:
        await app1.state.container.close()

    # Fresh process simulation: new app, new engine, same database.
    app2 = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app2), base_url="http://t") as c2:
            persisted = await c2.get(
                "/v1/audit",
                params={"request_id": request_id, "limit": 10},
                headers=headers_for("restart-principal", PERMS_AUDIT_ADMIN),
            )
        assert persisted.status_code == 200
        assert persisted.json()["count"] >= 2  # request_received + response_screened
        types = {e["event_type"] for e in persisted.json()["events"]}
        assert "request_received" in types
    finally:
        await app2.state.container.close()


async def test_audit_rows_contain_no_chat_content(pg_engine, pg_settings):
    """Canary phrase from the message must not exist in ANY column/row."""
    app = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            await client.post(
                "/v1/chat",
                json={"message": f"hello {CANARY}"},
                headers=headers_for("content-scan", PERMS_ALL_DEMO),
            )
    finally:
        await app.state.container.close()

    async with pg_engine.connect() as conn:
        rows = (
            (await conn.execute(text("SELECT * FROM audit_events ORDER BY timestamp")))
            .mappings()
            .all()
        )
    assert rows, "expected audit rows from the chat request"
    for row in rows:
        for value in row.values():
            assert CANARY not in str(value), f"content leaked into column {row.keys()}"


async def test_policy_metadata_persisted_with_config(pg_settings, pg_engine):
    app = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            await client.post(
                "/v1/tools/execute",
                json={"tool_id": "system_status", "arguments": {}},
                headers=headers_for("policy-check", PERMS_ALL_DEMO),
            )
    finally:
        await app.state.container.close()

    async with pg_engine.connect() as conn:
        row = (await conn.execute(text("SELECT version, config FROM policies"))).first()
    assert row is not None
    version, config_json = row
    assert version  # a real version identifier was recorded
    assert "tools" in config_json  # the configuration itself is retained


# --- approvals: durability + validated transitions ---------------------------------


async def test_approval_persists_across_restart_and_transitions(pg_settings):
    # 1. Create a pending approval through the API.
    app1 = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app1), base_url="http://t") as c1:
            response = await c1.post(
                "/v1/tools/execute",
                json={
                    "tool_id": "publish_announcement",
                    "arguments": {"title": "t", "body": "b"},
                },
                headers=headers_for("requester", PERMS_ALL_DEMO),
            )
        assert response.status_code == 202
        approval_id = response.json()["approval_id"]
    finally:
        await app1.state.container.close()

    # 2. Restart: the pending record is still there; a reviewer approves it.
    app2 = create_app(pg_settings)
    try:
        store = app2.state.container.approvals
        record = await store.get(approval_id)
        assert record is not None
        assert record.status == ApprovalStatus.PENDING

        approved = await store.transition(
            approval_id, ApprovalStatus.APPROVED, reviewer_ref="reviewer-1"
        )
        assert approved.status == ApprovalStatus.APPROVED

        # Invalid moves are rejected by the validated state machine.
        from rasp.approvals.store import InvalidApprovalTransition

        with pytest.raises(InvalidApprovalTransition):
            await store.transition(approval_id, ApprovalStatus.REJECTED)
    finally:
        await app2.state.container.close()

    # 3. Restart again: the decision survived.
    app3 = create_app(pg_settings)
    try:
        final = await app3.state.container.approvals.get(approval_id)
        assert final is not None
        assert final.status == ApprovalStatus.APPROVED
        assert final.reviewer_ref == "reviewer-1"
        assert final.decided_at is not None
    finally:
        await app3.state.container.close()


async def test_duplicate_submission_creates_single_pending(pg_settings, pg_engine):
    """DB-enforced idempotency: one pending record per exact action."""
    app = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            body = {
                "tool_id": "publish_announcement",
                "arguments": {"title": "same", "body": "same"},
            }
            first = await client.post(
                "/v1/tools/execute", json=body, headers=headers_for("dup", PERMS_ALL_DEMO)
            )
            second = await client.post(
                "/v1/tools/execute", json=body, headers=headers_for("dup", PERMS_ALL_DEMO)
            )
        assert first.status_code == 202 and second.status_code == 202
        # Both submissions reference the SAME approval (partial unique index).
        assert first.json()["approval_id"] == second.json()["approval_id"]
        store = app.state.container.approvals
        records = await store.all()
        assert len(records) == 1
    finally:
        await app.state.container.close()

    async with pg_engine.connect() as conn:
        count = (await conn.execute(text("SELECT count(*) FROM approval_requests"))).scalar_one()
    assert count == 1


# --- access control (spec M2: unauthorized users cannot read records) --------------


async def test_audit_records_inaccessible_without_permission(pg_client):
    response = await pg_client.get("/v1/audit", headers=headers_for("intruder", ""))
    assert response.status_code == 403


async def test_audit_records_scoped_to_own_principal_in_database(pg_settings):
    app = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            victim = await client.post(
                "/v1/chat",
                json={"message": "victim activity"},
                headers=headers_for("db-victim", PERMS_ALL_DEMO),
            )
            victim_request = victim.json()["request_id"]

            # Observer generates their own activity to compare scopes.
            observer = await client.post(
                "/v1/chat",
                json={"message": "observer activity"},
                headers=headers_for("db-observer", PERMS_ALL_DEMO),
            )
            observer_request = observer.json()["request_id"]

            # Without audit:admin the observer sees none of the victim's
            # events, but does see their own (scoped to their principal)...
            scoped = await client.get(
                "/v1/audit",
                params={"limit": 100},
                headers=headers_for("db-observer", PERMS_ALL_DEMO),
            )
            seen = {e["request_id"] for e in scoped.json()["events"]}
            assert victim_request not in seen
            assert observer_request in seen  # own events visible

            # ...and a direct request for the victim's id returns nothing.
            filtered = await client.get(
                "/v1/audit",
                params={"request_id": victim_request},
                headers=headers_for("db-observer", PERMS_ALL_DEMO),
            )
            assert filtered.json()["count"] == 0

            # ...while audit:admin legitimately can review it.
            admin = await client.get(
                "/v1/audit",
                params={"request_id": victim_request},
                headers=headers_for("db-reviewer", PERMS_AUDIT_ADMIN),
            )
            assert admin.json()["count"] >= 1
    finally:
        await app.state.container.close()


async def test_no_http_surface_exists_for_approval_records(pg_client):
    """Approval records are not exposed by any route in M2 (decision API = M3)."""
    for path in ("/v1/approvals", "/v1/approvals/all", "/v1/review"):
        response = await pg_client.get(path, headers=headers_for("probe", PERMS_AUDIT_ADMIN))
        assert response.status_code == 404, path
