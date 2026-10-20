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
from rasp.schemas.approval import ApprovalRecord, ApprovalStatus
from tests.conftest import PERMS_ALL_DEMO, PERMS_APPROVER, PERMS_AUDIT_ADMIN, headers_for

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
        columns = {
            row[0]
            for row in await conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'approval_requests'"
                )
            )
        }
    assert {"policies", "approval_requests", "audit_events"} <= tables
    # Milestone 3 head: adds single-use consumption.
    assert version == "0002_approval_consumed"
    assert "consumed_at" in columns


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


async def test_approval_records_require_permission_over_http(pg_client):
    """Milestone 3: approval records have an API surface — but default deny.

    A caller without `approvals:read` cannot list or fetch records; unknown
    ids never leak existence. (M2 asserted no surface existed at all; the
    decision API is exactly what M3 adds.)
    """
    # audit:admin does NOT imply approvals:read (default deny).
    listing = await pg_client.get(
        "/v1/approvals", headers=headers_for("probe", "audit:read,audit:admin")
    )
    assert listing.status_code == 403
    assert listing.json()["error"]["code"] == "forbidden"

    single = await pg_client.get(
        "/v1/approvals/does-not-exist", headers=headers_for("probe", "audit:read")
    )
    assert single.status_code == 403

    # Still-unknown routes stay 404.
    for path in ("/v1/approvals/all", "/v1/review"):
        response = await pg_client.get(path, headers=headers_for("probe", PERMS_AUDIT_ADMIN))
        assert response.status_code == 404, path


# --- Milestone 3: consumption, decisions, and durable single-use --------------------


async def test_approved_action_executes_once_and_consumption_is_durable(pg_settings, pg_engine):
    """The full lifecycle against the real database.

    propose -> reviewer approves -> action executes once -> the approval is
    CONSUMED (durably, with consumed_at) -> replay re-parks without executing.
    """
    from rasp.tools import builtin

    builtin.EXECUTION_LOG.clear()
    try:
        app = create_app(pg_settings)
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
                proposed = await client.post(
                    "/v1/tools/execute",
                    json={
                        "tool_id": "publish_announcement",
                        "arguments": {"title": "dbconsumed", "body": "b"},
                    },
                    headers=headers_for("db-requester", PERMS_ALL_DEMO),
                )
                assert proposed.status_code == 202
                approval_id = proposed.json()["approval_id"]

                # Self-approval is forbidden even with reviewer rights.
                forbidden = await client.post(
                    f"/v1/approvals/{approval_id}/approve",
                    headers=headers_for("db-requester", PERMS_APPROVER),
                )
                assert forbidden.status_code == 403
                assert forbidden.json()["error"]["code"] == "self_review_forbidden"

                decided = await client.post(
                    f"/v1/approvals/{approval_id}/approve",
                    headers=headers_for("db-reviewer", PERMS_APPROVER),
                )
                assert decided.status_code == 200
                assert decided.json()["approval"]["status"] == "approved"

                executed = await client.post(
                    "/v1/tools/execute",
                    json={
                        "tool_id": "publish_announcement",
                        "arguments": {"title": "dbconsumed", "body": "b"},
                    },
                    headers=headers_for("db-requester", PERMS_ALL_DEMO),
                )
                assert executed.status_code == 200
                assert builtin.EXECUTION_LOG == ["publish_announcement:dbconsumed"]

                replay = await client.post(
                    "/v1/tools/execute",
                    json={
                        "tool_id": "publish_announcement",
                        "arguments": {"title": "dbconsumed", "body": "b"},
                    },
                    headers=headers_for("db-requester", PERMS_ALL_DEMO),
                )
                assert replay.status_code == 202
                assert replay.json()["approval_id"] != approval_id
        finally:
            await app.state.container.close()
    finally:
        builtin.EXECUTION_LOG.clear()

    # Durable consumption: the row itself records the terminal state.
    async with pg_engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT status, consumed_at FROM approval_requests WHERE approval_id = :aid"),
                {"aid": approval_id},
            )
        ).one()
    assert row[0] == "consumed"
    assert row[1] is not None


async def test_consumed_status_survives_restart(pg_settings):
    """A consumed approval stays consumed across an application restart."""
    app1 = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app1), base_url="http://t") as c1:
            proposed = await c1.post(
                "/v1/tools/execute",
                json={"tool_id": "publish_announcement", "arguments": {"title": "r", "body": "b"}},
                headers=headers_for("restart-consumer", PERMS_ALL_DEMO),
            )
            approval_id = proposed.json()["approval_id"]
            store = app1.state.container.approvals
            await store.decide(approval_id, "approve", reviewer_ref="pid_reviewer")
            consumed = await store.claim(approval_id)
            assert consumed.status == ApprovalStatus.CONSUMED
    finally:
        await app1.state.container.close()

    app2 = create_app(pg_settings)
    try:
        record = await app2.state.container.approvals.get(approval_id)
        assert record is not None
        assert record.status == ApprovalStatus.CONSUMED
        assert record.consumed_at is not None
    finally:
        await app2.state.container.close()


async def test_claim_is_race_safe_in_the_database(pg_settings):
    """Concurrent claims of one approved record: exactly one succeeds."""
    import asyncio

    from rasp.approvals.store import InvalidApprovalTransition

    app = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            proposed = await client.post(
                "/v1/tools/execute",
                json={
                    "tool_id": "publish_announcement",
                    "arguments": {"title": "race", "body": "b"},
                },
                headers=headers_for("race-db", PERMS_ALL_DEMO),
            )
        approval_id = proposed.json()["approval_id"]
        store = app.state.container.approvals
        await store.decide(approval_id, "approve", reviewer_ref="pid_reviewer")

        results = await asyncio.gather(
            *(store.claim(approval_id) for _ in range(6)),
            return_exceptions=True,
        )
        successes = [r for r in results if isinstance(r, ApprovalRecord)]
        failures = [r for r in results if isinstance(r, InvalidApprovalTransition)]
        assert len(successes) == 1
        assert len(failures) == 5
    finally:
        await app.state.container.close()


async def test_decision_endpoints_persist_audit_event(pg_settings, pg_engine):
    """A reviewer decision emits a content-free APPROVAL_DECIDED audit event."""
    app = create_app(pg_settings)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            proposed = await client.post(
                "/v1/tools/execute",
                json={
                    "tool_id": "publish_announcement",
                    "arguments": {"title": "aud", "body": "b"},
                },
                headers=headers_for("audit-requester", PERMS_ALL_DEMO),
            )
            approval_id = proposed.json()["approval_id"]
            decided = await client.post(
                f"/v1/approvals/{approval_id}/reject",
                headers=headers_for("audit-reviewer", PERMS_APPROVER),
            )
            assert decided.status_code == 200
            decision_request_id = decided.json()["request_id"]
    finally:
        await app.state.container.close()

    async with pg_engine.connect() as conn:
        rows = (
            (
                await conn.execute(
                    text(
                        "SELECT event_type, decision, reason_code, approval_id, tool_id "
                        "FROM audit_events WHERE request_id = :rid"
                    ),
                    {"rid": decision_request_id},
                )
            )
            .mappings()
            .all()
        )
    assert len(rows) == 1
    event = rows[0]
    assert event["event_type"] == "approval_decided"
    assert event["decision"] == "deny"
    assert event["reason_code"] == "approval_rejected"
    assert event["approval_id"] == approval_id
    assert event["tool_id"] == "publish_announcement"
