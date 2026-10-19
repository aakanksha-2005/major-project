"""Integration tests: audit endpoint authorization, scoping, and privacy."""

from __future__ import annotations

from tests.conftest import PERMS_ALL_DEMO, PERMS_AUDIT_ADMIN, headers_for


async def _make_events(client, principal: str, perms: str, message: str) -> str:
    """Generate audit activity and return the chat request_id."""
    response = await client.post(
        "/v1/chat",
        json={"message": message},
        headers=headers_for(principal, perms),
    )
    assert response.status_code == 200
    return response.json()["request_id"]


async def test_audit_requires_permission(client):
    response = await client.get("/v1/audit", headers=headers_for("nobody", ""))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_audit_returns_events_with_pagination(client, demo_headers):
    request_id = await _make_events(client, "audited-principal", PERMS_ALL_DEMO, "hello audit")
    response = await client.get(
        "/v1/audit",
        params={"request_id": request_id, "limit": 10},
        headers=headers_for("audited-principal", PERMS_ALL_DEMO),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 2  # request_received + response_screened minimum
    types = {event["event_type"] for event in data["events"]}
    assert "request_received" in types


async def test_audit_never_contains_chat_message_text(client, demo_headers):
    canary = "CANARY_SECRET_PHRASE_9f3a must not appear in audit"
    request_id = await _make_events(client, "privacy-checker", PERMS_ALL_DEMO, canary)
    response = await client.get(
        "/v1/audit",
        params={"request_id": request_id},
        headers=headers_for("privacy-checker", PERMS_ALL_DEMO),
    )
    assert response.status_code == 200
    assert canary not in response.text
    assert "9f3a" not in response.text


async def test_audit_scoped_to_own_principal_without_admin(client):
    victim_request = await _make_events(
        client, "victim-principal", PERMS_ALL_DEMO, "private activity victim"
    )
    await _make_events(client, "observer", PERMS_ALL_DEMO, "own activity observer")

    response = await client.get(
        "/v1/audit",
        params={"limit": 100},
        headers=headers_for("observer", PERMS_ALL_DEMO),
    )
    assert response.status_code == 200
    events = response.json()["events"]
    assert events, "observer should see own events"
    # The victim's events must not be visible to the observer.
    victim_ids = {victim_request}
    seen_request_ids = {event["request_id"] for event in events}
    assert not (victim_ids & seen_request_ids)
    # And filtering directly for the victim's request returns nothing.
    filtered = await client.get(
        "/v1/audit",
        params={"request_id": victim_request},
        headers=headers_for("observer", PERMS_ALL_DEMO),
    )
    assert filtered.json()["count"] == 0


async def test_audit_admin_sees_all_scopes(client):
    victim_request = await _make_events(
        client, "victim-principal", PERMS_ALL_DEMO, "activity victim 2"
    )
    response = await client.get(
        "/v1/audit",
        params={"request_id": victim_request},
        headers=headers_for("reviewer", PERMS_AUDIT_ADMIN),
    )
    assert response.status_code == 200
    assert response.json()["count"] >= 1


async def test_audit_pagination_bounds(client, demo_headers):
    response = await client.get(
        "/v1/audit",
        params={"limit": 1, "offset": 0},
        headers=headers_for("audited-principal", PERMS_ALL_DEMO),
    )
    if response.status_code == 200:
        assert response.json()["limit"] == 1
        assert len(response.json()["events"]) <= 1
    # Invalid bounds rejected.
    bad = await client.get(
        "/v1/audit",
        params={"limit": 5000},
        headers=headers_for("audited-principal", PERMS_ALL_DEMO),
    )
    assert bad.status_code == 422
