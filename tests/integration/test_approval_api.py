"""Integration tests: approval decision endpoints (Milestone 3).

Covers the full approval lifecycle over HTTP:
  propose (202) -> list/fetch (scoped) -> reviewer decides ->
  approved exact action executes once -> replay re-parks.

Authorization is default-deny and separation of duties is enforced:
`approvals:read` to see records, `approvals:review` to decide, and a
requester may never approve their own request.
"""

from __future__ import annotations

from tests.conftest import (
    PERMS_ALL_DEMO,
    PERMS_APPROVER,
    headers_for,
)

REQUESTER = "announcer"
REVIEWER = "reviewer-1"
ARGS = {"title": "t", "body": "b"}


async def _propose(client, principal: str = REQUESTER, perms: str = PERMS_ALL_DEMO) -> str:
    response = await client.post(
        "/v1/tools/execute",
        json={"tool_id": "publish_announcement", "arguments": ARGS},
        headers=headers_for(principal, perms),
    )
    assert response.status_code == 202
    return response.json()["approval_id"]


# --- authz: reading -----------------------------------------------------------------


async def test_list_requires_approvals_read(client):
    # audit:read alone does NOT imply approvals:read (default deny).
    response = await client.get("/v1/approvals", headers=headers_for("nobody", "audit:read"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_list_scoped_to_own_requests_without_review(client):
    await _propose(client, "victim-requester")
    await _propose(client, "observer-requester")

    response = await client.get(
        "/v1/approvals",
        params={"limit": 100},
        headers=headers_for("observer-requester", PERMS_ALL_DEMO),
    )
    assert response.status_code == 200
    approvers = {a["principal_ref"] for a in response.json()["approvals"]}
    # Only the observer's own records are visible.
    assert len(approvers) == 1


async def test_reviewer_sees_all_records(client):
    await _propose(client, "some-requester")
    response = await client.get(
        "/v1/approvals", params={"limit": 100}, headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    assert response.status_code == 200
    assert response.json()["count"] >= 1


async def test_fetch_other_principals_request_is_404_not_403(client):
    approval_id = await _propose(client, "secret-requester")
    response = await client.get(
        f"/v1/approvals/{approval_id}", headers=headers_for("intruder", PERMS_ALL_DEMO)
    )
    # Existence is never confirmed for another principal's record.
    assert response.status_code == 404


async def test_fetch_own_record_succeeds(client):
    approval_id = await _propose(client, REQUESTER)
    response = await client.get(
        f"/v1/approvals/{approval_id}", headers=headers_for(REQUESTER, PERMS_ALL_DEMO)
    )
    assert response.status_code == 200
    assert response.json()["approval_id"] == approval_id
    assert response.json()["status"] == "pending"


async def test_fetch_unknown_id_is_404(client):
    response = await client.get(
        "/v1/approvals/does-not-exist",
        headers=headers_for(REVIEWER, PERMS_APPROVER),
    )
    assert response.status_code == 404


# --- authz: deciding ----------------------------------------------------------------


async def test_decide_requires_review_permission(client):
    approval_id = await _propose(client, REQUESTER)
    response = await client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers=headers_for(REQUESTER, PERMS_ALL_DEMO),  # read only, no review
    )
    assert response.status_code == 403


async def test_self_approval_is_forbidden(client):
    approval_id = await _propose(client, REQUESTER)
    # The requester holds review authority but still may not approve their own.
    response = await client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers=headers_for(REQUESTER, PERMS_APPROVER),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "self_review_forbidden"
    # Still pending after the attempt.
    record = await client.get(
        f"/v1/approvals/{approval_id}", headers=headers_for(REQUESTER, PERMS_APPROVER)
    )
    assert record.json()["status"] == "pending"


async def test_reviewer_can_approve_a_different_requesters_action(client):
    approval_id = await _propose(client, REQUESTER)
    response = await client.post(
        f"/v1/approvals/{approval_id}/approve", headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    assert response.status_code == 200
    assert response.json()["approval"]["status"] == "approved"


async def test_requester_may_withdraw_own_request(client):
    approval_id = await _propose(client, REQUESTER)
    response = await client.post(
        f"/v1/approvals/{approval_id}/reject", headers=headers_for(REQUESTER, PERMS_APPROVER)
    )
    assert response.status_code == 200
    assert response.json()["approval"]["status"] == "rejected"


# --- idempotency and conflicts ------------------------------------------------------


async def test_repeated_approve_is_idempotent(client):
    approval_id = await _propose(client, REQUESTER)
    first = await client.post(
        f"/v1/approvals/{approval_id}/approve", headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    second = await client.post(
        f"/v1/approvals/{approval_id}/approve", headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    assert first.status_code == 200 and second.status_code == 200
    assert first.json()["approval"] == second.json()["approval"]


async def test_conflicting_decision_is_409(client):
    approval_id = await _propose(client, REQUESTER)
    await client.post(
        f"/v1/approvals/{approval_id}/approve", headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    conflict = await client.post(
        f"/v1/approvals/{approval_id}/reject", headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "invalid_approval_transition"


async def test_decision_body_cannot_carry_forged_claims(client):
    approval_id = await _propose(client, REQUESTER)
    response = await client.post(
        f"/v1/approvals/{approval_id}/approve",
        json={"approved": True, "reviewer": "admin"},
        headers=headers_for(REVIEWER, PERMS_APPROVER),
    )
    assert response.status_code == 422  # extra fields forbidden


async def test_decision_on_unknown_id_is_404(client):
    response = await client.post(
        "/v1/approvals/missing/approve", headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    assert response.status_code == 404


# --- full lifecycle over HTTP -------------------------------------------------------


async def test_approved_action_executes_once_and_is_consumed(client, container):
    from rasp.tools import builtin

    approval_id = await _propose(client, REQUESTER)

    # Approve, then re-submit the identical action: it executes once.
    await client.post(
        f"/v1/approvals/{approval_id}/approve", headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    executed = await client.post(
        "/v1/tools/execute",
        json={"tool_id": "publish_announcement", "arguments": ARGS},
        headers=headers_for(REQUESTER, PERMS_ALL_DEMO),
    )
    assert executed.status_code == 200
    assert builtin.EXECUTION_LOG == ["publish_announcement:t"]

    record = await container.approvals.get(approval_id)
    assert record.status.value == "consumed"

    # Replaying the same action never re-executes: it opens a fresh cycle.
    replay = await client.post(
        "/v1/tools/execute",
        json={"tool_id": "publish_announcement", "arguments": ARGS},
        headers=headers_for(REQUESTER, PERMS_ALL_DEMO),
    )
    assert replay.status_code == 202
    assert replay.json()["approval_id"] != approval_id
    assert builtin.EXECUTION_LOG == ["publish_announcement:t"]


async def test_rejected_action_never_executes_over_http(client):
    from rasp.tools import builtin

    approval_id = await _propose(client, REQUESTER)
    await client.post(
        f"/v1/approvals/{approval_id}/reject", headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    response = await client.post(
        "/v1/tools/execute",
        json={"tool_id": "publish_announcement", "arguments": ARGS},
        headers=headers_for(REQUESTER, PERMS_ALL_DEMO),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "approval_invalid"
    assert builtin.EXECUTION_LOG == []


# --- status filter ------------------------------------------------------------------


async def test_status_filter(client):
    approval_id = await _propose(client, REQUESTER)
    await client.post(
        f"/v1/approvals/{approval_id}/approve", headers=headers_for(REVIEWER, PERMS_APPROVER)
    )
    approved = await client.get(
        "/v1/approvals",
        params={"status": "approved", "limit": 100},
        headers=headers_for(REVIEWER, PERMS_APPROVER),
    )
    assert approved.status_code == 200
    assert all(a["status"] == "approved" for a in approved.json()["approvals"])
