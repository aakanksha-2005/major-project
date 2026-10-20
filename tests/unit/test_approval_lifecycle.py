"""Milestone 3 approval lifecycle tests: decide, claim, find_for_action.

These exercise the backend-independent facade (in-memory backend), so they
run in the documented default suite without PostgreSQL.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from rasp.approvals.store import (
    ApprovalNotFoundError,
    ApprovalStore,
    InvalidApprovalTransition,
    SelfReviewForbidden,
)
from rasp.schemas.approval import ApprovalStatus, compute_action_digest

REQUESTER = "pid_requester"
REVIEWER = "pid_reviewer"


async def _pending(
    store: ApprovalStore,
    *,
    principal_ref: str = REQUESTER,
    tool_id: str = "publish_announcement",
    args: dict | None = None,
) -> str:
    record = await store.create_pending(
        request_id="req",
        principal_ref=principal_ref,
        tool_id=tool_id,
        action_digest=compute_action_digest(tool_id, args or {}, principal_ref, "1.0"),
        policy_version="1.0",
    )
    return record.approval_id


# --- decide: separation of duties ------------------------------------------------


async def test_requester_cannot_approve_own_request():
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    with pytest.raises(SelfReviewForbidden):
        await store.decide(approval_id, "approve", reviewer_ref=REQUESTER)
    # The record is untouched.
    record = await store.get(approval_id)
    assert record.status == ApprovalStatus.PENDING


async def test_different_reviewer_can_approve():
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    approved = await store.decide(approval_id, "approve", reviewer_ref=REVIEWER)
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.reviewer_ref == REVIEWER
    assert approved.decided_at is not None


async def test_requester_may_withdraw_own_pending_request():
    """Fail-closed withdrawals (reject) do not violate separation of duties."""
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    rejected = await store.decide(approval_id, "reject", reviewer_ref=REQUESTER)
    assert rejected.status == ApprovalStatus.REJECTED


# --- decide: idempotency ---------------------------------------------------------


async def test_repeated_approve_is_idempotent_and_unchanged():
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    first = await store.decide(approval_id, "approve", reviewer_ref=REVIEWER)
    second = await store.decide(approval_id, "approve", reviewer_ref=REVIEWER)
    assert first.model_dump() == second.model_dump()  # no new transition/timestamp


async def test_repeated_reject_is_idempotent():
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    first = await store.decide(approval_id, "reject", reviewer_ref=REVIEWER)
    second = await store.decide(approval_id, "reject", reviewer_ref=REVIEWER)
    assert first.model_dump() == second.model_dump()


async def test_repeat_approve_still_forbidden_for_self_review():
    """The self-approval guard is checked before idempotent short-circuit."""
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    await store.decide(approval_id, "approve", reviewer_ref=REVIEWER)
    with pytest.raises(SelfReviewForbidden):
        await store.decide(approval_id, "approve", reviewer_ref=REQUESTER)


async def test_conflicting_decision_raises_invalid_transition():
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    await store.decide(approval_id, "approve", reviewer_ref=REVIEWER)
    with pytest.raises(InvalidApprovalTransition):
        await store.decide(approval_id, "reject", reviewer_ref=REVIEWER)


async def test_decide_unknown_id_raises_not_found():
    store = ApprovalStore(ttl_seconds=60)
    with pytest.raises(ApprovalNotFoundError):
        await store.decide("missing", "approve", reviewer_ref=REVIEWER)


async def test_decide_unknown_action_raises_value_error():
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    with pytest.raises(ValueError):
        await store.decide(approval_id, "escalate", reviewer_ref=REVIEWER)


# --- revoke ----------------------------------------------------------------------


async def test_approved_can_be_revoked():
    store = ApprovalStore(ttl_seconds=60)
    approved_id = await _pending(store)
    await store.decide(approved_id, "approve", reviewer_ref=REVIEWER)
    revoked = await store.decide(approved_id, "revoke", reviewer_ref=REVIEWER)
    assert revoked.status == ApprovalStatus.INVALIDATED


async def test_revoking_pending_is_a_failclosed_withdrawal():
    """Revoking a still-pending request is legal (it withdraws authority)."""
    store = ApprovalStore(ttl_seconds=60)
    pending_id = await _pending(store, args={"title": "x"})
    revoked = await store.decide(pending_id, "revoke", reviewer_ref=REVIEWER)
    assert revoked.status == ApprovalStatus.INVALIDATED


async def test_terminal_records_cannot_be_revoked():
    store = ApprovalStore(ttl_seconds=60)
    rejected_id = await _pending(store, args={"title": "y"})
    await store.decide(rejected_id, "reject", reviewer_ref=REVIEWER)
    with pytest.raises(InvalidApprovalTransition):
        await store.decide(rejected_id, "revoke", reviewer_ref=REVIEWER)


# --- claim (single-use consumption) ----------------------------------------------


async def test_claim_consumes_approved_record():
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    await store.decide(approval_id, "approve", reviewer_ref=REVIEWER)
    claimed = await store.claim(approval_id)
    assert claimed.status == ApprovalStatus.CONSUMED
    assert claimed.consumed_at is not None


async def test_claim_is_single_use_second_attempt_fails():
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)
    await store.decide(approval_id, "approve", reviewer_ref=REVIEWER)
    await store.claim(approval_id)
    with pytest.raises(InvalidApprovalTransition):
        await store.claim(approval_id)


async def test_claim_requires_approved_status():
    store = ApprovalStore(ttl_seconds=60)
    approval_id = await _pending(store)  # still pending
    with pytest.raises(InvalidApprovalTransition):
        await store.claim(approval_id)


async def test_claim_unknown_id_raises_not_found():
    store = ApprovalStore(ttl_seconds=60)
    with pytest.raises(ApprovalNotFoundError):
        await store.claim("missing")


# --- find_for_action -------------------------------------------------------------


async def test_find_for_action_returns_none_when_absent():
    store = ApprovalStore(ttl_seconds=60)
    assert (
        await store.find_for_action(action_digest="d" * 64, principal_ref=REQUESTER, tool_id="t")
        is None
    )


async def test_find_for_action_prefers_live_pending():
    store = ApprovalStore(ttl_seconds=60)
    digest = compute_action_digest("t", {}, REQUESTER, "1.0")
    record = await store.create_pending(
        request_id="r",
        principal_ref=REQUESTER,
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    found = await store.find_for_action(action_digest=digest, principal_ref=REQUESTER, tool_id="t")
    assert found is not None and found.approval_id == record.approval_id


async def test_find_for_action_returns_approved_over_rejected():
    store = ApprovalStore(ttl_seconds=60)
    digest = compute_action_digest("t", {}, REQUESTER, "1.0")
    old = await store.create_pending(
        request_id="r1",
        principal_ref=REQUESTER,
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    await store.decide(old.approval_id, "approve", reviewer_ref=REVIEWER)
    found = await store.find_for_action(action_digest=digest, principal_ref=REQUESTER, tool_id="t")
    assert found is not None and found.status == ApprovalStatus.APPROVED


async def test_find_for_action_surfaces_newest_terminal_record():
    store = ApprovalStore(ttl_seconds=60)
    digest = compute_action_digest("t", {}, REQUESTER, "1.0")
    record = await store.create_pending(
        request_id="r",
        principal_ref=REQUESTER,
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    await store.decide(record.approval_id, "reject", reviewer_ref=REVIEWER)
    found = await store.find_for_action(action_digest=digest, principal_ref=REQUESTER, tool_id="t")
    assert found is not None and found.status == ApprovalStatus.REJECTED


async def test_find_for_action_lazily_expires_stale_pending():
    store = ApprovalStore(ttl_seconds=30)
    digest = compute_action_digest("t", {}, REQUESTER, "1.0")
    record = await store.create_pending(
        request_id="r",
        principal_ref=REQUESTER,
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    store.backend._records[record.approval_id] = record.model_copy(
        update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    found = await store.find_for_action(action_digest=digest, principal_ref=REQUESTER, tool_id="t")
    assert found is not None and found.status == ApprovalStatus.EXPIRED


async def test_find_for_action_is_action_scoped():
    store = ApprovalStore(ttl_seconds=60)
    await _pending(store, args={"title": "a"})
    other = await store.find_for_action(
        action_digest=compute_action_digest("t", {"title": "b"}, REQUESTER, "1.0"),
        principal_ref=REQUESTER,
        tool_id="t",
    )
    assert other is None


# --- stale pending does not block a fresh window ---------------------------------


async def test_stale_pending_does_not_block_new_pending():
    """A time-expired pending is retired so re-requesting opens a new window."""
    store = ApprovalStore(ttl_seconds=30)
    digest = compute_action_digest("t", {}, REQUESTER, "1.0")
    first = await store.create_pending(
        request_id="r1",
        principal_ref=REQUESTER,
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    store.backend._records[first.approval_id] = first.model_copy(
        update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    second = await store.create_pending(
        request_id="r2",
        principal_ref=REQUESTER,
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    assert second.approval_id != first.approval_id
    assert second.status == ApprovalStatus.PENDING
    # The original is now expired, not pending.
    original = await store.get(first.approval_id)
    assert original.status == ApprovalStatus.EXPIRED
