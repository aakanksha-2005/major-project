"""Approval binding, digest, and store tests (spec §11: approval integrity)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from rasp.approvals.store import ApprovalStore
from rasp.schemas.approval import (
    ApprovalRecord,
    ApprovalStatus,
    compute_action_digest,
)

# --- digest binding ------------------------------------------------------------


def test_digest_is_deterministic():
    a = compute_action_digest("tool_x", {"n": 1}, "principal-1", "1.0")
    b = compute_action_digest("tool_x", {"n": 1}, "principal-1", "1.0")
    assert a == b
    assert len(a) == 64


def test_digest_changes_when_arguments_change():
    base = compute_action_digest("tool_x", {"n": 1}, "p", "1.0")
    changed = compute_action_digest("tool_x", {"n": 2}, "p", "1.0")
    assert base != changed


def test_digest_changes_when_principal_changes():
    base = compute_action_digest("tool_x", {"n": 1}, "p1", "1.0")
    changed = compute_action_digest("tool_x", {"n": 1}, "p2", "1.0")
    assert base != changed


def test_digest_changes_when_policy_version_changes():
    base = compute_action_digest("tool_x", {}, "p", "1.0")
    changed = compute_action_digest("tool_x", {}, "p", "1.1")
    assert base != changed


def test_digest_is_key_order_independent():
    a = compute_action_digest("t", {"a": 1, "b": 2}, "p", "1.0")
    b = compute_action_digest("t", {"b": 2, "a": 1}, "p", "1.0")
    assert a == b


# --- record validity -----------------------------------------------------------


def _record(status=ApprovalStatus.APPROVED, expires_in=timedelta(minutes=5)) -> ApprovalRecord:
    now = datetime.now(UTC)
    args = {"title": "t"}
    return ApprovalRecord(
        request_id="req-1",
        principal_ref="p1",
        tool_id="publish_announcement",
        action_digest=compute_action_digest("publish_announcement", args, "p1", "1.0"),
        policy_version="1.0",
        status=status,
        created_at=now,
        expires_at=now + expires_in,
    )


def _valid_args_digest() -> str:
    return compute_action_digest("publish_announcement", {"title": "t"}, "p1", "1.0")


def test_approved_matching_binding_is_valid():
    record = _record()
    assert record.is_valid_for(action_digest=_valid_args_digest(), principal_ref="p1")


def test_pending_is_never_valid():
    record = _record(status=ApprovalStatus.PENDING)
    assert not record.is_valid_for(action_digest=_valid_args_digest(), principal_ref="p1")


def test_rejected_is_never_valid():
    record = _record(status=ApprovalStatus.REJECTED)
    assert not record.is_valid_for(action_digest=_valid_args_digest(), principal_ref="p1")


def test_wrong_digest_is_invalid():
    record = _record()
    assert not record.is_valid_for(action_digest="0" * 64, principal_ref="p1")


def test_wrong_principal_is_invalid():
    record = _record()
    assert not record.is_valid_for(action_digest=_valid_args_digest(), principal_ref="p2")


def test_expired_is_invalid():
    record = _record(expires_in=timedelta(seconds=-5))
    assert not record.is_valid_for(action_digest=_valid_args_digest(), principal_ref="p1")


# --- store (async facade, in-memory backend) -------------------------------------


async def test_create_pending_and_get():
    store = ApprovalStore(ttl_seconds=60)
    digest = compute_action_digest("t", {}, "p", "1.0")
    record = await store.create_pending(
        request_id="req",
        principal_ref="p",
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    assert record.status == ApprovalStatus.PENDING
    fetched = await store.get(record.approval_id)
    assert fetched is not None and fetched.approval_id == record.approval_id


async def test_duplicate_pending_for_same_action_is_idempotent():
    """Re-submitting the identical action returns the SAME pending record."""
    store = ApprovalStore(ttl_seconds=60)
    digest = compute_action_digest("t", {"a": 1}, "p", "1.0")
    first = await store.create_pending(
        request_id="req-1",
        principal_ref="p",
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    second = await store.create_pending(
        request_id="req-2",  # different request, identical action
        principal_ref="p",
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    assert second.approval_id == first.approval_id
    records = await store.all()
    assert len(records) == 1  # never two parallel approvals for one action


async def test_different_action_gets_its_own_pending():
    store = ApprovalStore(ttl_seconds=60)
    a = await store.create_pending(
        request_id="r1",
        principal_ref="p",
        tool_id="t",
        action_digest=compute_action_digest("t", {"a": 1}, "p", "1.0"),
        policy_version="1.0",
    )
    b = await store.create_pending(
        request_id="r2",
        principal_ref="p",
        tool_id="t",
        action_digest=compute_action_digest("t", {"a": 2}, "p", "1.0"),
        policy_version="1.0",
    )
    assert a.approval_id != b.approval_id


async def test_get_unknown_returns_none():
    assert await ApprovalStore().get("missing") is None


async def test_stale_pending_lazily_expires():
    store = ApprovalStore(ttl_seconds=30)
    digest = compute_action_digest("t", {}, "p", "1.0")
    record = await store.create_pending(
        request_id="req",
        principal_ref="p",
        tool_id="t",
        action_digest=digest,
        policy_version="1.0",
    )
    # Force expiry as if time passed.
    store.backend._records[record.approval_id] = record.model_copy(
        update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    fetched = await store.get(record.approval_id)
    assert fetched is not None
    assert fetched.status == ApprovalStatus.EXPIRED


# --- approval state machine (Milestone 2 acceptance) ------------------------------


async def _pending(store: ApprovalStore) -> ApprovalRecord:
    return await store.create_pending(
        request_id="req",
        principal_ref="p",
        tool_id="t",
        action_digest=compute_action_digest("t", {}, "p", "1.0"),
        policy_version="1.0",
    )


async def test_pending_can_be_approved_with_reviewer():
    store = ApprovalStore(ttl_seconds=60)
    record = await _pending(store)
    approved = await store.transition(
        record.approval_id, ApprovalStatus.APPROVED, reviewer_ref="reviewer-1"
    )
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.reviewer_ref == "reviewer-1"
    assert approved.decided_at is not None


async def test_pending_can_be_rejected():
    store = ApprovalStore(ttl_seconds=60)
    record = await _pending(store)
    rejected = await store.transition(record.approval_id, ApprovalStatus.REJECTED)
    assert rejected.status == ApprovalStatus.REJECTED


async def test_rejected_is_terminal_no_reopening():
    from rasp.approvals.store import InvalidApprovalTransition

    store = ApprovalStore(ttl_seconds=60)
    record = await _pending(store)
    await store.transition(record.approval_id, ApprovalStatus.REJECTED)
    with pytest.raises(InvalidApprovalTransition):
        await store.transition(record.approval_id, ApprovalStatus.APPROVED)


async def test_approved_cannot_be_rejected_only_invalidated():
    from rasp.approvals.store import InvalidApprovalTransition

    store = ApprovalStore(ttl_seconds=60)
    record = await _pending(store)
    await store.transition(record.approval_id, ApprovalStatus.APPROVED)
    with pytest.raises(InvalidApprovalTransition):
        await store.transition(record.approval_id, ApprovalStatus.REJECTED)
    # Revocation remains possible.
    revoked = await store.transition(record.approval_id, ApprovalStatus.INVALIDATED)
    assert revoked.status == ApprovalStatus.INVALIDATED


async def test_expired_is_terminal():
    from rasp.approvals.store import InvalidApprovalTransition

    store = ApprovalStore(ttl_seconds=60)
    record = await _pending(store)
    store.backend._records[record.approval_id] = record.model_copy(
        update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    await store.get(record.approval_id)  # lazily flips to expired
    with pytest.raises(InvalidApprovalTransition):
        await store.transition(record.approval_id, ApprovalStatus.APPROVED)


async def test_transition_unknown_id_raises_not_found():
    from rasp.approvals.store import ApprovalNotFoundError

    store = ApprovalStore(ttl_seconds=60)
    with pytest.raises(ApprovalNotFoundError):
        await store.transition("missing", ApprovalStatus.APPROVED)
