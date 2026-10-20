"""Approval store (Milestone 2: PostgreSQL-backed, pluggable backend).

The facade owns domain logic that must hold for EVERY backend:
- pending creation is digest-bound and idempotent per exact action;
- lazy expiry of stale pendings;
- a validated state machine for approval transitions (spec M2:
  "approval state transitions are validated");
- Milestone 3: reviewer decisions (`decide`), single-use consumption
  (`claim`), and lookup of the effective record for an exact action
  (`find_for_action`).

Lifecycle decision endpoints (approve/reject/revoke HTTP routes, reviewer
authz) live in `rasp.api.routes_approvals` and call `decide()`.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Protocol

from rasp.schemas.approval import ApprovalRecord, ApprovalStatus


class ApprovalError(Exception):
    """Base class for approval persistence/validation failures."""


class ApprovalNotFoundError(ApprovalError):
    def __init__(self, approval_id: str) -> None:
        super().__init__(f"approval '{approval_id}' does not exist")
        self.approval_id = approval_id


class InvalidApprovalTransition(ApprovalError):
    """Raised when a status change would violate the approval state machine."""

    def __init__(self, current: ApprovalStatus, requested: ApprovalStatus) -> None:
        super().__init__(f"invalid approval transition: {current.value} -> {requested.value}")
        self.current = current
        self.requested = requested


class SelfReviewForbidden(ApprovalError):
    """Raised when the requester attempts to approve their own request.

    Separation of duties: the principal who requested an action may never
    grant the approval that authorizes it. Fail-closed decisions (reject /
    revoke / withdraw) are NOT blocked — see `decide`.
    """

    def __init__(self, approval_id: str) -> None:
        super().__init__(f"the requester of approval '{approval_id}' cannot approve it")
        self.approval_id = approval_id


# Terminal states never transition again. Approved may only be expired,
# invalidated (revocation), or consumed (Milestone 3: single-use execution).
_ALLOWED_TRANSITIONS: dict[ApprovalStatus, frozenset[ApprovalStatus]] = {
    ApprovalStatus.PENDING: frozenset(
        {
            ApprovalStatus.APPROVED,
            ApprovalStatus.REJECTED,
            ApprovalStatus.EXPIRED,
            ApprovalStatus.INVALIDATED,
        }
    ),
    ApprovalStatus.APPROVED: frozenset(
        {ApprovalStatus.EXPIRED, ApprovalStatus.INVALIDATED, ApprovalStatus.CONSUMED}
    ),
    ApprovalStatus.REJECTED: frozenset(),
    ApprovalStatus.EXPIRED: frozenset(),
    ApprovalStatus.INVALIDATED: frozenset(),
    ApprovalStatus.CONSUMED: frozenset(),
}

_DECIDED_STATUSES = frozenset(
    {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.INVALIDATED}
)

# Reviewer decision actions -> target status. "revoke" withdraws an already
# approved authorization (fail closed) and is only legal from APPROVED.
DecisionAction = str  # "approve" | "reject" | "revoke"

_ACTION_TARGET: dict[str, ApprovalStatus] = {
    "approve": ApprovalStatus.APPROVED,
    "reject": ApprovalStatus.REJECTED,
    "revoke": ApprovalStatus.INVALIDATED,
}


class ApprovalBackend(Protocol):
    """Storage contract. Implementations may raise on persistence failure."""

    async def create(self, record: ApprovalRecord) -> ApprovalRecord:
        """Insert a pending record.

        If an identical pending record already exists for the same
        (action_digest, principal_ref, tool_id), return THAT record —
        duplicate submissions never create parallel approvals.
        """
        ...

    async def get_or_expire(self, approval_id: str, now: datetime) -> ApprovalRecord | None:
        """Fetch by id, lazily expiring stale pendings (race-safe in backend)."""
        ...

    async def find_for_action(
        self, action_digest: str, principal_ref: str, tool_id: str, now: datetime
    ) -> ApprovalRecord | None:
        """Return the effective record for one exact action.

        Preference order: a live PENDING record (lazily expiring stale ones
        first), then an APPROVED record, else the most recent record for the
        action. Returns None when no record exists at all.
        """
        ...

    async def all(self) -> list[ApprovalRecord]: ...

    async def save_status(
        self, record: ApprovalRecord, *, expected_status: ApprovalStatus
    ) -> ApprovalRecord:
        """Persist a status change only if the row is still in `expected_status`.

        Raises InvalidApprovalTransition on concurrent modification.
        """
        ...

    async def claim(self, approval_id: str, now: datetime) -> ApprovalRecord:
        """Atomically transition an APPROVED record to CONSUMED (single-use).

        Race-safe in every backend: exactly one caller may win. Raises
        InvalidApprovalTransition when the record is not currently APPROVED,
        and ApprovalNotFoundError when it does not exist.
        """
        ...


class InMemoryApprovalBackend:
    """NOT durable — restarts lose approvals. Used by the documented M1
    test/demo configuration (`RASP_PERSISTENCE=in_memory`)."""

    def __init__(self, ttl_seconds: int = 900) -> None:
        self._ttl_seconds = ttl_seconds
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = threading.Lock()

    async def create(self, record: ApprovalRecord) -> ApprovalRecord:
        with self._lock:
            for existing in self._records.values():
                if (
                    existing.status == ApprovalStatus.PENDING
                    and existing.action_digest == record.action_digest
                    and existing.principal_ref == record.principal_ref
                    and existing.tool_id == record.tool_id
                ):
                    if existing.expires_at <= datetime.now(UTC):
                        # Stale pending: retire it so a fresh approval window
                        # can open (mirrors the Postgres backend).
                        self._records[existing.approval_id] = existing.model_copy(
                            update={"status": ApprovalStatus.EXPIRED}
                        )
                        continue
                    return existing
            self._records[record.approval_id] = record
            return record

    async def get_or_expire(self, approval_id: str, now: datetime) -> ApprovalRecord | None:
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return None
            if record.status == ApprovalStatus.PENDING and record.expires_at <= now:
                expired = record.model_copy(update={"status": ApprovalStatus.EXPIRED})
                self._records[approval_id] = expired
                return expired
            return record

    async def find_for_action(
        self, action_digest: str, principal_ref: str, tool_id: str, now: datetime
    ) -> ApprovalRecord | None:
        with self._lock:
            matches: list[ApprovalRecord] = []
            for record in self._records.values():
                if (
                    record.action_digest != action_digest
                    or record.principal_ref != principal_ref
                    or record.tool_id != tool_id
                ):
                    continue
                if record.status == ApprovalStatus.PENDING and record.expires_at <= now:
                    record = record.model_copy(update={"status": ApprovalStatus.EXPIRED})
                    self._records[record.approval_id] = record
                matches.append(record)
            if not matches:
                return None
            for status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
                for record in matches:
                    if record.status == status:
                        return record
            # No live pending/approved record: surface the newest terminal
            # record for the action (rejected/expired/invalidated/consumed).
            return max(matches, key=lambda r: r.created_at)

    async def all(self) -> list[ApprovalRecord]:
        with self._lock:
            return list(self._records.values())

    async def save_status(
        self, record: ApprovalRecord, *, expected_status: ApprovalStatus
    ) -> ApprovalRecord:
        with self._lock:
            current = self._records.get(record.approval_id)
            if current is None:
                raise ApprovalNotFoundError(record.approval_id)
            if current.status != expected_status:
                raise InvalidApprovalTransition(current.status, record.status)
            self._records[record.approval_id] = record
            return record

    async def claim(self, approval_id: str, now: datetime) -> ApprovalRecord:
        with self._lock:
            current = self._records.get(approval_id)
            if current is None:
                raise ApprovalNotFoundError(approval_id)
            if current.status != ApprovalStatus.APPROVED:
                raise InvalidApprovalTransition(current.status, ApprovalStatus.CONSUMED)
            consumed = current.model_copy(
                update={"status": ApprovalStatus.CONSUMED, "consumed_at": now}
            )
            self._records[approval_id] = consumed
            return consumed


class ApprovalStore:
    """Facade over an ApprovalBackend: domain rules stay backend-independent.

    Constructor stays backwards-compatible (`ApprovalStore(ttl_seconds=...)`
    builds the in-memory backend) so the Milestone 1 unit suite keeps working.
    """

    def __init__(self, ttl_seconds: int = 900, backend: ApprovalBackend | None = None) -> None:
        self._ttl_seconds = ttl_seconds
        self._backend: ApprovalBackend = backend or InMemoryApprovalBackend(ttl_seconds)

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    @property
    def backend(self) -> ApprovalBackend:
        return self._backend

    async def create_pending(
        self,
        *,
        request_id: str,
        principal_ref: str,
        tool_id: str,
        action_digest: str,
        policy_version: str,
    ) -> ApprovalRecord:
        now = datetime.now(UTC)
        record = ApprovalRecord(
            request_id=request_id,
            principal_ref=principal_ref,
            tool_id=tool_id,
            action_digest=action_digest,
            policy_version=policy_version,
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
        )
        return await self._backend.create(record)

    async def get(self, approval_id: str) -> ApprovalRecord | None:
        """Fetch a record, lazily expiring stale pendings."""
        return await self._backend.get_or_expire(approval_id, datetime.now(UTC))

    async def find_for_action(
        self, *, action_digest: str, principal_ref: str, tool_id: str
    ) -> ApprovalRecord | None:
        """The effective record for one exact action (see backend contract)."""
        return await self._backend.find_for_action(
            action_digest, principal_ref, tool_id, datetime.now(UTC)
        )

    async def all(self) -> list[ApprovalRecord]:
        return await self._backend.all()

    async def claim(self, approval_id: str) -> ApprovalRecord:
        """Atomically consume an APPROVED record (single-use execution).

        Exactly one concurrent caller may win; the rest receive
        InvalidApprovalTransition. Raises ApprovalNotFoundError when unknown.
        """
        return await self._backend.claim(approval_id, datetime.now(UTC))

    async def decide(
        self,
        approval_id: str,
        action: DecisionAction,
        *,
        reviewer_ref: str,
    ) -> ApprovalRecord:
        """Apply a reviewer decision, enforcing separation of duties.

        - `approve` requires the reviewer to differ from the requester;
          self-approval raises SelfReviewForbidden.
        - `reject` / `revoke` are fail-closed withdrawals and may be
          performed by anyone with review authority (including the requester,
          to withdraw their own request).
        - Repeating the same decision is idempotent: the unchanged record is
          returned (and re-transitions are never attempted).
        - Any other transition raises InvalidApprovalTransition (HTTP 409).
        """
        target = _ACTION_TARGET.get(action)
        if target is None:
            raise ValueError(f"unknown approval action '{action}'")
        record = await self.get(approval_id)
        if record is None:
            raise ApprovalNotFoundError(approval_id)

        if target == ApprovalStatus.APPROVED and record.principal_ref == reviewer_ref:
            # Separation of duties: never let a requester authorize their own
            # action. Checked before idempotency so the rule is unconditional.
            raise SelfReviewForbidden(approval_id)

        if record.status == target:
            return record  # idempotent replay: unchanged, no new transition

        return await self.transition(approval_id, target, reviewer_ref=reviewer_ref)

    async def transition(
        self,
        approval_id: str,
        new_status: ApprovalStatus,
        *,
        reviewer_ref: str | None = None,
    ) -> ApprovalRecord:
        """Apply a validated state transition (Milestone 2 acceptance).

        Raises ApprovalNotFoundError for unknown ids and
        InvalidApprovalTransition for illegal state-machine moves.
        """
        record = await self.get(approval_id)
        if record is None:
            raise ApprovalNotFoundError(approval_id)
        if new_status not in _ALLOWED_TRANSITIONS[record.status]:
            raise InvalidApprovalTransition(record.status, new_status)
        update: dict = {"status": new_status}
        if new_status in _DECIDED_STATUSES:
            update["decided_at"] = datetime.now(UTC)
            update["reviewer_ref"] = reviewer_ref
        elif new_status == ApprovalStatus.EXPIRED:
            update["reviewer_ref"] = None
        new_record = record.model_copy(update=update)
        return await self._backend.save_status(new_record, expected_status=record.status)


__all__ = [
    "ApprovalBackend",
    "ApprovalError",
    "ApprovalNotFoundError",
    "ApprovalStore",
    "InMemoryApprovalBackend",
    "InvalidApprovalTransition",
    "SelfReviewForbidden",
]
