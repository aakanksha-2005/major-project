"""Approval store (Milestone 2: PostgreSQL-backed, pluggable backend).

The facade owns domain logic that must hold for EVERY backend:
- pending creation is digest-bound and idempotent per exact action;
- lazy expiry of stale pendings;
- a validated state machine for approval transitions (spec M2:
  "approval state transitions are validated").

Lifecycle decision endpoints (approve/reject HTTP routes, reviewer authz)
arrive in Milestone 3 and will call `transition()`.
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


# Terminal states (rejected/expired) never transition again; approved can only
# be expired or invalidated (revocation), never re-decided.
_ALLOWED_TRANSITIONS: dict[ApprovalStatus, frozenset[ApprovalStatus]] = {
    ApprovalStatus.PENDING: frozenset(
        {
            ApprovalStatus.APPROVED,
            ApprovalStatus.REJECTED,
            ApprovalStatus.EXPIRED,
            ApprovalStatus.INVALIDATED,
        }
    ),
    ApprovalStatus.APPROVED: frozenset({ApprovalStatus.EXPIRED, ApprovalStatus.INVALIDATED}),
    ApprovalStatus.REJECTED: frozenset(),
    ApprovalStatus.EXPIRED: frozenset(),
    ApprovalStatus.INVALIDATED: frozenset(),
}

_DECIDED_STATUSES = frozenset(
    {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.INVALIDATED}
)


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

    async def all(self) -> list[ApprovalRecord]: ...

    async def save_status(
        self, record: ApprovalRecord, *, expected_status: ApprovalStatus
    ) -> ApprovalRecord:
        """Persist a status change only if the row is still in `expected_status`.

        Raises InvalidApprovalTransition on concurrent modification.
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

    async def all(self) -> list[ApprovalRecord]:
        return await self._backend.all()

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
