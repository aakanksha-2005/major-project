"""PostgreSQL implementations of the audit/approval store contracts.

Fail-closed posture (Milestone 2 acceptance: "database failure prevents
sensitive actions from executing"): these implementations RAISE when the
database is unreachable. The executor decides how to treat the failure —
mutating actions are denied, read-only actions may proceed with a
documented `audit_persistence_failed` flag (see docs/LIMITATIONS.md).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from rasp.approvals.store import (
    ApprovalNotFoundError,
    InvalidApprovalTransition,
)
from rasp.persistence.db import Database
from rasp.persistence.models import ApprovalRow, AuditEventRow, PolicyRow
from rasp.policy.config import PolicyConfig
from rasp.schemas.approval import ApprovalRecord, ApprovalStatus
from rasp.schemas.audit import AuditEvent


class PolicyRepository:
    """Persists which policy version was in force (spec §9: policies).

    `ensure_persisted` is idempotent (INSERT ... ON CONFLICT DO NOTHING)
    and cached per process/version, so callers can invoke it cheaply
    before any write that references a policy version.
    """

    def __init__(self, db: Database, config: PolicyConfig) -> None:
        self._db = db
        self._config = config
        self._persisted: set[str] = set()

    async def ensure_persisted(self, version: str | None = None) -> str:
        target = version or self._config.version
        if target in self._persisted:
            return target
        if target == self._config.version:
            payload: dict = self._config.model_dump(mode="json")
        else:
            # A version we cannot reconstruct (e.g. events recorded before a
            # restart under older policy) — persist an explicit marker
            # instead of pretending we hold that configuration.
            payload = {"version": target, "source": "not_captured_at_runtime"}
        stmt = (
            pg_insert(PolicyRow)
            .values(version=target, config=payload, enabled=True)
            .on_conflict_do_nothing(index_elements=[PolicyRow.version])
        )
        async with self._db.session() as session:
            await session.execute(stmt)
        self._persisted.add(target)
        return target


class PostgresAuditStore:
    """Durable, queryable audit trail (content-free by column design)."""

    def __init__(self, db: Database, policy_repo: PolicyRepository) -> None:
        self._db = db
        self._policy = policy_repo

    async def record(self, event: AuditEvent) -> AuditEvent:
        if event.policy_version:
            await self._policy.ensure_persisted(event.policy_version)
        async with self._db.session() as session:
            session.add(_event_to_row(event))
        return event

    async def query(
        self,
        *,
        request_id: str | None = None,
        principal_refs: Iterable[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEvent]:
        stmt = select(AuditEventRow)
        if request_id is not None:
            stmt = stmt.where(AuditEventRow.request_id == request_id)
        if principal_refs is not None:
            refs = list(principal_refs)
            stmt = stmt.where(AuditEventRow.principal_ref.in_(refs))
        # Newest first; event_id breaks timestamp ties deterministically.
        stmt = stmt.order_by(AuditEventRow.timestamp.desc(), AuditEventRow.event_id.desc())
        stmt = stmt.limit(limit).offset(offset)
        async with self._db.session() as session:
            rows = (await session.execute(stmt)).scalars().all()
        return [_row_to_event(row) for row in rows]

    async def count(self) -> int:
        async with self._db.session() as session:
            result = await session.execute(select(func.count()).select_from(AuditEventRow))
            return int(result.scalar_one())


class PostgresApprovalStore:
    """Approval records with race-safe idempotent pending creation."""

    def __init__(self, db: Database, policy_repo: PolicyRepository) -> None:
        self._db = db
        self._policy = policy_repo

    async def create(self, record: ApprovalRecord) -> ApprovalRecord:
        # Approval rows carry a foreign key to policies — metadata first.
        await self._policy.ensure_persisted(record.policy_version)
        # Retire any matching stale pending first so a fresh approval window
        # can open (the partial unique index would otherwise keep pointing at
        # an already-expired request).
        expire_stale = (
            update(ApprovalRow)
            .where(
                ApprovalRow.action_digest == record.action_digest,
                ApprovalRow.principal_ref == record.principal_ref,
                ApprovalRow.tool_id == record.tool_id,
                ApprovalRow.status == "pending",
                ApprovalRow.expires_at <= record.created_at,
            )
            .values(status="expired")
        )
        stmt = (
            pg_insert(ApprovalRow)
            .values(**_approval_to_row_values(record))
            .on_conflict_do_nothing(
                index_elements=[
                    ApprovalRow.action_digest,
                    ApprovalRow.principal_ref,
                    ApprovalRow.tool_id,
                ],
                index_where=ApprovalRow.status == "pending",
            )
        )
        try:
            async with self._db.session() as session:
                await session.execute(expire_stale)
                await session.execute(stmt)
        except IntegrityError:
            # Concurrent duplicate: the partial unique index won. The
            # authoritative pending row is fetched below.
            pass
        existing = await self._find_pending(record)
        if existing is None:
            # The pending row vanished between insert and fetch (concurrent
            # transition). Fail loudly: the executor treats this as a
            # persistence failure and denies.
            raise ApprovalNotFoundError(record.approval_id)
        return existing

    async def _find_pending(self, record: ApprovalRecord) -> ApprovalRecord | None:
        stmt = select(ApprovalRow).where(
            ApprovalRow.action_digest == record.action_digest,
            ApprovalRow.principal_ref == record.principal_ref,
            ApprovalRow.tool_id == record.tool_id,
            ApprovalRow.status == "pending",
        )
        async with self._db.session() as session:
            row = (await session.execute(stmt)).scalar_one_or_none()
        return _row_to_approval(row) if row is not None else None

    async def get_or_expire(self, approval_id: str, now: datetime) -> ApprovalRecord | None:
        expire = (
            update(ApprovalRow)
            .where(
                ApprovalRow.approval_id == approval_id,
                ApprovalRow.status == "pending",
                ApprovalRow.expires_at <= now,
            )
            .values(status="expired")
        )
        select_stmt = select(ApprovalRow).where(ApprovalRow.approval_id == approval_id)
        async with self._db.session() as session:
            await session.execute(expire)
            row = (await session.execute(select_stmt)).scalar_one_or_none()
        return _row_to_approval(row) if row is not None else None

    async def all(self) -> list[ApprovalRecord]:
        stmt = select(ApprovalRow).order_by(ApprovalRow.created_at.desc())
        async with self._db.session() as session:
            rows = (await session.execute(stmt)).scalars().all()
        return [_row_to_approval(row) for row in rows]

    async def find_for_action(
        self, action_digest: str, principal_ref: str, tool_id: str, now: datetime
    ) -> ApprovalRecord | None:
        # Lazily retire a stale pending for this action so the returned state
        # reflects reality (and a fresh window can be opened afterwards).
        expire_stale = (
            update(ApprovalRow)
            .where(
                ApprovalRow.action_digest == action_digest,
                ApprovalRow.principal_ref == principal_ref,
                ApprovalRow.tool_id == tool_id,
                ApprovalRow.status == "pending",
                ApprovalRow.expires_at <= now,
            )
            .values(status="expired")
        )
        stmt = (
            select(ApprovalRow)
            .where(
                ApprovalRow.action_digest == action_digest,
                ApprovalRow.principal_ref == principal_ref,
                ApprovalRow.tool_id == tool_id,
            )
            .order_by(ApprovalRow.created_at.desc())
        )
        async with self._db.session() as session:
            await session.execute(expire_stale)
            rows = (await session.execute(stmt)).scalars().all()
        records = [_row_to_approval(row) for row in rows]
        if not records:
            return None
        # Prefer a live pending, then an approved record, else newest terminal.
        for status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
            for record in records:
                if record.status == status:
                    return record
        return records[0]  # newest-first ordering

    async def claim(self, approval_id: str, now: datetime) -> ApprovalRecord:
        """Atomic single-use consumption: UPDATE ... WHERE status='approved'.

        The row-level guard makes this race-safe: concurrent executors of the
        same approved action cannot both win.
        """
        stmt = (
            update(ApprovalRow)
            .where(
                ApprovalRow.approval_id == approval_id,
                ApprovalRow.status == ApprovalStatus.APPROVED.value,
            )
            .values(status=ApprovalStatus.CONSUMED.value, consumed_at=now)
        )
        async with self._db.session() as session:
            result = await session.execute(stmt)
            if result.rowcount == 0:
                current = (
                    await session.execute(
                        select(ApprovalRow).where(ApprovalRow.approval_id == approval_id)
                    )
                ).scalar_one_or_none()
                if current is None:
                    raise ApprovalNotFoundError(approval_id)
                raise InvalidApprovalTransition(
                    ApprovalStatus(current.status), ApprovalStatus.CONSUMED
                )
            row = (
                await session.execute(
                    select(ApprovalRow).where(ApprovalRow.approval_id == approval_id)
                )
            ).scalar_one()
        return _row_to_approval(row)

    async def save_status(
        self, record: ApprovalRecord, *, expected_status: ApprovalStatus
    ) -> ApprovalRecord:
        stmt = (
            update(ApprovalRow)
            .where(
                ApprovalRow.approval_id == record.approval_id,
                ApprovalRow.status == expected_status.value,
            )
            .values(
                status=record.status.value,
                reviewer_ref=record.reviewer_ref,
                decided_at=record.decided_at,
                consumed_at=record.consumed_at,
            )
        )
        async with self._db.session() as session:
            result = await session.execute(stmt)
            if result.rowcount == 0:
                # Optimistic guard failed: read the actual state for an
                # accurate error (the block's rollback discards nothing).
                current = (
                    await session.execute(
                        select(ApprovalRow).where(ApprovalRow.approval_id == record.approval_id)
                    )
                ).scalar_one_or_none()
                if current is None:
                    raise ApprovalNotFoundError(record.approval_id)
                raise InvalidApprovalTransition(ApprovalStatus(current.status), record.status)
        return record


# --- row <-> domain mapping -----------------------------------------------------


def _event_to_row(event: AuditEvent) -> AuditEventRow:
    return AuditEventRow(
        event_id=event.event_id,
        request_id=event.request_id,
        correlation_id=event.correlation_id,
        timestamp=event.timestamp,
        principal_ref=event.principal_ref,
        event_type=event.event_type.value,
        tool_id=event.tool_id,
        policy_version=event.policy_version,
        decision=event.decision.value if event.decision else None,
        reason_code=event.reason_code.value if event.reason_code else None,
        approval_id=event.approval_id,
        execution_status=event.execution_status,
        duration_ms=event.duration_ms,
        error_category=event.error_category,
        action_digest=event.action_digest,
        security_flags=list(event.security_flags),
    )


def _row_to_event(row: AuditEventRow) -> AuditEvent:
    # Pydantic coerces the stored strings back into the enum types.
    return AuditEvent(
        event_id=row.event_id,
        request_id=row.request_id,
        correlation_id=row.correlation_id,
        timestamp=row.timestamp,
        principal_ref=row.principal_ref,
        event_type=row.event_type,
        tool_id=row.tool_id,
        policy_version=row.policy_version,
        decision=row.decision,
        reason_code=row.reason_code,
        approval_id=row.approval_id,
        execution_status=row.execution_status,
        duration_ms=row.duration_ms,
        error_category=row.error_category,
        action_digest=row.action_digest,
        security_flags=list(row.security_flags or []),
    )


def _approval_to_row_values(record: ApprovalRecord) -> dict:
    return {
        "approval_id": record.approval_id,
        "request_id": record.request_id,
        "principal_ref": record.principal_ref,
        "tool_id": record.tool_id,
        "action_digest": record.action_digest,
        "policy_version": record.policy_version,
        "status": record.status.value,
        "reviewer_ref": record.reviewer_ref,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "decided_at": record.decided_at,
        "consumed_at": record.consumed_at,
    }


def _row_to_approval(row: ApprovalRow) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=row.approval_id,
        request_id=row.request_id,
        principal_ref=row.principal_ref,
        tool_id=row.tool_id,
        action_digest=row.action_digest,
        policy_version=row.policy_version,
        status=row.status,
        reviewer_ref=row.reviewer_ref,
        created_at=row.created_at,
        expires_at=row.expires_at,
        decided_at=row.decided_at,
        consumed_at=row.consumed_at,
    )


__all__ = [
    "PolicyRepository",
    "PostgresApprovalStore",
    "PostgresAuditStore",
]
