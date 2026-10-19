"""SQLAlchemy 2.0 models for the Milestone 2 schema (spec §9).

Privacy mirror: `audit_events` has exactly the columns of the content-free
AuditEvent schema — there is no column for prompts, arguments, outputs,
credentials, or records. `policy_version` on audit rows is a plain VARCHAR
(not a foreign key) so forensic writes are never blocked by metadata
ordering; `approval_requests.policy_version` IS a foreign key because the
approval flow always persists policy metadata first.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Server default: `now()` — set by Alembic migrations, not here.
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class PolicyRow(Base):
    """Persisted policy metadata: which policy version was in force."""

    __tablename__ = "policies"

    version: Mapped[str] = mapped_column(String(32), primary_key=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ApprovalRow(Base):
    """Pending/approved/rejected approval requests, digest-bound to one action."""

    __tablename__ = "approval_requests"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','rejected','expired','invalidated')",
            name="ck_approval_status",
        ),
        # At most ONE pending record per (action, principal): duplicate
        # submissions are idempotent instead of creating parallel approvals.
        Index(
            "uq_approval_pending",
            "action_digest",
            "principal_ref",
            "tool_id",
            unique=True,
            postgresql_where="status = 'pending'",
        ),
        Index("ix_approval_status_expires", "status", "expires_at"),
        Index("ix_approval_request_id", "request_id"),
    )

    approval_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    principal_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(
        String(32), ForeignKey("policies.version"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    reviewer_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEventRow(Base):
    """Sanitized audit event — structurally identical to AuditEvent."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_request_id", "request_id"),
        Index("ix_audit_principal_timestamp", "principal_ref", "timestamp"),
        Index("ix_audit_timestamp", "timestamp"),
        Index("ix_audit_event_type", "event_type"),
    )

    event_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    principal_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)

    tool_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    execution_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="not_applicable"
    )
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    security_flags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Deliberately NO content columns exist on this table: prompts,
    # arguments, outputs, credentials, and records are never persisted.
