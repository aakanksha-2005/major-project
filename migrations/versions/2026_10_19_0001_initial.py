"""initial schema: policies, approval_requests, audit_events

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-19

Mirrors src/rasp/persistence/models.py — this migration is the single
source of truth for schema initialization (alembic upgrade head).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("version"),
    )

    op.create_table(
        "approval_requests",
        sa.Column("approval_id", sa.String(length=32), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("principal_ref", sa.String(length=128), nullable=False),
        sa.Column("tool_id", sa.String(length=128), nullable=False),
        sa.Column("action_digest", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reviewer_ref", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','approved','rejected','expired','invalidated')",
            name="ck_approval_status",
        ),
        sa.ForeignKeyConstraint(["policy_version"], ["policies.version"]),
        sa.PrimaryKeyConstraint("approval_id"),
    )
    op.create_index("ix_approval_request_id", "approval_requests", ["request_id"])
    op.create_index(
        "ix_approval_status_expires",
        "approval_requests",
        ["status", "expires_at"],
    )
    # At most ONE pending approval per (action, principal): duplicate
    # submissions are idempotent instead of creating parallel approvals.
    op.create_index(
        "uq_approval_pending",
        "approval_requests",
        ["action_digest", "principal_ref", "tool_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )

    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(length=32), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("principal_ref", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("tool_id", sa.String(length=128), nullable=True),
        sa.Column("policy_version", sa.String(length=32), nullable=True),
        sa.Column("decision", sa.String(length=32), nullable=True),
        sa.Column("reason_code", sa.String(length=32), nullable=True),
        sa.Column("approval_id", sa.String(length=32), nullable=True),
        sa.Column("execution_status", sa.String(length=24), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.Column("action_digest", sa.String(length=64), nullable=True),
        sa.Column("security_flags", sa.JSON(), nullable=False),
        # No content columns exist here by design: prompts, arguments,
        # outputs, credentials, and records are never persisted.
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index("ix_audit_request_id", "audit_events", ["request_id"])
    op.create_index(
        "ix_audit_principal_timestamp",
        "audit_events",
        ["principal_ref", "timestamp"],
    )
    op.create_index("ix_audit_timestamp", "audit_events", ["timestamp"])
    op.create_index("ix_audit_event_type", "audit_events", ["event_type"])


def downgrade() -> None:
    op.drop_index("ix_audit_event_type", table_name="audit_events")
    op.drop_index("ix_audit_timestamp", table_name="audit_events")
    op.drop_index("ix_audit_principal_timestamp", table_name="audit_events")
    op.drop_index("ix_audit_request_id", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("uq_approval_pending", table_name="approval_requests")
    op.drop_index("ix_approval_status_expires", table_name="approval_requests")
    op.drop_index("ix_approval_request_id", table_name="approval_requests")
    op.drop_table("approval_requests")
    op.drop_table("policies")
