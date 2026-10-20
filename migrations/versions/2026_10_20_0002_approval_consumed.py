"""approval consumption: single-use approvals (Milestone 3)

Revision ID: 0002_approval_consumed
Revises: 0001_initial
Create Date: 2026-10-20

Adds the `consumed` terminal status, a `consumed_at` timestamp, and an
action-lookup index. Mirrors src/rasp/persistence/models.py — this migration
is the single source of truth for schema changes (alembic upgrade head).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_approval_consumed"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NEW_STATUSES = "'pending','approved','rejected','expired','invalidated','consumed'"
_OLD_STATUSES = "'pending','approved','rejected','expired','invalidated'"


def upgrade() -> None:
    op.add_column(
        "approval_requests",
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Extend the status CHECK constraint with the consumed terminal state.
    op.drop_constraint("ck_approval_status", "approval_requests", type_="check")
    op.create_check_constraint(
        "ck_approval_status",
        "approval_requests",
        f"status IN ({_NEW_STATUSES})",
    )
    # Effective-record lookup for an exact action (any status).
    op.create_index(
        "ix_approval_action",
        "approval_requests",
        ["action_digest", "principal_ref", "tool_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_approval_action", table_name="approval_requests")
    op.drop_constraint("ck_approval_status", "approval_requests", type_="check")
    op.create_check_constraint(
        "ck_approval_status",
        "approval_requests",
        f"status IN ({_OLD_STATUSES})",
    )
    op.drop_column("approval_requests", "consumed_at")
