"""PostgreSQL persistence layer (Milestone 2).

Provides the async engine/session plumbing, SQLAlchemy models, and store
implementations that back the AuditService/ApprovalStore facades. The
application defaults to this store; `RASP_PERSISTENCE=in_memory` is the
explicit opt-out used by the documented M1 test strategy.
"""

from __future__ import annotations

from rasp.persistence.db import Database
from rasp.persistence.repositories import (
    PolicyRepository,
    PostgresApprovalStore,
    PostgresAuditStore,
)

__all__ = ["Database", "PolicyRepository", "PostgresApprovalStore", "PostgresAuditStore"]
