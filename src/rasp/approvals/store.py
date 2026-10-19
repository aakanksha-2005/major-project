"""In-memory approval store (Milestone 1).

Milestone 2 moves approval persistence to PostgreSQL. Lifecycle decision
operations (approve/reject endpoints, reviewer authz) arrive in Milestone 3;
binding and expiry logic is implemented and unit-tested from Milestone 1.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

from rasp.schemas.approval import ApprovalRecord, ApprovalStatus


class ApprovalStore:
    def __init__(self, ttl_seconds: int = 900) -> None:
        self._ttl_seconds = ttl_seconds
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    def create_pending(
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
        with self._lock:
            self._records[record.approval_id] = record
        return record

    def get(self, approval_id: str) -> ApprovalRecord | None:
        """Fetch a record, lazily expiring stale pendings."""
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return None
            if record.status == ApprovalStatus.PENDING and record.expires_at <= datetime.now(UTC):
                expired = record.model_copy(update={"status": ApprovalStatus.EXPIRED})
                self._records[approval_id] = expired
                return expired
            return record

    def all(self) -> list[ApprovalRecord]:
        with self._lock:
            return list(self._records.values())
