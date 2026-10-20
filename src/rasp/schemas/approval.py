"""Approval contracts (spec §3.H, §10).

An approval record is bound to an immutable representation of the exact
action. A model-generated claim such as "the user approved this" is never
valid approval evidence.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from rasp.schemas.common import new_id


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"
    # Milestone 3: single-use consumption. An approved record is consumed
    # when the authorized action actually executes; replaying the identical
    # action afterwards requires a fresh human approval (never re-executes).
    CONSUMED = "consumed"


def compute_action_digest(
    tool_id: str,
    arguments: dict,
    principal_id: str,
    policy_version: str,
) -> str:
    """Integrity-protected canonical hash binding an approval to one action.

    Any change to tool, arguments, principal, or policy version produces a
    different digest, which invalidates the approval.
    """
    canonical = json.dumps(
        {
            "tool_id": tool_id,
            "arguments": arguments,
            "principal_id": principal_id,
            "policy_version": policy_version,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(default_factory=new_id)
    request_id: str
    principal_ref: str
    tool_id: str
    action_digest: str = Field(min_length=64, max_length=64)
    policy_version: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    decided_at: datetime | None = None
    reviewer_ref: str | None = None
    # Milestone 3: set exactly when the approval was claimed for execution
    # (status approved -> consumed). None until then.
    consumed_at: datetime | None = None

    def is_valid_for(
        self,
        *,
        action_digest: str,
        principal_ref: str,
        now: datetime | None = None,
    ) -> bool:
        """True only if this approval currently authorizes exactly this action.

        Consumed, rejected, expired, invalidated, and pending records are never
        valid: one approval authorizes at most one execution.
        """
        now = now or datetime.now(UTC)
        if self.status != ApprovalStatus.APPROVED:
            return False
        if self.expires_at <= now:
            return False
        return self.action_digest == action_digest and self.principal_ref == principal_ref
