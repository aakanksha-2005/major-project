"""Approval decision endpoints (Milestone 3).

Routes:
  GET  /v1/approvals                 list (scoped unless reviewer)
  GET  /v1/approvals/{approval_id}   fetch one (own record or reviewer)
  POST /v1/approvals/{id}/approve    grant (reviewer; never self-approval)
  POST /v1/approvals/{id}/reject     deny   (reviewer; requester may withdraw)
  POST /v1/approvals/{id}/revoke     withdraw a granted approval (reviewer)

Authorization (default deny):
  approvals:read    required to list/fetch any approval record.
  approvals:review  required to decide; also widens visibility to all records.
  Without approvals:review a caller sees ONLY their own requests (scoped by
  the same salted pseudonym the audit trail uses).

Separation of duties: a requester may never approve their own request
(403 self_review_forbidden). Fail-closed withdrawals (reject/revoke) are
allowed by anyone with review authority, including the requester.

The request body is intentionally empty and forbids extra fields: a
caller-supplied `approved`/`role`/`note` claim cannot even be expressed (422).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from rasp.api.deps import Principal, get_container, get_principal
from rasp.api.errors import error_response
from rasp.approvals.store import (
    ApprovalError,
    ApprovalNotFoundError,
    InvalidApprovalTransition,
    SelfReviewForbidden,
)
from rasp.container import Container
from rasp.schemas.audit import AuditEvent, AuditEventType
from rasp.schemas.common import new_id
from rasp.schemas.policy import DecisionOutcome, ReasonCode

logger = logging.getLogger("rasp.api.approvals")

router = APIRouter(tags=["approvals"])

_NOT_FOUND = "Approval not found."
_FORBIDDEN_REVIEW = "The 'approvals:review' permission is required."


class EmptyDecisionBody(BaseModel):
    """No decision data belongs in the body — reviewer identity comes from
    authenticated headers, never from caller-supplied claims."""

    model_config = ConfigDict(extra="forbid")


# Reviewer action -> (target outcome, audit reason code)
_ACTION_AUDIT = {
    "approve": (DecisionOutcome.ALLOW, ReasonCode.APPROVAL_GRANTED),
    "reject": (DecisionOutcome.DENY, ReasonCode.APPROVAL_REJECTED),
    "revoke": (DecisionOutcome.DENY, ReasonCode.APPROVAL_REVOKED),
}


def _record_json(record) -> dict:  # noqa: ANN001
    return record.model_dump(mode="json")


@router.get("/v1/approvals", response_model=None)
async def list_approvals(
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
    status: str | None = Query(default=None, max_length=16),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> object:
    if not principal.has_permission("approvals:read"):
        return error_response(403, "forbidden", "The 'approvals:read' permission is required.")

    try:
        records = await container.approvals.all()
    except Exception:
        logger.exception("approval listing failed")
        return error_response(
            503, "persistence_unavailable", "Approval storage is temporarily unavailable."
        )

    if not principal.has_permission("approvals:review"):
        own_ref = container.audit.principal_ref(principal.principal_id)
        records = [r for r in records if r.principal_ref == own_ref]
    if status:
        records = [r for r in records if r.status.value == status]
    # Newest first (the backends also order by created_at desc).
    records = sorted(records, key=lambda r: r.created_at, reverse=True)
    page = records[offset : offset + limit]
    return {
        "approvals": [_record_json(r) for r in page],
        "count": len(page),
        "limit": limit,
        "offset": offset,
    }


@router.get("/v1/approvals/{approval_id}", response_model=None)
async def get_approval(
    approval_id: str,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> object:
    if not principal.has_permission("approvals:read"):
        return error_response(403, "forbidden", "The 'approvals:read' permission is required.")

    try:
        record = await container.approvals.get(approval_id)
    except Exception:
        logger.exception("approval fetch failed")
        return error_response(
            503, "persistence_unavailable", "Approval storage is temporarily unavailable."
        )
    if record is None:
        return error_response(404, "not_found", _NOT_FOUND)

    visible = principal.has_permission("approvals:review") or record.principal_ref == (
        container.audit.principal_ref(principal.principal_id)
    )
    if not visible:
        # 404 rather than 403: never confirm the existence of another
        # principal's approval record.
        return error_response(404, "not_found", _NOT_FOUND)
    return _record_json(record)


async def _decide(
    approval_id: str,
    action: str,
    container: Container,
    principal: Principal,
    body: EmptyDecisionBody | None,  # noqa: ARG001 - part of the contract
) -> object:
    if not principal.has_permission("approvals:review"):
        return error_response(403, "forbidden", _FORBIDDEN_REVIEW)

    reviewer_ref = container.audit.principal_ref(principal.principal_id)
    try:
        record = await container.approvals.decide(approval_id, action, reviewer_ref=reviewer_ref)
    except ApprovalNotFoundError:
        return error_response(404, "not_found", _NOT_FOUND)
    except SelfReviewForbidden:
        return error_response(
            403,
            "self_review_forbidden",
            "A requester cannot approve their own action request.",
        )
    except InvalidApprovalTransition:
        return error_response(
            409,
            "invalid_approval_transition",
            "The approval is not in a state that allows this decision.",
        )
    except ApprovalError:
        logger.exception("approval decision failed")
        return error_response(
            503, "persistence_unavailable", "Approval storage is temporarily unavailable."
        )
    except Exception:
        logger.exception("approval decision failed")
        return error_response(
            503, "persistence_unavailable", "Approval storage is temporarily unavailable."
        )

    request_id = new_id()
    outcome, reason = _ACTION_AUDIT[action]
    try:
        await container.audit.record(
            AuditEvent(
                request_id=request_id,
                correlation_id=request_id,
                timestamp=datetime.now(UTC),
                principal_ref=reviewer_ref,
                event_type=AuditEventType.APPROVAL_DECIDED,
                tool_id=record.tool_id,
                policy_version=record.policy_version,
                decision=outcome,
                reason_code=reason,
                approval_id=record.approval_id,
                execution_status=record.status.value,
                action_digest=record.action_digest,
            )
        )
    except Exception:
        # The decision is already durable in the approval store; a failed
        # audit write is post-hoc and must not fabricate a failure. It is
        # logged (content-free) for operators.
        logger.exception("approval decision audit write failed")

    return JSONResponse(
        status_code=200,
        content={
            "approval": _record_json(record),
            "action": action,
            "request_id": request_id,
        },
    )


@router.post("/v1/approvals/{approval_id}/approve", response_model=None)
async def approve(
    approval_id: str,
    body: EmptyDecisionBody | None = None,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> object:
    return await _decide(approval_id, "approve", container, principal, body)


@router.post("/v1/approvals/{approval_id}/reject", response_model=None)
async def reject(
    approval_id: str,
    body: EmptyDecisionBody | None = None,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> object:
    return await _decide(approval_id, "reject", container, principal, body)


@router.post("/v1/approvals/{approval_id}/revoke", response_model=None)
async def revoke(
    approval_id: str,
    body: EmptyDecisionBody | None = None,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> object:
    return await _decide(approval_id, "revoke", container, principal, body)
