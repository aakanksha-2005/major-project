"""GET /v1/audit — restricted, paginated access to sanitized events.

Authorization:
  audit:read  required to call the endpoint at all
  audit:admin required to see events beyond one's own principal scope

Events contain no prompts, arguments, or outputs (structural guarantee of
the AuditEvent schema).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query

from rasp.api.deps import Principal, get_container, get_principal
from rasp.api.errors import error_response
from rasp.container import Container

logger = logging.getLogger("rasp.api.audit")

router = APIRouter(tags=["audit"])


@router.get("/v1/audit", response_model=None)
async def read_audit(
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    request_id: str | None = Query(default=None, max_length=64),
) -> object:
    if not principal.has_permission("audit:read"):
        return error_response(403, "forbidden", "The 'audit:read' permission is required.")

    principal_refs = None
    if not principal.has_permission("audit:admin"):
        # Scope to the caller's own events; others' records stay hidden.
        principal_refs = [container.audit.principal_ref(principal.principal_id)]

    try:
        events = await container.audit.query(
            request_id=request_id,
            principal_refs=principal_refs,
            limit=limit,
            offset=offset,
        )
    except Exception:
        # Storage outage: honest 503 instead of an unhandled crash.
        logger.exception("audit query failed")
        return error_response(
            503,
            "persistence_unavailable",
            "Audit storage is temporarily unavailable.",
        )
    return {
        "events": [event.model_dump(mode="json") for event in events],
        "count": len(events),
        "limit": limit,
        "offset": offset,
    }
