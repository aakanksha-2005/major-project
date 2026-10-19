"""Tool execution and discovery endpoints (spec §8, §12).

POST /v1/tools/execute re-validates everything at execution time through
the policy engine and controlled executor. The request schema forbids
extra fields, so no caller-supplied "authorized"/"approved" claim can even
be expressed, let alone trusted.

Status codes:
  200 executed (constraints enforced server-side)
  202 pending approval (nothing executed)
  403 denied (unknown / disabled / permission / invalid args / policy error)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from rasp.api.deps import Principal, get_container, get_principal
from rasp.container import Container
from rasp.executor.executor import decision_summary
from rasp.schemas.common import ErrorDetail, new_id
from rasp.schemas.execution import ExecutionOutcome, ToolExecutionRequest
from rasp.schemas.model import ToolProposal

router = APIRouter(tags=["tools"])


@router.get("/v1/tools")
async def list_tools(
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> dict:
    # Metadata only: handler references are never exposed.
    return {"tools": [t.public_metadata() for t in container.registry.list()]}


@router.post("/v1/tools/execute", response_model=None)
async def execute_tool(
    body: ToolExecutionRequest,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> ExecutionOutcome | JSONResponse:
    request_id = new_id()
    outcome = await container.executor.execute(
        ToolProposal(tool_id=body.tool_id, arguments=body.arguments),
        principal=principal,
        request_id=request_id,
    )
    decision_info = decision_summary(outcome.decision).model_dump(mode="json")

    if outcome.decision.outcome.value == "require_approval":
        return JSONResponse(
            status_code=202,
            content={
                "error": None,
                "decision": decision_info,
                "approval_id": outcome.approval_id,
                "request_id": request_id,
                "message": outcome.decision.message,
            },
        )

    if outcome.decision.outcome.value == "deny":
        return JSONResponse(
            status_code=403,
            content={
                "error": ErrorDetail(
                    code=outcome.decision.reason_code.value,
                    message=outcome.decision.message,
                    request_id=request_id,
                ).model_dump(),
                "decision": decision_info,
                "request_id": request_id,
            },
        )

    # ALLOW / ALLOW_WITH_CONSTRAINTS
    return outcome
