"""POST /v1/chat — mediated chat lifecycle (spec §4, §8)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from rasp.api.deps import Principal, get_container, get_principal
from rasp.container import Container
from rasp.schemas.chat import ChatRequest, ChatResponse

router = APIRouter(tags=["chat"])


@router.post("/v1/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> ChatResponse:
    # The message text never grants permissions, roles, or approvals:
    # identity comes solely from trusted headers via get_principal.
    return await container.orchestrator.handle_chat(body, principal)
