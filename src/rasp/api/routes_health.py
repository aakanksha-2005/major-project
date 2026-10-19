"""GET /v1/health — minimal operational health (spec §8).

Reveals no credentials, connection strings, configuration, or infrastructure
detail.
"""

from __future__ import annotations

from fastapi import APIRouter

from rasp import PROTOTYPE_NOTICE, __version__

router = APIRouter(tags=["health"])


@router.get("/v1/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "rasp",
        "version": __version__,
        "notice": PROTOTYPE_NOTICE,
    }
