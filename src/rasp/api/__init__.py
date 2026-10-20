"""API package."""

from fastapi import FastAPI

from rasp.api import (
    routes_approvals,
    routes_audit,
    routes_chat,
    routes_health,
    routes_tools,
)
from rasp.api.errors import BodySizeLimitMiddleware, register_exception_handlers


def register_routes(app: FastAPI) -> None:
    app.include_router(routes_health.router)
    app.include_router(routes_chat.router)
    app.include_router(routes_tools.router)
    app.include_router(routes_audit.router)
    app.include_router(routes_approvals.router)


__all__ = ["BodySizeLimitMiddleware", "register_exception_handlers", "register_routes"]
