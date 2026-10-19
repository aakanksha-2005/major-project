"""Shared API dependencies."""

from __future__ import annotations

from starlette.requests import Request

from rasp.auth.dev_identity import Principal, get_principal
from rasp.container import Container


def get_container(request: Request) -> Container:
    return request.app.state.container


__all__ = ["Principal", "get_container", "get_principal"]
