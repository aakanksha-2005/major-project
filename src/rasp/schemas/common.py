"""Shared schema primitives: identifiers, trust categories, error contracts."""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

# Safe for clients: no internal detail, always disclosed in responses.
PROTOTYPE_NOTICE_SAFE = "Experimental prototype — not production-certified."


class TrustCategory(StrEnum):
    """Trust boundary label carried with content (spec §3.F).

    Security decisions must never depend on the textual content of
    untrusted categories; tool authorization is independent of content.
    """

    SYSTEM_POLICY = "system_policy"  # trusted, application-authored
    USER = "user"  # untrusted
    RETRIEVED_DOCUMENT = "retrieved_document"  # untrusted
    TOOL_OUTPUT = "tool_output"  # untrusted
    MODEL = "model"  # untrusted proposal


class ErrorDetail(BaseModel):
    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=512)
    request_id: str | None = None


class ApiError(BaseModel):
    """Consistent error envelope for every non-2xx response.

    Messages are safe for clients: they never include stack traces,
    raw policy documents, or internal configuration.
    """

    error: ErrorDetail


def new_id() -> str:
    return uuid4().hex
