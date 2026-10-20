"""Structured observability (Milestone 3).

Two guarantees:

1. **JSON (or text) logs with a request id.** Every log record emitted while
   handling a request carries the same `request_id` as the audit trail, so an
   operator can correlate logs without ever logging request content.
2. **No content leaks into logs.** The formatter only serializes standard log
   record attributes; callers log identifiers, decisions, and reason codes —
   never prompts, tool arguments, outputs, or credentials.
"""

from __future__ import annotations

from rasp.observability.logging import (
    JsonFormatter,
    RequestIdMiddleware,
    configure_logging,
    current_request_id,
)
from rasp.observability.redaction import LOG_REDACTION_NOTE

__all__ = [
    "LOG_REDACTION_NOTE",
    "JsonFormatter",
    "RequestIdMiddleware",
    "configure_logging",
    "current_request_id",
]
