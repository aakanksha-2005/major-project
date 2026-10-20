"""Structured logging helpers (Milestone 3).

Design:
- A `ContextVar` carries the request id across async tasks; `configure_logging`
  installs a formatter that stamps it onto every record.
- `RequestIdMiddleware` establishes the request id (honouring a well-formed
  inbound `X-Request-Id`), echoes it back, and emits exactly one access log
  line per request. Query strings and bodies are NEVER logged.
- Unknown log level/format refuses to start (no silent fallback), matching the
  fail-closed posture used for other security-relevant settings.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from contextvars import ContextVar
from datetime import UTC, datetime

from rasp.schemas.common import new_id

# Standard LogRecord attributes we already render explicitly; anything else in
# a record's __dict__ is treated as caller-supplied structured context.
_STANDARD_ATTRS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
        "request_id",
    }
)

_request_id: ContextVar[str | None] = ContextVar("rasp_request_id", default=None)

_VALID_FORMATS = frozenset({"json", "text"})
_HANDLER_MARKER = "_rasp_configured"


def current_request_id() -> str | None:
    """The request id bound to the current async context, if any."""
    return _request_id.get()


def set_request_id(value: str) -> None:
    _request_id.set(value)


def reset_request_id() -> None:
    _request_id.set(None)


def new_request_id() -> str:
    return new_id()


def sanitize_request_id(candidate: str | None) -> str:
    """Accept a client-supplied request id only if it is safe and bounded."""
    if not candidate:
        return new_id()
    candidate = candidate.strip()
    if not 1 <= len(candidate) <= 64:
        return new_id()
    if not all(ch.isalnum() or ch in "-_.:" for ch in candidate):
        return new_id()
    return candidate


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON with the request id attached."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None) or current_request_id(),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key.startswith("_"):
                continue
            try:
                json.dumps(value)  # only JSON-safe extras are included
            except (TypeError, ValueError):
                value = repr(value)
            payload[key] = value
        if record.exc_info:
            # Exception *type* only — messages may carry untrusted content.
            payload["error_type"] = getattr(record.exc_info[0], "__name__", "Exception")
        return json.dumps(payload, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Human-readable single-line format for local development."""

    default_format = "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"

    def __init__(self) -> None:
        super().__init__(fmt=self.default_format, datefmt="%Y-%m-%dT%H:%M:%S%z")

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        if getattr(record, "request_id", None) is None:
            record.request_id = current_request_id() or "-"
        return super().format(record)


def configure_logging(*, level: str = "INFO", log_format: str = "json") -> None:
    """Install a single RASP handler. Raises on unknown level/format."""
    normalized_level = level.upper()
    if normalized_level not in logging.getLevelNamesMapping():
        raise ValueError(f"unknown log level '{level}'")
    if log_format not in _VALID_FORMATS:
        raise ValueError(
            f"unknown log format '{log_format}'; expected one of {sorted(_VALID_FORMATS)} "
            "(no silent fallback)"
        )

    logger = logging.getLogger("rasp")
    logger.setLevel(normalized_level)
    logger.propagate = True  # keep pytest's caplog working

    # Replace only our own handler; never touch root/uvicorn handlers.
    for handler in list(logger.handlers):
        if getattr(handler, _HANDLER_MARKER, False):
            logger.removeHandler(handler)

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if log_format == "json" else TextFormatter())
    setattr(handler, _HANDLER_MARKER, True)
    logger.addHandler(handler)


_ACCESS_LOGGER = logging.getLogger("rasp.access")


class RequestIdMiddleware:
    """Establishes a per-request id and logs one content-free access line.

    Deliberately a pure ASGI middleware (no BaseHTTPMiddleware overhead): it
    records the final status code without consuming the response body.
    """

    def __init__(self, app, *, header_name: str = "x-request-id") -> None:  # noqa: ANN001
        self._app = app
        self._header = header_name.lower().encode("latin-1")

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        inbound = None
        for key, value in scope.get("headers", []):
            if key.lower() == self._header:
                inbound = value.decode("latin-1")
                break
        request_id = sanitize_request_id(inbound)
        token = _request_id.set(request_id)

        status_holder = {"status": 500}
        started = time.perf_counter()

        async def send_wrapper(message) -> None:  # noqa: ANN001
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self._app(scope, receive, send_wrapper)
        finally:
            duration_ms = (time.perf_counter() - started) * 1000.0
            _ACCESS_LOGGER.info(
                "request",
                extra={
                    "request_id": request_id,
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "status": status_holder["status"],
                    "duration_ms": round(duration_ms, 3),
                },
            )
            _request_id.reset(token)


def iter_known_loggers() -> Iterable[str]:
    """Names of RASP loggers (useful for tests and diagnostics)."""
    return ("rasp", "rasp.access", "rasp.api", "rasp.executor", "rasp.policy")


__all__ = [
    "JsonFormatter",
    "RequestIdMiddleware",
    "TextFormatter",
    "configure_logging",
    "current_request_id",
    "iter_known_loggers",
    "new_request_id",
    "reset_request_id",
    "sanitize_request_id",
    "set_request_id",
]
