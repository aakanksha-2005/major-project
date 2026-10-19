"""Consistent error handling and request-size enforcement (spec §8, §12).

- One ApiError envelope for every error response.
- No stack traces, raw policy documents, or internal configuration leak.
- Request bodies larger than settings.max_request_bytes are rejected (413).
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from rasp.auth.dev_identity import AuthenticationRequired
from rasp.schemas.common import ApiError, ErrorDetail

logger = logging.getLogger("rasp.api")

_STATUS_CODES = {
    400: "bad_request",
    401: "authentication_required",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
    429: "rate_limited",
}


def error_response(
    status_code: int,
    code: str,
    message: str,
    request_id: str | None = None,
) -> JSONResponse:
    body = ApiError(error=ErrorDetail(code=code, message=message, request_id=request_id))
    return JSONResponse(status_code=status_code, content=body.model_dump())


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Count only; raw invalid values are not echoed back.
        return error_response(
            422,
            "validation_error",
            f"Request failed validation ({len(exc.errors())} issue(s)).",
        )

    @app.exception_handler(AuthenticationRequired)
    async def _auth_required(request: Request, exc: AuthenticationRequired) -> JSONResponse:
        return error_response(401, "authentication_required", "Authentication is required.")

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "http_error")
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return error_response(exc.status_code, code, detail)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Log server-side with traceback; return a generic envelope only.
        logger.exception("unhandled error: %s", type(exc).__name__)
        return error_response(500, "internal_error", "An internal error occurred.")


class BodySizeLimitMiddleware:
    """Reject request bodies exceeding the configured limit with 413.

    Reads the body up to the limit before dispatching, so oversized requests
    are rejected deterministically before application code runs.
    """

    def __init__(self, app, max_bytes: int) -> None:  # noqa: ANN001 - ASGI app
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        # Fast path: declared Content-Length over the limit.
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        declared = headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self._max_bytes:
            await self._send_413(send)
            return

        body = b""
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body += message.get("body", b"")
            if len(body) > self._max_bytes:
                await self._send_413(send)
                return
            if not message.get("more_body"):
                break

        delivered = False

        async def replay_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self._app(scope, replay_receive, send)

    async def _send_413(self, send) -> None:  # noqa: ANN001
        body = (
            ApiError(
                error=ErrorDetail(
                    code="payload_too_large", message="Request body exceeds the size limit."
                )
            )
            .model_dump_json()
            .encode("utf-8")
        )
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("latin-1")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
