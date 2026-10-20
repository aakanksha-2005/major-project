"""Structured logging tests (Milestone 3).

Two guarantees:
  1. Every access log line carries a request id that is echoed to the client.
  2. Logs never contain request content (prompts, arguments, outputs) — a
     canary is planted in a message and in tool arguments and asserted absent.
"""

from __future__ import annotations

import json
import logging

import pytest

from rasp.main import create_app
from rasp.observability.logging import (
    JsonFormatter,
    configure_logging,
    current_request_id,
    sanitize_request_id,
    set_request_id,
)
from rasp.settings import Settings
from tests.conftest import PERMS_ALL_DEMO, headers_for

CANARY = "CANARY_LOG_SECRET_5b21"


def test_json_formatter_includes_core_fields_and_request_id():
    configure_logging(level="INFO", log_format="json")
    record = logging.LogRecord(
        name="rasp.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    set_request_id("req-abc")
    try:
        payload = json.loads(JsonFormatter().format(record))
    finally:
        from rasp.observability.logging import reset_request_id

        reset_request_id()
    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "rasp.test"
    assert payload["request_id"] == "req-abc"


def test_json_formatter_includes_structured_extras():
    record = logging.LogRecord(
        name="rasp.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="decision",
        args=(),
        exc_info=None,
    )
    record.tool_id = "system_status"
    record.status = 200
    payload = json.loads(JsonFormatter().format(record))
    assert payload["tool_id"] == "system_status"
    assert payload["status"] == 200


def test_unknown_log_format_refuses_startup():
    with pytest.raises(ValueError, match="unknown log format"):
        configure_logging(level="INFO", log_format="xml")


def test_unknown_log_level_refuses_startup():
    with pytest.raises(ValueError, match="unknown log level"):
        configure_logging(level="VERBOSE", log_format="json")


def test_create_app_refuses_unknown_log_format():
    with pytest.raises(ValueError, match="unknown log format"):
        create_app(Settings(persistence="in_memory", log_format="xml"))


def test_sanitize_request_id_accepts_safe_and_replaces_unsafe():
    assert sanitize_request_id("abc-123_DEF.4") == "abc-123_DEF.4"
    assert sanitize_request_id("") != ""
    assert sanitize_request_id("has space") != "has space"
    assert sanitize_request_id("x" * 200) != "x" * 200


async def test_response_echoes_request_id(client):
    response = await client.get("/v1/health", headers={"X-Request-Id": "client-supplied-1"})
    assert response.status_code == 200
    assert response.headers["x-request-id"] == "client-supplied-1"


async def test_generated_request_id_when_absent(client):
    response = await client.get("/v1/health")
    assert response.headers["x-request-id"]


async def test_access_log_carries_request_id(client, caplog):
    with caplog.at_level(logging.INFO, logger="rasp.access"):
        await client.get("/v1/health", headers={"X-Request-Id": "log-correlation-9"})
    access_records = [r for r in caplog.records if r.name == "rasp.access"]
    assert access_records
    latest = access_records[-1]
    assert getattr(latest, "request_id", None) == "log-correlation-9"
    assert getattr(latest, "path", None) == "/v1/health"
    assert getattr(latest, "status", None) == 200


async def test_logs_never_contain_chat_content(client, caplog):
    with caplog.at_level(logging.DEBUG):
        await client.post(
            "/v1/chat",
            json={"message": f"please remember {CANARY}"},
            headers=headers_for("log-canary", PERMS_ALL_DEMO),
        )
    rendered = " ".join(JsonFormatter().format(r) for r in caplog.records)
    assert CANARY not in rendered


async def test_logs_never_contain_tool_arguments(client, caplog):
    with caplog.at_level(logging.DEBUG):
        await client.post(
            "/v1/tools/execute",
            json={"tool_id": "document_search", "arguments": {"query": CANARY}},
            headers=headers_for("log-canary", PERMS_ALL_DEMO),
        )
    rendered = " ".join(JsonFormatter().format(r) for r in caplog.records)
    assert CANARY not in rendered


async def test_access_log_does_not_contain_query_string(client, caplog):
    with caplog.at_level(logging.INFO, logger="rasp.access"):
        await client.get(
            "/v1/audit",
            params={"request_id": CANARY},
            headers=headers_for("log-canary", PERMS_ALL_DEMO),
        )
    rendered = " ".join(JsonFormatter().format(r) for r in caplog.records)
    assert CANARY not in rendered


def test_current_request_id_defaults_to_none():
    from rasp.observability.logging import reset_request_id

    reset_request_id()
    assert current_request_id() is None
