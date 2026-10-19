"""Shared test fixtures.

All tests run without external model credentials, PostgreSQL, or network
access (Milestone 1 strategy): the mock adapter and in-memory audit/approval
stores are the documented targets. PostgreSQL-backed fixtures arrive in
Milestone 2 without changing these call sites.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from rasp.main import create_app
from rasp.settings import Settings
from rasp.tools import builtin

# Convenience permission bundles for the development identity mechanism.
PERMS_ALL_DEMO = (
    "system:status,documents:read,applications:preview,announcements:publish,audit:read"
)
PERMS_AUDIT_ADMIN = PERMS_ALL_DEMO + ",audit:admin"


def headers_for(principal: str, perms: str = "") -> dict[str, str]:
    headers = {"X-Dev-Principal": principal}
    if perms:
        headers["X-Dev-Permissions"] = perms
    return headers


@pytest.fixture
def settings() -> Settings:
    return Settings(policy_path="config/policies.example.yaml")


@pytest.fixture
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture
def container(app):
    return app.state.container


@pytest.fixture
def demo_headers() -> dict[str, str]:
    return headers_for("test-principal", PERMS_ALL_DEMO)


@pytest.fixture(autouse=True)
def _reset_execution_log():
    """Synthetic mutation log starts empty so 'never executed' tests are airtight."""
    builtin.EXECUTION_LOG.clear()
    yield
    builtin.EXECUTION_LOG.clear()
