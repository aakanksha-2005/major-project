"""Shared test fixtures.

Milestone 1+2 documented test strategy (see docs/DEVELOPMENT.md):

- The default suite runs WITHOUT PostgreSQL, model credentials, or
  network access: fixtures set `persistence="in_memory"` explicitly —
  an opt-out, never a silent database substitution.
- PostgreSQL-backed tests live under `tests/postgres/`, are marked
  `postgres`, use an isolated `*_test` database, and SKIP with an
  explicit reason when the server is unreachable.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from rasp.main import create_app
from rasp.settings import Settings
from rasp.tools import builtin

# Convenience permission bundles for the development identity mechanism.
PERMS_ALL_DEMO = (
    "system:status,documents:read,applications:preview,announcements:publish,"
    "audit:read,approvals:read"
)
PERMS_AUDIT_ADMIN = PERMS_ALL_DEMO + ",audit:admin"
# A reviewer can see all approval records and decide on them.
PERMS_APPROVER = PERMS_ALL_DEMO + ",approvals:review"


def headers_for(principal: str, perms: str = "") -> dict[str, str]:
    headers = {"X-Dev-Principal": principal}
    if perms:
        headers["X-Dev-Permissions"] = perms
    return headers


@pytest.fixture
def settings() -> Settings:
    return Settings(policy_path="config/policies.example.yaml", persistence="in_memory")


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
