"""Fixtures for PostgreSQL-backed tests (Milestone 2).

Documented test strategy (docs/DEVELOPMENT.md §8):

- These tests use an ISOLATED database (`rasp_test` by default) and refuse
  to run destructive fixtures against any database whose name lacks
  "test" — a developer's real database can never be altered.
- If PostgreSQL is unreachable the entire package SKIPS with an explicit
  reason ("skipped, not passed") — it is never silently replaced with
  SQLite or another engine.
- Schema comes only from Alembic migrations (`alembic upgrade head`),
  exercised here through the same path developers use.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from rasp.settings import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_DB_URL = os.environ.get(
    "RASP_TEST_DATABASE_URL",
    "postgresql+asyncpg://rasp:rasp@127.0.0.1:5433/rasp_test",
)


@pytest.fixture(scope="session")
def pg_url() -> str:
    """Reachable, correctly-named test database URL — or an explicit skip."""
    import asyncpg
    from sqlalchemy.engine import make_url

    url = make_url(TEST_DB_URL)
    dbname = url.database or ""

    # Destructive-fixture guard: NEVER touch a database that isn't a test one.
    if "test" not in dbname.lower():
        pytest.fail(
            f"refusing to run destructive test fixtures against '{dbname}': "
            "the database name must contain 'test'. "
            "Set RASP_TEST_DATABASE_URL to an isolated *_test database."
        )

    async def ensure_database() -> None:
        conn = await asyncpg.connect(
            host=url.host or "127.0.0.1",
            port=url.port or 5432,
            user=url.username,
            password=url.password,
            database="postgres",
            timeout=5,
        )
        try:
            exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", dbname)
            if not exists:
                # First-boot init script may not have run (pre-existing volume).
                await conn.execute(f'CREATE DATABASE "{dbname}"')
        finally:
            await conn.close()

    try:
        asyncio.run(ensure_database())
    except Exception as exc:
        pytest.skip(
            "PostgreSQL is unreachable — postgres-marked tests SKIPPED, not "
            "passed (start it with `docker compose up -d`): "
            f"{type(exc).__name__}: {exc}"
        )

    return TEST_DB_URL


@pytest.fixture(scope="session", autouse=True)
def pg_schema(pg_url: str) -> None:
    """Initialize the schema exactly as documented: `alembic upgrade head`."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "migrations"))

    previous = os.environ.get("RASP_DATABASE_URL")
    os.environ["RASP_DATABASE_URL"] = pg_url
    try:
        command.upgrade(cfg, "head")
    finally:
        if previous is None:
            os.environ.pop("RASP_DATABASE_URL", None)
        else:
            os.environ["RASP_DATABASE_URL"] = previous


@pytest.fixture
async def pg_engine(pg_url: str):
    """Function-scoped async engine (created, used, and disposed in one loop)."""
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(pg_url)
    yield engine
    await engine.dispose()


@pytest.fixture(autouse=True)
async def clean_tables(pg_engine):
    """Every test starts with empty tables (deterministic isolation)."""
    from sqlalchemy import text

    async with pg_engine.begin() as conn:
        await conn.execute(text("TRUNCATE TABLE audit_events, approval_requests, policies CASCADE"))
    yield


@pytest.fixture
def pg_settings(pg_url: str) -> Settings:
    return Settings(
        policy_path="config/policies.example.yaml",
        persistence="postgres",
        database_url=pg_url,
    )


@pytest.fixture
def pg_app(pg_settings: Settings):
    from rasp.main import create_app

    return create_app(pg_settings)


@pytest.fixture
async def pg_client(pg_app):
    transport = ASGITransport(app=pg_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    await pg_app.state.container.close()
