"""Async PostgreSQL engine/session plumbing.

Design notes:
- The engine is created lazily (SQLAlchemy does not connect until first
  use), so importing the application or running the in-memory test suite
  never requires a database.
- Every connection gets a server-side statement timeout: a hung database
  surfaces as an error the executor can fail closed on, instead of
  hanging an authorization decision.
- `pool_pre_ping` recycles dead connections after a database restart.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from rasp.settings import Settings


class Database:
    """Async engine + session factory for one configured database URL."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._engine: AsyncEngine = create_async_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_pool_size,
            pool_timeout=settings.database_pool_timeout,
            # Statement timeout applied by the server at connect time
            # (asyncpg `server_settings`): a hung database surfaces as an
            # error the executor can fail closed on, instead of hanging an
            # authorization decision.
            connect_args={
                "server_settings": {
                    "statement_timeout": str(int(settings.database_statement_timeout_ms)),
                    "application_name": "rasp",
                }
            },
        )

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def url(self) -> str:
        # Redacted form for logs: credentials never appear in output.
        return self._settings.database_url.rsplit("@", 1)[-1]

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """One transaction per block: commit on success, rollback on error."""
        factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._engine, expire_on_commit=False
        )
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def ping(self) -> bool:
        """True when the database answers a trivial query."""
        try:
            async with self._engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    async def dispose(self) -> None:
        await self._engine.dispose()


class FailingDatabase(Database):
    """Test double: every operation raises `fail_with`.

    Lives in production code (not tests) so adversarial/unit suites can
    exercise the fail-closed path deterministically without a server.
    """

    def __init__(self, settings: Settings, fail_with: Exception | None = None) -> None:
        # Do NOT call super().__init__ — no engine is created; this object
        # must work with the database completely unavailable.
        self._settings = settings
        self._fail_with = fail_with or ConnectionError("database unavailable (test double)")
        self._engine = None  # type: ignore[assignment]

    @asynccontextmanager
    async def session(self):  # noqa: ANN201
        raise self._fail_with
        yield  # pragma: no cover — makes this an async generator

    async def ping(self) -> bool:
        return False

    async def dispose(self) -> None:
        return None
