"""Alembic environment: URL comes from RASP_DATABASE_URL (never committed).

Runs through the same async engine as the application (asyncpg), so a single
driver serves both migrations and runtime.
"""

from __future__ import annotations

import asyncio
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

# Repository-root/src importability when invoked from any working directory.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from rasp.persistence.models import Base  # noqa: E402
from rasp.settings import Settings  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Fail closed: migration runs use the same validated settings object as the
# application (unknown/invalid configuration raises here too).
_settings = Settings()
DATABASE_URL = _settings.database_url

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a database connection (`alembic upgrade --sql`)."""
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:  # noqa: ANN001
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    section = config.get_section(config.config_ini_section) or {}
    # Bypass ini interpolation entirely: database URLs may contain '%'.
    section["sqlalchemy.url"] = DATABASE_URL
    connectable = async_engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
