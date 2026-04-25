"""Async SQLAlchemy engine and session factory.

Both services build their engine from the same DATABASE_URL. The URL
must use the `sqlite+aiosqlite://` driver so we get native asyncio
semantics on a single-file DB.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is None:
        url = os.environ.get("DATABASE_URL", "").strip()
        if not url:
            raise RuntimeError("DATABASE_URL is not set.")
        _engine = create_async_engine(
            url,
            # SQLite behaves much better under concurrent readers when WAL
            # is enabled. The PRAGMA is applied on the first connection.
            connect_args={"timeout": 30},
            pool_pre_ping=True,
            future=True,
        )
        _sessionmaker = async_sessionmaker(
            _engine, expire_on_commit=False, autoflush=False
        )
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        get_engine()
    assert _sessionmaker is not None
    return _sessionmaker


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Open a session, commit on clean exit, rollback on exception."""
    sm = get_sessionmaker()
    async with sm() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def enable_sqlite_wal() -> None:
    """Apply WAL mode and synchronous=NORMAL for better concurrency.

    Called once at startup. Safe to call multiple times.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        await conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
        await conn.exec_driver_sql("PRAGMA foreign_keys=ON")


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
