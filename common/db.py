"""Async SQLAlchemy engine and session factory.

Both services build their engine from the same DATABASE_URL. The URL
must use the `sqlite+aiosqlite://` driver so we get native asyncio
semantics on a single-file DB.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _apply_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
    """Apply per-connection PRAGMAs to every new SQLite connection.

    ``journal_mode=WAL`` is a persistent, DB-level property, but
    ``synchronous`` and ``foreign_keys`` are per-connection and reset to
    the SQLite defaults on every new one. Since NullPool opens a fresh
    connection per session, applying them once at startup is not enough:
    ``synchronous`` would silently fall back to FULL, quietly undoing the
    WAL/NORMAL trade-off this engine is configured for.

    ``foreign_keys=ON`` has no effect on the current schema, which
    declares no foreign keys — it is set so enforcement is correct by
    construction if any are ever added.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def get_engine() -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is None:
        url = os.environ.get("DATABASE_URL", "").strip()
        if not url:
            raise RuntimeError("DATABASE_URL is not set.")
        _engine = create_async_engine(
            url,
            # NullPool: every session gets a fresh aiosqlite connection that
            # is fully closed on release. A connection left in a wedged state
            # by a cancelled request (client/proxy disconnect mid-query) can
            # therefore NOT poison later requests — that was the failure mode
            # that made the panel hang after hours of uptime until a container
            # restart. SQLite connections are cheap to open, so for this
            # low-concurrency workload a persistent pool bought nothing but
            # that risk.
            poolclass=NullPool,
            connect_args={"timeout": 30},
            future=True,
        )
        event.listen(_engine.sync_engine, "connect", _apply_sqlite_pragmas)
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
