"""Ban bookkeeping.

Exposes three primitives, all async:

    is_banned(session, kind, scope, value) -> bool
    record_failure(session, kind, scope, value, source_ip, threshold, duration_min) -> bool
    clear(session, kind, scope, value)

`record_failure` returns True iff the failure pushed the (scope, value)
past the threshold and a ban was created as a side effect. Callers can
use that to log `user_ban` to the audit trail.

All row writes happen on the caller's session; the caller commits.
"""

from __future__ import annotations

import datetime as _dt
from typing import Optional

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Ban, BanKind, BanScope, FailedAttempt


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


async def is_banned(
    session: AsyncSession,
    *,
    kind: BanKind,
    scope: BanScope,
    value: str,
) -> bool:
    """Return True iff an unexpired ban exists for this (kind, scope, value)."""
    now = _utcnow()
    stmt = select(Ban.id).where(
        Ban.kind == kind,
        Ban.scope == scope,
        Ban.value == value,
        Ban.until > now,
    )
    return (await session.execute(stmt)).first() is not None


async def active_ban(
    session: AsyncSession,
    *,
    kind: BanKind,
    scope: BanScope,
    value: str,
) -> Optional[Ban]:
    now = _utcnow()
    stmt = select(Ban).where(
        Ban.kind == kind,
        Ban.scope == scope,
        Ban.value == value,
        Ban.until > now,
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def record_failure(
    session: AsyncSession,
    *,
    kind: BanKind,
    scope: BanScope,
    value: str,
    source_ip: str | None,
    threshold: int,
    duration_min: int,
    reason: str | None = None,
) -> bool:
    """Record one failed attempt; ban if threshold reached.

    Counts attempts in the window [now - duration_min, now]. When a
    new ban is created, the attempt counter is NOT reset — expired
    rows are pruned by `prune_old_attempts` periodically.
    """
    now = _utcnow()
    window_start = now - _dt.timedelta(minutes=duration_min)

    session.add(
        FailedAttempt(
            kind=kind, scope=scope, value=value, source_ip=source_ip
        )
    )
    await session.flush()

    count_stmt = select(func.count(FailedAttempt.id)).where(
        FailedAttempt.kind == kind,
        FailedAttempt.scope == scope,
        FailedAttempt.value == value,
        FailedAttempt.created_at >= window_start,
    )
    count = (await session.execute(count_stmt)).scalar_one()

    if count < threshold:
        return False

    # Already banned? Extend the expiry but don't create a duplicate.
    existing = await active_ban(session, kind=kind, scope=scope, value=value)
    until = now + _dt.timedelta(minutes=duration_min)
    if existing is not None:
        if existing.until < until:
            existing.until = until
        return False

    session.add(
        Ban(
            kind=kind,
            scope=scope,
            value=value,
            reason=reason or f"{count} failed attempts in {duration_min}m",
            until=until,
        )
    )
    await session.flush()
    return True


async def clear(
    session: AsyncSession,
    *,
    kind: BanKind,
    scope: BanScope,
    value: str,
) -> int:
    """Remove any active ban matching this tuple. Returns rows deleted."""
    stmt = delete(Ban).where(
        Ban.kind == kind,
        Ban.scope == scope,
        Ban.value == value,
    )
    res = await session.execute(stmt)
    return res.rowcount or 0


async def prune_old_attempts(
    session: AsyncSession, *, older_than_min: int
) -> int:
    cutoff = _utcnow() - _dt.timedelta(minutes=older_than_min)
    res = await session.execute(
        delete(FailedAttempt).where(FailedAttempt.created_at < cutoff)
    )
    return res.rowcount or 0


async def prune_expired_bans(session: AsyncSession) -> int:
    now = _utcnow()
    res = await session.execute(delete(Ban).where(Ban.until <= now))
    return res.rowcount or 0
