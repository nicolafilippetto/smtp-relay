"""Inbound SMTP rate limiting.

Checked immediately before DATA is enqueued. Counts prior accepted
DATA commands within a sliding window (`rate_limit_window_sec` seconds),
per IP, per username, or both — depending on `rate_limit_scope` in
settings. If the count reaches `rate_limit_threshold`, the DATA is
refused with SMTP `452 4.7.1`.

The event counter is written into `smtp_rate_events`. Rows are pruned
by the relay housekeeper when they fall outside the longest active
window.
"""

from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass

from sqlalchemy import delete, func, select

from common.db import session_scope
from common.models import Settings, SmtpRateEvent

_log = logging.getLogger("relay.ratelimit")


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


@dataclass(slots=True)
class RateCheckResult:
    allowed: bool
    reason: str | None = None   # when not allowed, what tripped
    retry_after_sec: int = 0


async def check_and_record(
    *, source_ip: str | None, username: str | None
) -> RateCheckResult:
    """Look up current policy, count prior events, record this one if allowed.

    Returns `allowed=True` and writes a fresh row in smtp_rate_events on
    pass, or `allowed=False` with a reason on fail (and does NOT write
    the row).
    """
    async with session_scope() as s:
        settings = await s.scalar(select(Settings).where(Settings.id == 1))
        if settings is None or not settings.rate_limit_enabled:
            # Feature off: still record the event for future auditability?
            # No — keep the table small. Only record when enforcement is on.
            return RateCheckResult(allowed=True)

        scope = (settings.rate_limit_scope or "both").lower()
        threshold = int(settings.rate_limit_threshold or 10)
        window_sec = int(settings.rate_limit_window_sec or 60)

        since = _utcnow() - _dt.timedelta(seconds=window_sec)

        check_ip = scope in ("ip", "both") and bool(source_ip)
        check_user = scope in ("username", "both") and bool(username)

        if check_ip:
            count = await s.scalar(
                select(func.count(SmtpRateEvent.id)).where(
                    SmtpRateEvent.source_ip == source_ip,
                    SmtpRateEvent.timestamp >= since,
                )
            )
            if (count or 0) >= threshold:
                return RateCheckResult(
                    allowed=False,
                    reason=f"ip={source_ip} exceeded {threshold}/{window_sec}s",
                    retry_after_sec=window_sec,
                )

        if check_user:
            count = await s.scalar(
                select(func.count(SmtpRateEvent.id)).where(
                    SmtpRateEvent.username == username,
                    SmtpRateEvent.timestamp >= since,
                )
            )
            if (count or 0) >= threshold:
                return RateCheckResult(
                    allowed=False,
                    reason=f"user={username} exceeded {threshold}/{window_sec}s",
                    retry_after_sec=window_sec,
                )

        # Allowed: record the event.
        s.add(
            SmtpRateEvent(
                timestamp=_utcnow(),
                source_ip=source_ip,
                username=username,
            )
        )
    return RateCheckResult(allowed=True)


async def prune_old_events() -> int:
    """Delete rows older than the current window (×2 for safety margin).

    Called periodically by the relay housekeeper.
    """
    async with session_scope() as s:
        settings = await s.scalar(select(Settings).where(Settings.id == 1))
        if settings is None:
            return 0
        window_sec = int(settings.rate_limit_window_sec or 60) * 2
        cutoff = _utcnow() - _dt.timedelta(seconds=window_sec)
        res = await s.execute(
            delete(SmtpRateEvent).where(SmtpRateEvent.timestamp < cutoff)
        )
    return res.rowcount or 0
