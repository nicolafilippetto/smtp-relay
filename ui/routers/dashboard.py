"""Dashboard view.

Aggregates:
  - Relay heartbeat & uptime
  - Mail stats (received/sent/failed/dead/queued) over 24h / 7d / 30d
  - Graph token status (last acquired / last expires)
  - Last 10 audit events
  - Alerts: dead queue non-empty, active bans, token expiring,
    disk usage threshold, retention at the minimum floor
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import time as _time
from dataclasses import dataclass

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

from common import archive
from common.constants import (
    ARCHIVE_RETENTION_MIN_DAYS,
    AUDIT_RETENTION_MIN_DAYS,
)
from common.db import session_scope
from common.models import (
    AuditLog,
    Ban,
    MailQueue,
    MailStatus,
    RelayHeartbeat,
    Settings,
    TenantConfig,
)

from ..security import SessionPayload, require_user
from ..templating import render


router = APIRouter()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


@dataclass(slots=True)
class RelayStatus:
    state: str          # "running" | "stopped" | "error"
    started_at: _dt.datetime | None
    last_seen_at: _dt.datetime | None
    uptime_seconds: int | None
    last_error: str | None


def _classify_heartbeat(hb: RelayHeartbeat | None, now: _dt.datetime) -> RelayStatus:
    if hb is None:
        return RelayStatus(
            state="stopped",
            started_at=None,
            last_seen_at=None,
            uptime_seconds=None,
            last_error=None,
        )
    # The relay writes a heartbeat every 10s; if we haven't seen one in
    # 60s the relay is presumed down. last_seen_at can briefly be NULL
    # right after the relay creates its row but before the first tick.
    if hb.status == "error":
        state = "error"
    elif hb.last_seen_at is None:
        state = "stopped"
    elif (now - hb.last_seen_at).total_seconds() > 60:
        state = "stopped"
    else:
        state = "running"
    uptime = int((now - hb.started_at).total_seconds()) if hb.started_at else None
    return RelayStatus(
        state=state,
        started_at=hb.started_at,
        last_seen_at=hb.last_seen_at,
        uptime_seconds=uptime,
        last_error=hb.last_error,
    )


# Archive disk usage is derived from a full recursive scan of the archive
# tree, which grows unbounded over time. Running it inline on the event
# loop blocked every other request (including the liveness probe) while it
# ran, and a slow-enough scan tripped the reverse-proxy read timeout. We
# push it into a worker thread and cache the result for a minute — the
# dashboard is a status view, so a slightly stale byte count is fine.
_DISK_CACHE_TTL_S = 60.0
_disk_cache: tuple[float, tuple[int, int, float]] | None = None


async def _archive_disk_stats() -> tuple[int, int, float]:
    """Return ``(disk_bytes, disk_total, disk_pct)``, cached and off-loop."""
    global _disk_cache
    now = _time.monotonic()
    if _disk_cache is not None and now < _disk_cache[0]:
        return _disk_cache[1]

    def _compute() -> tuple[int, int, float]:
        disk_bytes = archive.archive_disk_usage_bytes()
        disk_total = _volume_total_bytes(str(archive.archive_root()))
        disk_pct = (disk_bytes / disk_total * 100) if disk_total else 0.0
        return disk_bytes, disk_total, disk_pct

    stats = await asyncio.to_thread(_compute)
    _disk_cache = (now + _DISK_CACHE_TTL_S, stats)
    return stats


async def _stats_for_window(session, since: _dt.datetime) -> dict[str, int]:
    """Return counts grouped by status for rows received after `since`."""
    stmt = (
        select(MailQueue.status, func.count(MailQueue.id))
        .where(MailQueue.timestamp_received >= since)
        .group_by(MailQueue.status)
    )
    counts = {s.value: 0 for s in MailStatus}
    for status, n in (await session.execute(stmt)).all():
        key = status.value if hasattr(status, "value") else str(status)
        counts[key] = int(n)
    return counts


# -----------------------------------------------------------------------------
# View
# -----------------------------------------------------------------------------

@router.get("/dashboard", include_in_schema=False)
async def dashboard(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    now = _utcnow()
    day_ago = now - _dt.timedelta(days=1)
    week_ago = now - _dt.timedelta(days=7)
    month_ago = now - _dt.timedelta(days=30)

    async with session_scope() as s:
        hb = await s.get(RelayHeartbeat, 1)
        tenant = await s.get(TenantConfig, 1)
        settings = await s.get(Settings, 1)

        stats_24h = await _stats_for_window(s, day_ago)
        stats_7d = await _stats_for_window(s, week_ago)
        stats_30d = await _stats_for_window(s, month_ago)

        pending_or_sending = await s.scalar(
            select(func.count(MailQueue.id)).where(
                MailQueue.status.in_([MailStatus.PENDING, MailStatus.SENDING])
            )
        ) or 0
        dead_count = await s.scalar(
            select(func.count(MailQueue.id)).where(
                MailQueue.status == MailStatus.DEAD
            )
        ) or 0

        active_bans = (
            await s.scalars(
                select(Ban).where(Ban.until > now).order_by(Ban.until.desc()).limit(50)
            )
        ).all()

        recent_events = (
            await s.scalars(
                select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10)
            )
        ).all()

    relay = _classify_heartbeat(hb, now)

    # Archive disk usage (bytes); we emit an alert over 80% of the
    # filesystem size of /data. Computed off the event loop and cached —
    # see _archive_disk_stats.
    disk_bytes, disk_total, disk_pct = await _archive_disk_stats()

    token_warn = _token_warning(tenant, now)

    alerts: list[dict[str, str]] = []
    if dead_count:
        alerts.append(
            {
                "level": "warn",
                "message": f"{dead_count} mail(s) in DEAD queue. "
                           "Investigate and requeue from the Queue page.",
            }
        )
    if active_bans:
        alerts.append(
            {
                "level": "info",
                "message": f"{len(active_bans)} active ban(s).",
            }
        )
    if token_warn:
        alerts.append({"level": "warn", "message": token_warn})
    if disk_pct >= 80:
        alerts.append(
            {
                "level": "warn",
                "message": f"Archive volume at {disk_pct:.0f}% capacity.",
            }
        )
    if settings and settings.archive_retention_days <= ARCHIVE_RETENTION_MIN_DAYS:
        alerts.append(
            {
                "level": "info",
                "message": f"Archive retention at the minimum floor "
                           f"({ARCHIVE_RETENTION_MIN_DAYS} days).",
            }
        )
    if settings and settings.audit_retention_days <= AUDIT_RETENTION_MIN_DAYS:
        alerts.append(
            {
                "level": "info",
                "message": f"Audit retention at the minimum floor "
                           f"({AUDIT_RETENTION_MIN_DAYS} days).",
            }
        )

    expiry_alert = _secret_expiry_alert(tenant, settings, now.date())
    if expiry_alert:
        alerts.append(expiry_alert)

    return render(
        request,
        "dashboard.html",
        {
            "session": session,
            "relay": relay,
            "stats": {"h24": stats_24h, "d7": stats_7d, "d30": stats_30d},
            "pending": pending_or_sending,
            "dead": dead_count,
            "tenant": tenant,
            "settings": settings,
            "active_bans": active_bans,
            "recent_events": recent_events,
            "alerts": alerts,
            "disk_bytes": disk_bytes,
            "disk_total": disk_total,
            "disk_pct": disk_pct,
        },
    )


def _token_warning(tenant: TenantConfig | None, now: _dt.datetime) -> str | None:
    if tenant is None:
        return "Entra tenant is not configured yet."
    if not tenant.tenant_id or not tenant.client_id or not tenant.has_active_credential:
        return "Entra tenant configuration is incomplete."
    if tenant.last_test_ok is False:
        return "Last Graph connection test failed — check the Config page."
    expires = tenant.last_token_expires_at
    if expires is None:
        return None
    if expires <= now:
        return "Last known Graph token is expired."
    if expires - now <= _dt.timedelta(hours=24):
        return "Last known Graph token expires within 24 hours."
    return None


def _secret_expiry_alert(
    tenant: TenantConfig | None,
    settings: Settings | None,
    today: _dt.date,
) -> dict[str, str] | None:
    """Mirror the digest-section logic so the dashboard shows the same state."""
    if tenant is None or tenant.credential_expires_at is None:
        return None
    expiry = tenant.credential_expires_at
    label = tenant.credential_label  # "client secret" | "certificate"
    threshold = settings.alert_secret_expiry_days if settings else 30
    days = (expiry - today).days
    if days > threshold:
        return None
    if days < 0:
        return {
            "level": "err",
            "message": (
                f"Azure AD {label} expiry date passed {-days} day(s) ago "
                f"({expiry.isoformat()})."
            ),
        }
    if days == 0:
        return {
            "level": "err",
            "message": f"Azure AD {label} expires TODAY ({expiry.isoformat()}).",
        }
    return {
        "level": "warn",
        "message": (
            f"Azure AD {label} expires in {days} day(s) ({expiry.isoformat()})."
        ),
    }


def _volume_total_bytes(path: str) -> int:
    """Total size (bytes) of the filesystem holding `path`.

    Uses shutil.disk_usage so it works on both POSIX and Windows
    (os.statvfs does not exist on Windows). Returns 0 if the path is not
    accessible yet, in which case callers skip the capacity alert.
    """
    import shutil
    try:
        return shutil.disk_usage(path).total
    except (OSError, ValueError):
        return 0
