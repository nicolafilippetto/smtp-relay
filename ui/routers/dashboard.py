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

import datetime as _dt
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
    # 60s the relay is presumed down.
    lag = (now - hb.last_seen_at).total_seconds()
    if hb.status == "error":
        state = "error"
    elif lag > 60:
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
    # filesystem size of /data.
    disk_bytes = archive.archive_disk_usage_bytes()
    disk_total = _volume_total_bytes("/data")
    disk_pct = (disk_bytes / disk_total * 100) if disk_total else 0.0

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
    if not tenant.tenant_id or not tenant.client_id or not tenant.client_secret_enc:
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
    if tenant is None or tenant.secret_expires_at is None:
        return None
    threshold = settings.alert_secret_expiry_days if settings else 30
    days = (tenant.secret_expires_at - today).days
    if days > threshold:
        return None
    if days < 0:
        return {
            "level": "err",
            "message": (
                f"Azure AD client secret expiry date passed {-days} day(s) ago "
                f"({tenant.secret_expires_at.isoformat()}). "
                f"Verify the date or rotate the secret."
            ),
        }
    if days == 0:
        return {
            "level": "err",
            "message": (
                f"Azure AD client secret expires TODAY "
                f"({tenant.secret_expires_at.isoformat()})."
            ),
        }
    return {
        "level": "warn",
        "message": (
            f"Azure AD client secret expires in {days} day(s) "
            f"({tenant.secret_expires_at.isoformat()})."
        ),
    }


def _volume_total_bytes(path: str) -> int:
    import os
    try:
        s = os.statvfs(path)
        return s.f_blocks * s.f_frsize
    except OSError:
        return 0
