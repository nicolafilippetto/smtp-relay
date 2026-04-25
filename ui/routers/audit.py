"""Audit-log viewer and CSV export.

Pages:

    GET /audit                 Filtered, paginated table view
    GET /audit/export.csv      Streaming CSV with the same filters

Filters:
    event_type     — one of the AuditEventType values
    outcome        — "success" | "failure"
    username       — exact match
    source_ip      — exact match
    date_from      — YYYY-MM-DD (inclusive)
    date_to        — YYYY-MM-DD (inclusive, end-of-day)
"""

from __future__ import annotations

import csv
import datetime as _dt
import io
import logging
from typing import AsyncIterator

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from common.db import session_scope
from common.models import AuditEventType, AuditLog, AuditOutcome

from ..security import SessionPayload, require_user
from ..templating import render


router = APIRouter(prefix="/audit")
_log = logging.getLogger("ui.audit")


# -----------------------------------------------------------------------------
# Filter helpers
# -----------------------------------------------------------------------------

def _parse_date(value: str | None, *, end_of_day: bool) -> _dt.datetime | None:
    if not value:
        return None
    try:
        d = _dt.date.fromisoformat(value)
    except ValueError:
        return None
    if end_of_day:
        return _dt.datetime.combine(d, _dt.time(23, 59, 59))
    return _dt.datetime.combine(d, _dt.time(0, 0, 0))


def _build_filters(
    event_type: str | None,
    outcome: str | None,
    username: str | None,
    source_ip: str | None,
    date_from: str | None,
    date_to: str | None,
):
    filters = []
    if event_type:
        try:
            filters.append(AuditLog.event_type == AuditEventType(event_type))
        except ValueError:
            pass
    if outcome:
        try:
            filters.append(AuditLog.outcome == AuditOutcome(outcome))
        except ValueError:
            pass
    if username:
        filters.append(AuditLog.username == username.strip())
    if source_ip:
        filters.append(AuditLog.source_ip == source_ip.strip())
    df = _parse_date(date_from, end_of_day=False)
    dt = _parse_date(date_to, end_of_day=True)
    if df is not None:
        filters.append(AuditLog.timestamp >= df)
    if dt is not None:
        filters.append(AuditLog.timestamp <= dt)
    return filters


# -----------------------------------------------------------------------------
# HTML view
# -----------------------------------------------------------------------------

@router.get("", include_in_schema=False)
async def list_view(
    request: Request,
    event_type: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    username: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    page: int = Query(default=1, ge=1, le=10_000),
    session: SessionPayload = Depends(require_user),
):
    page_size = 100
    filters = _build_filters(
        event_type, outcome, username, source_ip, date_from, date_to
    )

    async with session_scope() as s:
        count_stmt = select(func.count(AuditLog.id))
        for f in filters:
            count_stmt = count_stmt.where(f)
        total = int((await s.execute(count_stmt)).scalar_one() or 0)

        stmt = (
            select(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .limit(page_size)
            .offset((page - 1) * page_size)
        )
        for f in filters:
            stmt = stmt.where(f)
        rows = (await s.scalars(stmt)).all()

    total_pages = max(1, (total + page_size - 1) // page_size)
    return render(
        request,
        "audit.html",
        {
            "session": session,
            "rows": rows,
            "filters": {
                "event_type": event_type or "",
                "outcome": outcome or "",
                "username": username or "",
                "source_ip": source_ip or "",
                "date_from": date_from or "",
                "date_to": date_to or "",
            },
            "all_event_types": [e.value for e in AuditEventType],
            "all_outcomes": [o.value for o in AuditOutcome],
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
        },
    )


# -----------------------------------------------------------------------------
# CSV export
# -----------------------------------------------------------------------------

@router.get("/export.csv", include_in_schema=False)
async def export_csv(
    request: Request,
    event_type: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    username: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    session: SessionPayload = Depends(require_user),
):
    filters = _build_filters(
        event_type, outcome, username, source_ip, date_from, date_to
    )

    async def row_stream() -> AsyncIterator[bytes]:
        yield _csv_row(
            ["id", "timestamp", "event_type", "outcome", "source_ip", "username", "details"]
        )

        # Stream in 500-row chunks so a year's worth of audit history
        # doesn't buffer in memory.
        chunk = 500
        offset = 0
        while True:
            async with session_scope() as s:
                stmt = (
                    select(AuditLog)
                    .order_by(AuditLog.timestamp.asc())
                    .limit(chunk)
                    .offset(offset)
                )
                for f in filters:
                    stmt = stmt.where(f)
                rows = (await s.scalars(stmt)).all()
            if not rows:
                return
            for r in rows:
                yield _csv_row(
                    [
                        r.id,
                        r.timestamp.isoformat(sep=" ", timespec="seconds") if r.timestamp else "",
                        r.event_type.value if hasattr(r.event_type, "value") else r.event_type,
                        r.outcome.value if hasattr(r.outcome, "value") else r.outcome,
                        r.source_ip or "",
                        r.username or "",
                        r.details_json or "",
                    ]
                )
            offset += chunk

    filename = _csv_filename()
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
    }
    return StreamingResponse(
        row_stream(), media_type="text/csv; charset=utf-8", headers=headers
    )


# -----------------------------------------------------------------------------
# Low-level helpers
# -----------------------------------------------------------------------------

def _csv_row(values: list) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow([str(v) if v is not None else "" for v in values])
    return buf.getvalue().encode("utf-8")


def _csv_filename() -> str:
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"audit-{now}.csv"
