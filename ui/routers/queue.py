"""Mail queue management.

Pages:

    GET  /queue                   List queue with status filters + pagination
    GET  /queue/{id}              Detail view (headers + body preview)
    POST /queue/{id}/retry        Move one row back to PENDING (now)
    POST /queue/{id}/delete       Delete a queue row
    POST /queue/retry-all-dead    Requeue every DEAD row
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import logging
from email import message_from_bytes
from email.policy import default as email_default_policy

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select

from common.audit import record as audit_record
from common.db import session_scope
from common.models import (
    AuditEventType,
    AuditOutcome,
    MailQueue,
    MailStatus,
)

from .helpers import audit_config_change
from ..security import SessionPayload, require_csrf, require_user
from ..templating import render


router = APIRouter(prefix="/queue")
_log = logging.getLogger("ui.queue")


# -----------------------------------------------------------------------------
# List view
# -----------------------------------------------------------------------------

@router.get("", include_in_schema=False)
async def list_view(
    request: Request,
    status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1, le=10_000),
    session: SessionPayload = Depends(require_user),
):
    page_size = 50
    filters = []
    selected_status = None
    if status:
        try:
            selected_status = MailStatus(status)
            filters.append(MailQueue.status == selected_status)
        except ValueError:
            selected_status = None

    async with session_scope() as s:
        count_stmt = select(func.count(MailQueue.id))
        for f in filters:
            count_stmt = count_stmt.where(f)
        total = int((await s.execute(count_stmt)).scalar_one() or 0)

        stmt = (
            select(MailQueue)
            .order_by(MailQueue.timestamp_received.desc())
            .limit(page_size)
            .offset((page - 1) * page_size)
        )
        for f in filters:
            stmt = stmt.where(f)
        rows = (await s.scalars(stmt)).all()

        counts_by_status = {s_.value: 0 for s_ in MailStatus}
        for st, n in (
            await s.execute(
                select(MailQueue.status, func.count(MailQueue.id)).group_by(
                    MailQueue.status
                )
            )
        ).all():
            key = st.value if hasattr(st, "value") else str(st)
            counts_by_status[key] = int(n)

    total_pages = max(1, (total + page_size - 1) // page_size)
    return render(
        request,
        "queue.html",
        {
            "session": session,
            "rows": rows,
            "all_statuses": [s_.value for s_ in MailStatus],
            "selected_status": selected_status.value if selected_status else None,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
            "counts_by_status": counts_by_status,
        },
    )


# -----------------------------------------------------------------------------
# Single-message detail
# -----------------------------------------------------------------------------

@router.get("/{row_id}", include_in_schema=False)
async def detail_view(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(MailQueue, row_id)
        if row is None:
            raise HTTPException(status_code=404)

        try:
            raw = base64.b64decode(row.raw_mime_b64.encode("ascii"))
        except Exception:
            raw = b""

    headers, body_preview, body_truncated = _split_eml_for_display(raw)
    try:
        recipients = json.loads(row.recipients_json or "[]")
    except (TypeError, ValueError):
        recipients = []

    return render(
        request,
        "queue_detail.html",
        {
            "session": session,
            "row": row,
            "recipients": recipients,
            "headers": headers,
            "body_preview": body_preview,
            "body_truncated": body_truncated,
        },
    )


# -----------------------------------------------------------------------------
# Actions
# -----------------------------------------------------------------------------

@router.post(
    "/{row_id}/retry",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def retry_one(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(MailQueue, row_id)
        if row is None:
            raise HTTPException(status_code=404)
        row.status = MailStatus.PENDING
        row.next_attempt_at = _utcnow()
        row.last_error = None
        await audit_record(
            s,
            event_type=AuditEventType.QUEUE_RETRY,
            outcome=AuditOutcome.SUCCESS,
            username=session.username,
            source_ip=request.client.host if request.client else None,
            details={"queue_id": row_id, "scope": "single"},
        )
    return RedirectResponse(f"/queue/{row_id}", status_code=303)


@router.post(
    "/retry-all-dead",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def retry_all_dead(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    now = _utcnow()
    from sqlalchemy import update

    async with session_scope() as s:
        res = await s.execute(
            update(MailQueue)
            .where(MailQueue.status == MailStatus.DEAD)
            .values(status=MailStatus.PENDING, next_attempt_at=now, last_error=None)
            .execution_options(synchronize_session=False)
        )
        touched = res.rowcount or 0
        await audit_record(
            s,
            event_type=AuditEventType.QUEUE_RETRY,
            outcome=AuditOutcome.SUCCESS,
            username=session.username,
            source_ip=request.client.host if request.client else None,
            details={"scope": "all_dead", "count": touched},
        )
    return RedirectResponse("/queue?status=dead", status_code=303)


@router.post(
    "/{row_id}/delete",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def delete_row(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(MailQueue, row_id)
        if row is None:
            raise HTTPException(status_code=404)
        sender = row.sender
        status_val = row.status
        await s.delete(row)
        await audit_config_change(
            s, session, request,
            details={
                "section": "queue",
                "action": "delete",
                "queue_id": row_id,
                "sender": sender,
                "status": status_val.value if hasattr(status_val, "value") else str(status_val),
            },
        )
    return RedirectResponse("/queue", status_code=303)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


_PREVIEW_BYTES = 8192


def _split_eml_for_display(raw: bytes) -> tuple[list[tuple[str, str]], str, bool]:
    """Return (headers, body_preview, truncated) from a raw .eml.

    We only preview the text payload. HTML parts are rendered as
    escaped text to avoid any risk of the admin's browser parsing
    untrusted markup inside the CSP-protected admin UI.
    """
    if not raw:
        return [], "", False

    try:
        msg = message_from_bytes(raw, policy=email_default_policy)
    except Exception:
        return [("X-Parse-Error", "Could not parse MIME")], "", False

    headers = [(k, str(v)) for k, v in msg.items()]

    body = msg.get_body(preferencelist=("plain", "html"))
    if body is None:
        return headers, "", False

    try:
        text = body.get_content()
    except Exception:
        text = ""

    truncated = False
    if len(text) > _PREVIEW_BYTES:
        text = text[:_PREVIEW_BYTES]
        truncated = True
    return headers, text, truncated
