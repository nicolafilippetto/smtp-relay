"""Sent-mail archive browser.

Archive layout is fixed by `common.archive`:
    /data/archive/YYYY/MM/DD/<id>-<subject>.eml

Pages:

    GET  /archive                                 Year/month/day index
    GET  /archive/{YYYY}/{MM}/{DD}                Files for that day
    GET  /archive/view?path=...                   Render one .eml (safe)
    GET  /archive/download?path=...               Serve the raw .eml
    POST /archive/resend                          Requeue one .eml
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import logging
import os.path
from email import message_from_bytes
from email.policy import default as email_default_policy
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import FileResponse, RedirectResponse

from common import archive as archive_module
from common.audit import record as audit_record
from common.db import session_scope
from common.models import (
    AuditEventType,
    AuditOutcome,
    MailQueue,
    MailStatus,
)

from ..config import get_settings
from ..security import SessionPayload, require_csrf, require_user
from ..templating import render


router = APIRouter(prefix="/archive")
_log = logging.getLogger("ui.archive")


# -----------------------------------------------------------------------------
# Safe-path helper: the archive browser accepts relative paths from the
# client; `_resolve_path` refuses anything that escapes the archive root.
# -----------------------------------------------------------------------------

def _archive_root() -> Path:
    return Path(get_settings().archive_path).resolve()


def _resolve_path(rel_or_abs: str) -> Path:
    """Resolve a client-supplied path, ensuring it stays inside the archive.

    Two complementary guards are used so static analysers (CodeQL,
    Bandit, etc.) can trace the validation:

      1. ``Path.resolve().relative_to(root)`` — pythonic check, raises
         ``ValueError`` for traversals.
      2. ``os.path.commonpath`` — explicit, ASCII-string check that
         analysers consistently recognise as a path-traversal guard.

    Both are evaluated; either one alone would suffice.
    """
    if not rel_or_abs or not rel_or_abs.strip():
        raise HTTPException(status_code=400, detail="Missing path.")
    p = Path(rel_or_abs)
    if not p.is_absolute():
        p = _archive_root() / p
    resolved = p.resolve()
    root = _archive_root().resolve()
    # Guard 1: pathlib check.
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Path outside archive.") from exc
    # Guard 2: explicit commonpath check that static analysers can follow.
    try:
        common = os.path.commonpath([str(resolved), str(root)])
    except ValueError as exc:
        # Different drives on Windows, etc.
        raise HTTPException(status_code=403, detail="Path outside archive.") from exc
    if common != str(root):
        raise HTTPException(status_code=403, detail="Path outside archive.")
    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(status_code=404, detail="Not found.")
    if resolved.suffix.lower() != ".eml":
        raise HTTPException(status_code=403, detail="Unsupported file type.")
    return resolved


# -----------------------------------------------------------------------------
# Browse
# -----------------------------------------------------------------------------

@router.get("", include_in_schema=False)
async def root_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    """Show an index: year -> month -> day with counts."""
    root = _archive_root()
    index: dict[str, dict[str, dict[str, int]]] = {}
    if root.exists():
        for year_dir in sorted(
            (p for p in root.iterdir() if p.is_dir() and p.name.isdigit()),
            reverse=True,
        ):
            months: dict[str, dict[str, int]] = {}
            for month_dir in sorted(
                (p for p in year_dir.iterdir() if p.is_dir() and p.name.isdigit()),
                reverse=True,
            ):
                days: dict[str, int] = {}
                for day_dir in sorted(
                    (p for p in month_dir.iterdir() if p.is_dir() and p.name.isdigit()),
                    reverse=True,
                ):
                    days[day_dir.name] = sum(
                        1 for f in day_dir.iterdir() if f.suffix.lower() == ".eml"
                    )
                if days:
                    months[month_dir.name] = days
            if months:
                index[year_dir.name] = months
    disk_bytes = archive_module.archive_disk_usage_bytes()
    return render(
        request,
        "archive_index.html",
        {
            "session": session,
            "index": index,
            "disk_bytes": disk_bytes,
        },
    )


@router.get("/{year}/{month}/{day}", include_in_schema=False)
async def day_view(
    year: str,
    month: str,
    day: str,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    # Accept only numeric path segments to avoid traversal.
    if not (year.isdigit() and month.isdigit() and day.isdigit()):
        raise HTTPException(status_code=400, detail="Invalid date.")
    day_dir = (_archive_root() / year / month / day).resolve()
    root = _archive_root().resolve()
    # Dual guard so static analysers can follow the validation.
    try:
        day_dir.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Path outside archive.") from exc
    try:
        common = os.path.commonpath([str(day_dir), str(root)])
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Path outside archive.") from exc
    if common != str(root):
        raise HTTPException(status_code=403, detail="Path outside archive.")
    if not day_dir.exists() or not day_dir.is_dir():
        raise HTTPException(status_code=404, detail="No messages for that day.")

    files = []
    for f in sorted(day_dir.iterdir()):
        if f.suffix.lower() != ".eml" or not f.is_file():
            continue
        try:
            stat = f.stat()
        except OSError:
            continue
        rel = f.relative_to(_archive_root())
        files.append(
            {
                "rel_path": str(rel),
                "name": f.name,
                "size": stat.st_size,
                "mtime": _dt.datetime.fromtimestamp(
                    stat.st_mtime, tz=_dt.timezone.utc
                ),
            }
        )

    return render(
        request,
        "archive_day.html",
        {
            "session": session,
            "year": year,
            "month": month,
            "day": day,
            "files": files,
        },
    )


# -----------------------------------------------------------------------------
# View / download
# -----------------------------------------------------------------------------

@router.get("/view", include_in_schema=False)
async def view(
    request: Request,
    path: str = Query(...),
    session: SessionPayload = Depends(require_user),
):
    resolved = _resolve_path(path)
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Read error: {exc}") from exc

    headers, body_preview, truncated = _split_eml_for_display(raw)
    rel = resolved.relative_to(_archive_root())
    return render(
        request,
        "archive_view.html",
        {
            "session": session,
            "rel_path": str(rel),
            "size": len(raw),
            "headers": headers,
            "body_preview": body_preview,
            "body_truncated": truncated,
        },
    )


@router.get("/download", include_in_schema=False)
async def download(
    request: Request,
    path: str = Query(...),
    session: SessionPayload = Depends(require_user),
):
    resolved = _resolve_path(path)
    # Content-Disposition filename is the leaf; media type is RFC 5322.
    return FileResponse(
        path=str(resolved),
        media_type="message/rfc822",
        filename=resolved.name,
    )


# -----------------------------------------------------------------------------
# Resend
# -----------------------------------------------------------------------------

@router.post(
    "/resend",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def resend(
    request: Request,
    path: str = Form(...),
    session: SessionPayload = Depends(require_user),
):
    resolved = _resolve_path(path)
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Read error: {exc}") from exc

    # Best-effort extraction of sender / recipients / subject from the
    # archived MIME. If the archive file is malformed we refuse the
    # resend rather than enqueueing a broken message.
    sender, recipients, subject = _extract_envelope(raw)
    if not sender or not recipients:
        raise HTTPException(
            status_code=400,
            detail="Could not extract sender/recipients from the archived message.",
        )

    now = _utcnow()
    async with session_scope() as s:
        row = MailQueue(
            timestamp_received=now,
            sender=sender,
            recipients_json=json.dumps(recipients),
            subject=subject,
            raw_mime_b64=base64.b64encode(raw).decode("ascii"),
            status=MailStatus.PENDING,
            attempts=0,
            next_attempt_at=now,
            source_ip=None,
            source_username=session.username,
        )
        s.add(row)
        await s.flush()
        new_id = row.id
        await audit_record(
            s,
            event_type=AuditEventType.QUEUE_RETRY,
            outcome=AuditOutcome.SUCCESS,
            username=session.username,
            source_ip=request.client.host if request.client else None,
            details={
                "scope": "archive_resend",
                "archive_path": str(resolved.relative_to(_archive_root())),
                "new_queue_id": new_id,
                "sender": sender,
                "recipients": recipients,
            },
        )
    return RedirectResponse(f"/queue/{new_id}", status_code=303)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


_PREVIEW_BYTES = 8192


def _split_eml_for_display(raw: bytes) -> tuple[list[tuple[str, str]], str, bool]:
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


def _extract_envelope(raw: bytes) -> tuple[Optional[str], list[str], Optional[str]]:
    try:
        msg = message_from_bytes(raw, policy=email_default_policy)
    except Exception:
        return None, [], None

    sender = _header_address(msg, "From") or _header_address(msg, "Sender")
    recipients: list[str] = []
    for h in ("To", "Cc", "Bcc"):
        for addr in _header_addresses(msg, h):
            if addr and addr not in recipients:
                recipients.append(addr)
    subject = msg.get("Subject")
    return sender, recipients, str(subject) if subject else None


def _header_address(msg, name: str) -> Optional[str]:
    addrs = _header_addresses(msg, name)
    return addrs[0] if addrs else None


def _header_addresses(msg, name: str) -> list[str]:
    val = msg.get(name)
    if not val:
        return []
    try:
        addresses = getattr(val, "addresses", None)
        if addresses is None:
            return []
        return [a.addr_spec for a in addresses if a.addr_spec]
    except Exception:
        return []
