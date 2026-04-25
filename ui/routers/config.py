"""Configuration pages.

One router, five logical sections accessible under `/config`:

    /config/tenant                — Entra ID credentials + test connection
    /config/senders               — Authorised senders list
    /config/whitelist             — IP / CIDR whitelist
    /config/settings              — Global settings (bans, retention, ...)
    /config/bans                  — Active bans + manual unban

All state-changing endpoints depend on `require_csrf` and `require_user`.
"""

from __future__ import annotations

import datetime as _dt
import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select

from common.audit import record as audit_record
from common.constants import (
    ARCHIVE_RETENTION_MIN_DAYS,
    AUDIT_RETENTION_MIN_DAYS,
)
from common.crypto import decrypt_str, encrypt_str
from common.db import session_scope
from common.graph_client import GraphClient, GraphError
from common.models import (
    AuditEventType,
    AuditOutcome,
    AuthorisedSender,
    Ban,
    IpWhitelistEntry,
    Settings,
    TenantConfig,
)

from ..forms import (
    CidrIn,
    SenderIn,
    SettingsIn,
    cidr_form,
    sender_form,
    settings_form,
    tenant_form,
)
from .helpers import audit_config_change
from ..security import SessionPayload, require_csrf, require_user
from ..templating import render

router = APIRouter(prefix="/config")
_log = logging.getLogger("ui.config")


# =============================================================================
# Tenant (Entra ID)
# =============================================================================

@router.get("", include_in_schema=False)
async def config_root(request: Request, session: SessionPayload = Depends(require_user)):
    return RedirectResponse("/config/tenant", status_code=303)


@router.get("/tenant", include_in_schema=False)
async def tenant_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        cfg = await s.get(TenantConfig, 1)
    return render(
        request,
        "config_tenant.html",
        {
            "session": session,
            "cfg": cfg,
            "has_secret": bool(cfg and cfg.client_secret_enc),
            "error": None,
            "flash": None,
        },
    )


@router.post(
    "/tenant",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def tenant_save(
    request: Request,
    tenant_id: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    session: SessionPayload = Depends(require_user),
):
    try:
        data = tenant_form(
            tenant_id=tenant_id, client_id=client_id, client_secret=client_secret
        )
    except ValidationError as exc:
        return render(
            request,
            "config_tenant.html",
            {
                "session": session,
                "cfg": await _load_tenant(),
                "has_secret": True,
                "error": _first_error(exc),
                "flash": None,
            },
            status_code=400,
        )

    async with session_scope() as s:
        cfg = await s.get(TenantConfig, 1)
        if cfg is None:
            cfg = TenantConfig(id=1)
            s.add(cfg)
        cfg.tenant_id = data.tenant_id
        cfg.client_id = data.client_id
        if data.client_secret:
            cfg.client_secret_enc = encrypt_str(data.client_secret)
        # Invalidate cached test status — the operator must re-run it.
        cfg.last_test_at = None
        cfg.last_test_ok = None
        cfg.last_test_error = None

        await audit_config_change(
            s, session, request,
            details={
                "section": "tenant",
                "tenant_id": data.tenant_id,
                "client_id": data.client_id,
                "secret_updated": bool(data.client_secret),
            },
        )
    return RedirectResponse("/config/tenant?saved=1", status_code=303)


@router.post(
    "/tenant/test",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def tenant_test(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    """Try to acquire a Graph token with the stored credentials."""
    now = _utcnow()
    ok = False
    err: str | None = None
    expires_at: _dt.datetime | None = None

    async with session_scope() as s:
        cfg = await s.get(TenantConfig, 1)
        if (
            cfg is None
            or not cfg.tenant_id
            or not cfg.client_id
            or not cfg.client_secret_enc
        ):
            err = "Tenant configuration is incomplete."
        else:
            try:
                secret = decrypt_str(cfg.client_secret_enc)
                client = GraphClient(cfg.tenant_id, cfg.client_id, secret)
                import asyncio
                info = await asyncio.to_thread(client.acquire_token)
                ok = True
                expires_at = info.expires_at.replace(tzinfo=None)
            except GraphError as exc:
                err = str(exc)
            except Exception as exc:
                err = f"Unexpected error: {exc}"

        if cfg is None:
            cfg = TenantConfig(id=1)
            s.add(cfg)
        cfg.last_test_at = now
        cfg.last_test_ok = ok
        cfg.last_test_error = None if ok else (err or "Unknown error")[:2000]
        if ok:
            cfg.last_token_acquired_at = now
            cfg.last_token_expires_at = expires_at

        # NB: kept as raw audit_record because the outcome is conditional
        # on the Graph test result (SUCCESS vs FAILURE), while
        # audit_config_change() is hard-coded to SUCCESS.
        await audit_record(
            s,
            event_type=AuditEventType.CONFIG_CHANGE,
            outcome=AuditOutcome.SUCCESS if ok else AuditOutcome.FAILURE,
            username=session.username,
            source_ip=request.client.host if request.client else None,
            details={
                "section": "tenant",
                "action": "test_connection",
                "ok": ok,
                "error": None if ok else err,
            },
        )
    return RedirectResponse("/config/tenant?tested=1", status_code=303)


async def _load_tenant() -> TenantConfig | None:
    async with session_scope() as s:
        return await s.get(TenantConfig, 1)


# =============================================================================
# Authorised senders
# =============================================================================

@router.get("/senders", include_in_schema=False)
async def senders_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        rows = (
            await s.scalars(
                select(AuthorisedSender).order_by(AuthorisedSender.address)
            )
        ).all()
    return render(
        request,
        "config_senders.html",
        {"session": session, "rows": rows, "error": None},
    )


@router.post(
    "/senders",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def senders_add(
    request: Request,
    address: str = Form(""),
    description: str = Form(""),
    session: SessionPayload = Depends(require_user),
):
    try:
        data: SenderIn = sender_form(address=address, description=description)
    except ValidationError as exc:
        async with session_scope() as s:
            rows = (await s.scalars(select(AuthorisedSender))).all()
        return render(
            request,
            "config_senders.html",
            {"session": session, "rows": rows, "error": _first_error(exc)},
            status_code=400,
        )

    async with session_scope() as s:
        existing = await s.scalar(
            select(AuthorisedSender).where(AuthorisedSender.address == data.address)
        )
        if existing is not None:
            return RedirectResponse("/config/senders", status_code=303)
        s.add(
            AuthorisedSender(
                address=data.address,
                description=data.description or None,
                is_enabled=True,
            )
        )
        await audit_config_change(
            s, session, request,
            details={"section": "senders", "action": "add", "address": data.address},
        )
    return RedirectResponse("/config/senders", status_code=303)


@router.post(
    "/senders/{row_id}/toggle",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def senders_toggle(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(AuthorisedSender, row_id)
        if row is None:
            raise HTTPException(status_code=404)
        row.is_enabled = not row.is_enabled
        await audit_config_change(
            s, session, request,
            details={
                "section": "senders",
                "action": "toggle",
                "address": row.address,
                "enabled": row.is_enabled,
            },
        )
    return RedirectResponse("/config/senders", status_code=303)


@router.post(
    "/senders/{row_id}/delete",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def senders_delete(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(AuthorisedSender, row_id)
        if row is None:
            raise HTTPException(status_code=404)
        address = row.address
        await s.delete(row)
        await audit_config_change(
            s, session, request,
            details={"section": "senders", "action": "delete", "address": address},
        )
    return RedirectResponse("/config/senders", status_code=303)


# =============================================================================
# IP whitelist
# =============================================================================

@router.get("/whitelist", include_in_schema=False)
async def whitelist_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        rows = (
            await s.scalars(select(IpWhitelistEntry).order_by(IpWhitelistEntry.cidr))
        ).all()
    return render(
        request,
        "config_whitelist.html",
        {"session": session, "rows": rows, "error": None},
    )


@router.post(
    "/whitelist",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def whitelist_add(
    request: Request,
    cidr: str = Form(""),
    description: str = Form(""),
    session: SessionPayload = Depends(require_user),
):
    try:
        data: CidrIn = cidr_form(cidr=cidr, description=description)
    except ValidationError as exc:
        async with session_scope() as s:
            rows = (await s.scalars(select(IpWhitelistEntry))).all()
        return render(
            request,
            "config_whitelist.html",
            {"session": session, "rows": rows, "error": _first_error(exc)},
            status_code=400,
        )

    async with session_scope() as s:
        existing = await s.scalar(
            select(IpWhitelistEntry).where(IpWhitelistEntry.cidr == data.cidr)
        )
        if existing is None:
            s.add(
                IpWhitelistEntry(
                    cidr=data.cidr,
                    description=data.description or None,
                    is_enabled=True,
                )
            )
            await audit_config_change(
                s, session, request,
                details={"section": "whitelist", "action": "add", "cidr": data.cidr},
            )
    return RedirectResponse("/config/whitelist", status_code=303)


@router.post(
    "/whitelist/{row_id}/toggle",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def whitelist_toggle(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(IpWhitelistEntry, row_id)
        if row is None:
            raise HTTPException(status_code=404)
        row.is_enabled = not row.is_enabled
        await audit_config_change(
            s, session, request,
            details={
                "section": "whitelist",
                "action": "toggle",
                "cidr": row.cidr,
                "enabled": row.is_enabled,
            },
        )
    return RedirectResponse("/config/whitelist", status_code=303)


@router.post(
    "/whitelist/{row_id}/delete",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def whitelist_delete(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(IpWhitelistEntry, row_id)
        if row is None:
            raise HTTPException(status_code=404)
        cidr = row.cidr
        await s.delete(row)
        await audit_config_change(
            s, session, request,
            details={"section": "whitelist", "action": "delete", "cidr": cidr},
        )
    return RedirectResponse("/config/whitelist", status_code=303)


# =============================================================================
# Global settings
# =============================================================================

@router.get("/settings", include_in_schema=False)
async def settings_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(Settings, 1)
    return render(
        request,
        "config_settings.html",
        {
            "session": session,
            "row": row,
            "archive_floor": ARCHIVE_RETENTION_MIN_DAYS,
            "audit_floor": AUDIT_RETENTION_MIN_DAYS,
            "error": None,
        },
    )


@router.post(
    "/settings",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def settings_save(
    request: Request,
    smtp_auth_local_enabled: bool = Form(False),
    smtp_whitelist_enabled: bool = Form(False),
    smtp_ban_threshold: int = Form(5),
    smtp_ban_duration_min: int = Form(30),
    queue_max_attempts: int = Form(3),
    archive_retention_days: int = Form(30),
    audit_retention_days: int = Form(90),
    queue_sent_retention_days: int = Form(30),
    log_mail_contents: bool = Form(False),
    rate_limit_enabled: bool = Form(False),
    rate_limit_scope: str = Form("both"),
    rate_limit_threshold: int = Form(10),
    rate_limit_window_sec: int = Form(60),
    session: SessionPayload = Depends(require_user),
):
    try:
        data: SettingsIn = settings_form(
            smtp_auth_local_enabled=smtp_auth_local_enabled,
            smtp_whitelist_enabled=smtp_whitelist_enabled,
            smtp_ban_threshold=smtp_ban_threshold,
            smtp_ban_duration_min=smtp_ban_duration_min,
            queue_max_attempts=queue_max_attempts,
            archive_retention_days=archive_retention_days,
            audit_retention_days=audit_retention_days,
            queue_sent_retention_days=queue_sent_retention_days,
            log_mail_contents=log_mail_contents,
            rate_limit_enabled=rate_limit_enabled,
            rate_limit_scope=rate_limit_scope,
            rate_limit_threshold=rate_limit_threshold,
            rate_limit_window_sec=rate_limit_window_sec,
        )
    except ValidationError as exc:
        async with session_scope() as s:
            row = await s.get(Settings, 1)
        return render(
            request,
            "config_settings.html",
            {
                "session": session,
                "row": row,
                "archive_floor": ARCHIVE_RETENTION_MIN_DAYS,
                "audit_floor": AUDIT_RETENTION_MIN_DAYS,
                "error": _first_error(exc),
            },
            status_code=400,
        )

    if not (data.smtp_auth_local_enabled or data.smtp_whitelist_enabled):
        async with session_scope() as s:
            row = await s.get(Settings, 1)
        return render(
            request,
            "config_settings.html",
            {
                "session": session,
                "row": row,
                "archive_floor": ARCHIVE_RETENTION_MIN_DAYS,
                "audit_floor": AUDIT_RETENTION_MIN_DAYS,
                "error": "At least one SMTP authentication mode must be enabled.",
            },
            status_code=400,
        )

    # Enforce retention floors server-side as well as via clamping in
    # `common.archive.effective_retention_days`.
    archive_days = max(data.archive_retention_days, ARCHIVE_RETENTION_MIN_DAYS)
    audit_days = max(data.audit_retention_days, AUDIT_RETENTION_MIN_DAYS)

    async with session_scope() as s:
        row = await s.get(Settings, 1)
        if row is None:
            row = Settings(id=1)
            s.add(row)
        row.smtp_auth_local_enabled = data.smtp_auth_local_enabled
        row.smtp_whitelist_enabled = data.smtp_whitelist_enabled
        row.smtp_ban_threshold = data.smtp_ban_threshold
        row.smtp_ban_duration_min = data.smtp_ban_duration_min
        row.queue_max_attempts = data.queue_max_attempts
        row.archive_retention_days = archive_days
        row.audit_retention_days = audit_days
        row.queue_sent_retention_days = data.queue_sent_retention_days
        row.log_mail_contents = data.log_mail_contents
        row.rate_limit_enabled = data.rate_limit_enabled
        row.rate_limit_scope = data.rate_limit_scope
        row.rate_limit_threshold = data.rate_limit_threshold
        row.rate_limit_window_sec = data.rate_limit_window_sec

        await audit_config_change(
            s, session, request,
            details={
                "section": "settings",
                "archive_days": archive_days,
                "audit_days": audit_days,
                "queue_sent_days": data.queue_sent_retention_days,
                "ban_threshold": data.smtp_ban_threshold,
                "ban_duration_min": data.smtp_ban_duration_min,
                "auth_local": data.smtp_auth_local_enabled,
                "whitelist": data.smtp_whitelist_enabled,
                "log_mail_contents": data.log_mail_contents,
            },
        )
    return RedirectResponse("/config/settings?saved=1", status_code=303)


# =============================================================================
# Bans
# =============================================================================

@router.get("/bans", include_in_schema=False)
async def bans_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        rows = (
            await s.scalars(
                select(Ban)
                .where(Ban.until > _utcnow())
                .order_by(Ban.until.desc())
            )
        ).all()
    return render(
        request,
        "config_bans.html",
        {"session": session, "rows": rows},
    )


@router.post(
    "/bans/{ban_id}/unban",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def bans_unban(
    ban_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(Ban, ban_id)
        if row is None:
            raise HTTPException(status_code=404)
        kind = row.kind
        scope = row.scope
        value = row.value
        await s.delete(row)
        await audit_record(
            s,
            event_type=AuditEventType.USER_UNBAN,
            outcome=AuditOutcome.SUCCESS,
            username=session.username,
            source_ip=request.client.host if request.client else None,
            details={
                "kind": kind.value if hasattr(kind, "value") else str(kind),
                "scope": scope.value if hasattr(scope, "value") else str(scope),
                "value": value,
            },
        )
    return RedirectResponse("/config/bans", status_code=303)


# =============================================================================
# Helpers
# =============================================================================

def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def _first_error(exc: ValidationError) -> str:
    try:
        err = exc.errors()[0]
        loc = ".".join(str(p) for p in err.get("loc", ())) or "field"
        return f"{loc}: {err.get('msg', 'invalid')}"
    except Exception:
        return "Invalid input."
