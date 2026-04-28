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

from common import admin_alerts
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
    AdminNotificationsIn,
    CidrIn,
    SenderIn,
    SettingsIn,
    cidr_form,
    notifications_form,
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
            "today": _utcnow().date(),
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
    secret_expires_at: str = Form(""),
    clear_secret_expires_at: bool = Form(False),
    expiry_verified: bool = Form(False),
    session: SessionPayload = Depends(require_user),
):
    try:
        data = tenant_form(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            secret_expires_at=secret_expires_at,
            clear_secret_expires_at=clear_secret_expires_at,
            expiry_verified=expiry_verified,
        )
    except (ValidationError, ValueError) as exc:
        msg = _first_error(exc) if isinstance(exc, ValidationError) else str(exc)
        return render(
            request,
            "config_tenant.html",
            {
                "session": session,
                "cfg": await _load_tenant(),
                "has_secret": True,
                "today": _utcnow().date(),
                "error": msg,
                "flash": None,
            },
            status_code=400,
        )

    # When a new client_secret is being submitted, the operator must
    # explicitly confirm the expiry date is up-to-date. This guards
    # against the common "I rotated but forgot to update the date"
    # mistake.
    if data.client_secret and not data.expiry_verified:
        return render(
            request,
            "config_tenant.html",
            {
                "session": session,
                "cfg": await _load_tenant(),
                "has_secret": True,
                "today": _utcnow().date(),
                "error": (
                    "When updating the client secret you must tick "
                    "'I have verified the secret expiry date' to confirm "
                    "the date below reflects the new secret."
                ),
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
        if data.clear_secret_expires_at:
            cfg.secret_expires_at = None
        elif data.secret_expires_at is not None:
            cfg.secret_expires_at = data.secret_expires_at
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
                "secret_expires_at": (
                    cfg.secret_expires_at.isoformat()
                    if cfg.secret_expires_at else None
                ),
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
# Admin notifications
# =============================================================================

@router.get("/notifications", include_in_schema=False)
async def notifications_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(Settings, 1)
        senders = (
            await s.scalars(
                select(AuthorisedSender)
                .where(AuthorisedSender.is_enabled.is_(True))
                .order_by(AuthorisedSender.address)
            )
        ).all()
    return render(
        request,
        "config_notifications.html",
        {
            "session": session,
            "row": row,
            "senders": senders,
            "error": None,
            "flash": None,
        },
    )


@router.post(
    "/notifications",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def notifications_save(
    request: Request,
    admin_email_from_name: str = Form(""),
    admin_email_from: str = Form(""),
    admin_email_to: str = Form(""),
    alert_secret_expiry_days: int = Form(30),
    alert_daily_time: str = Form("09:00"),
    alert_secret_expiry: bool = Form(False),
    alert_dead_queue: bool = Form(False),
    alert_relay_down: bool = Form(False),
    alert_graph_test_failed: bool = Form(False),
    alert_disk_usage: bool = Form(False),
    alert_send_failures: bool = Form(False),
    alert_failed_login_spike: bool = Form(False),
    alert_user_banned: bool = Form(False),
    alert_admin_reset: bool = Form(False),
    alert_admin_password_change: bool = Form(False),
    alert_smtp_password_change: bool = Form(False),
    session: SessionPayload = Depends(require_user),
):
    try:
        data: AdminNotificationsIn = notifications_form(
            admin_email_from_name=admin_email_from_name,
            admin_email_from=admin_email_from,
            admin_email_to=admin_email_to,
            alert_secret_expiry_days=alert_secret_expiry_days,
            alert_daily_time=alert_daily_time,
            alert_secret_expiry=alert_secret_expiry,
            alert_dead_queue=alert_dead_queue,
            alert_relay_down=alert_relay_down,
            alert_graph_test_failed=alert_graph_test_failed,
            alert_disk_usage=alert_disk_usage,
            alert_send_failures=alert_send_failures,
            alert_failed_login_spike=alert_failed_login_spike,
            alert_user_banned=alert_user_banned,
            alert_admin_reset=alert_admin_reset,
            alert_admin_password_change=alert_admin_password_change,
            alert_smtp_password_change=alert_smtp_password_change,
        )
    except ValidationError as exc:
        return await _render_notifications(
            request, session, error=_first_error(exc)
        )

    async with session_scope() as s:
        senders_enabled = {
            r.address.lower()
            for r in (
                await s.scalars(
                    select(AuthorisedSender).where(
                        AuthorisedSender.is_enabled.is_(True)
                    )
                )
            ).all()
        }

    if data.admin_email_from and data.admin_email_from not in senders_enabled:
        return await _render_notifications(
            request,
            session,
            error=(
                f"From address '{data.admin_email_from}' must be one of "
                "the enabled Authorised Senders."
            ),
        )

    async with session_scope() as s:
        row = await s.get(Settings, 1)
        if row is None:
            row = Settings(id=1)
            s.add(row)
        row.admin_email_from_name = data.admin_email_from_name or None
        row.admin_email_from = data.admin_email_from or None
        row.admin_email_to = data.admin_email_to or None
        row.alert_secret_expiry_days = data.alert_secret_expiry_days
        row.alert_daily_time = data.alert_daily_time
        row.alert_secret_expiry = data.alert_secret_expiry
        row.alert_dead_queue = data.alert_dead_queue
        row.alert_relay_down = data.alert_relay_down
        row.alert_graph_test_failed = data.alert_graph_test_failed
        row.alert_disk_usage = data.alert_disk_usage
        row.alert_send_failures = data.alert_send_failures
        row.alert_failed_login_spike = data.alert_failed_login_spike
        row.alert_user_banned = data.alert_user_banned
        row.alert_admin_reset = data.alert_admin_reset
        row.alert_admin_password_change = data.alert_admin_password_change
        row.alert_smtp_password_change = data.alert_smtp_password_change

        await audit_config_change(
            s, session, request,
            details={
                "section": "notifications",
                "admin_email_from_name": data.admin_email_from_name or None,
                "admin_email_from": data.admin_email_from or None,
                "admin_email_to": data.admin_email_to or None,
                "daily_time": data.alert_daily_time,
            },
        )
    return RedirectResponse("/config/notifications?saved=1", status_code=303)


@router.post(
    "/notifications/test",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def notifications_test(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    ok, why = await admin_alerts.send_test_alert()
    qs = "tested=ok" if ok else f"tested=fail&why={(why or '').replace(' ', '+')[:200]}"
    return RedirectResponse(f"/config/notifications?{qs}", status_code=303)


async def _render_notifications(request, session, *, error: str):
    async with session_scope() as s:
        row = await s.get(Settings, 1)
        senders = (
            await s.scalars(
                select(AuthorisedSender)
                .where(AuthorisedSender.is_enabled.is_(True))
                .order_by(AuthorisedSender.address)
            )
        ).all()
    return render(
        request,
        "config_notifications.html",
        {
            "session": session,
            "row": row,
            "senders": senders,
            "error": error,
            "flash": None,
        },
        status_code=400,
    )


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
