"""Local SMTP account management.

CRUD for the `smtp_accounts` table. Passwords are bcrypt-hashed and
never returned to the UI; on edit the password field is empty and the
operator leaves it blank to keep the existing one.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select

from common.db import session_scope
from common.models import SmtpAccount
from common.passwords import hash_password

from ..forms import SmtpAccountIn, smtp_account_form
from .helpers import audit_config_change
from ..security import SessionPayload, require_csrf, require_user
from ..templating import render

router = APIRouter(prefix="/smtp-accounts")


def _first_error(exc: ValidationError) -> str:
    try:
        err = exc.errors()[0]
        loc = ".".join(str(p) for p in err.get("loc", ())) or "field"
        return f"{loc}: {err.get('msg', 'invalid')}"
    except Exception:
        return "Invalid input."


# -----------------------------------------------------------------------------
# List + create
# -----------------------------------------------------------------------------

@router.get("", include_in_schema=False)
async def list_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        rows = (
            await s.scalars(select(SmtpAccount).order_by(SmtpAccount.username))
        ).all()
    return render(
        request,
        "smtp_accounts.html",
        {"session": session, "rows": rows, "error": None},
    )


@router.post(
    "",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def create(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    allowed_cidrs: str = Form(""),
    description: str = Form(""),
    session: SessionPayload = Depends(require_user),
):
    try:
        data: SmtpAccountIn = smtp_account_form(
            username=username,
            password=password,
            allowed_cidrs=allowed_cidrs,
            description=description,
        )
    except ValidationError as exc:
        async with session_scope() as s:
            rows = (
                await s.scalars(select(SmtpAccount).order_by(SmtpAccount.username))
            ).all()
        return render(
            request,
            "smtp_accounts.html",
            {"session": session, "rows": rows, "error": _first_error(exc)},
            status_code=400,
        )

    if len(data.password) < 12:
        async with session_scope() as s:
            rows = (
                await s.scalars(select(SmtpAccount).order_by(SmtpAccount.username))
            ).all()
        return render(
            request,
            "smtp_accounts.html",
            {
                "session": session,
                "rows": rows,
                "error": "Password must be at least 12 characters.",
            },
            status_code=400,
        )

    async with session_scope() as s:
        existing = await s.scalar(
            select(SmtpAccount).where(SmtpAccount.username == data.username)
        )
        if existing is not None:
            rows = (
                await s.scalars(select(SmtpAccount).order_by(SmtpAccount.username))
            ).all()
            return render(
                request,
                "smtp_accounts.html",
                {
                    "session": session,
                    "rows": rows,
                    "error": "Username already in use.",
                },
                status_code=400,
            )
        s.add(
            SmtpAccount(
                username=data.username,
                password_hash=hash_password(data.password),
                allowed_cidrs=data.allowed_cidrs,
                description=data.description or None,
                is_enabled=True,
            )
        )
        await audit_config_change(
            s, session, request,
            details={
                "section": "smtp_accounts",
                "action": "create",
                "username": data.username,
                "allowed_cidrs_count": len(data.allowed_cidrs.splitlines()) if data.allowed_cidrs else 0,
            },
        )
    return RedirectResponse("/smtp-accounts", status_code=303)


# -----------------------------------------------------------------------------
# Edit / toggle / delete
# -----------------------------------------------------------------------------

@router.get("/{row_id}/edit", include_in_schema=False)
async def edit_view(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(SmtpAccount, row_id)
        if row is None:
            raise HTTPException(status_code=404)
    return render(
        request,
        "smtp_account_edit.html",
        {"session": session, "row": row, "error": None},
    )


@router.post(
    "/{row_id}/edit",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def edit_save(
    row_id: int,
    request: Request,
    password: str = Form(""),
    allowed_cidrs: str = Form(""),
    description: str = Form(""),
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(SmtpAccount, row_id)
        if row is None:
            raise HTTPException(status_code=404)

        # Validate the CIDR list shape via the shared pydantic model
        # (we only care about the side-effect of its validator).
        try:
            data: SmtpAccountIn = smtp_account_form(
                username=row.username,
                password=password,
                allowed_cidrs=allowed_cidrs,
                description=description,
            )
        except ValidationError as exc:
            return render(
                request,
                "smtp_account_edit.html",
                {
                    "session": session,
                    "row": row,
                    "error": _first_error(exc),
                },
                status_code=400,
            )

        if password:
            if len(password) < 12:
                return render(
                    request,
                    "smtp_account_edit.html",
                    {
                        "session": session,
                        "row": row,
                        "error": "Password must be at least 12 characters.",
                    },
                    status_code=400,
                )
            row.password_hash = hash_password(password)
        row.allowed_cidrs = data.allowed_cidrs
        row.description = description.strip() or None
        await audit_config_change(
            s, session, request,
            details={
                "section": "smtp_accounts",
                "action": "edit",
                "username": row.username,
                "password_changed": bool(password),
                "allowed_cidrs_count": len(data.allowed_cidrs.splitlines()) if data.allowed_cidrs else 0,
            },
        )
    return RedirectResponse("/smtp-accounts", status_code=303)


@router.post(
    "/{row_id}/toggle",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def toggle(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(SmtpAccount, row_id)
        if row is None:
            raise HTTPException(status_code=404)
        row.is_enabled = not row.is_enabled
        await audit_config_change(
            s, session, request,
            details={
                "section": "smtp_accounts",
                "action": "toggle",
                "username": row.username,
                "enabled": row.is_enabled,
            },
        )
    return RedirectResponse("/smtp-accounts", status_code=303)


@router.post(
    "/{row_id}/delete",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def delete(
    row_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        row = await s.get(SmtpAccount, row_id)
        if row is None:
            raise HTTPException(status_code=404)
        username = row.username
        await s.delete(row)
        await audit_config_change(
            s, session, request,
            details={
                "section": "smtp_accounts",
                "action": "delete",
                "username": username,
            },
        )
    return RedirectResponse("/smtp-accounts", status_code=303)
