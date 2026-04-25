"""UI user (admin) management.

Pages under /config/users:

    GET  /config/users                       List users
    POST /config/users                       Create user
    POST /config/users/{id}/toggle           Enable/disable
    POST /config/users/{id}/reset-password   Force password change + set new password
    POST /config/users/{id}/reset-totp       Clear TOTP; user will re-enrol at next login
    POST /config/users/{id}/delete           Delete (refused if it would leave zero admins)

All actions write an audit event with scrubbed details.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select

from common.db import session_scope
from common.models import User
from common.passwords import hash_password

from .helpers import audit_config_change
from ..security import SessionPayload, require_csrf, require_user
from ..templating import render


router = APIRouter(prefix="/config/users")


# -----------------------------------------------------------------------------
# List & create
# -----------------------------------------------------------------------------

@router.get("", include_in_schema=False)
async def list_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        rows = (
            await s.scalars(select(User).order_by(User.username))
        ).all()
    return render(
        request,
        "config_users.html",
        {"session": session, "rows": rows, "error": None, "flash": None},
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
    session: SessionPayload = Depends(require_user),
):
    username = (username or "").strip()
    if not username or len(username) > 64:
        return await _render_list(
            request, session, error="Username is required (1-64 chars)."
        )
    if len(password) < 12:
        return await _render_list(
            request, session, error="Password must be at least 12 characters."
        )

    async with session_scope() as s:
        existing = await s.scalar(select(User).where(User.username == username))
        if existing is not None:
            return await _render_list(
                request, session, error="Username already in use."
            )
        s.add(
            User(
                username=username,
                password_hash=hash_password(password),
                is_active=True,
                must_change_password=True,   # forced change on first login
            )
        )
        await audit_config_change(
            s, session, request,
            details={
                "section": "users",
                "action": "create",
                "target_username": username,
            },
        )
    return RedirectResponse("/config/users?created=1", status_code=303)


# -----------------------------------------------------------------------------
# Toggle enabled
# -----------------------------------------------------------------------------

@router.post(
    "/{user_id}/toggle",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def toggle(
    user_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        user = await s.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404)
        # Refuse to disable yourself.
        if user.id == session.user_id and user.is_active:
            return await _render_list(
                request, session, error="You cannot disable your own account."
            )
        # Refuse to disable the last active admin.
        if user.is_active:
            active_count = await s.scalar(
                select(func.count(User.id)).where(User.is_active.is_(True))
            )
            if (active_count or 0) <= 1:
                return await _render_list(
                    request, session,
                    error="Refusing to disable the last active user.",
                )
        user.is_active = not user.is_active
        await audit_config_change(
            s, session, request,
            details={
                "section": "users",
                "action": "toggle",
                "target_username": user.username,
                "active": user.is_active,
            },
        )
    return RedirectResponse("/config/users", status_code=303)


# -----------------------------------------------------------------------------
# Force password reset (for another user)
# -----------------------------------------------------------------------------

@router.post(
    "/{user_id}/reset-password",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def reset_password(
    user_id: int,
    request: Request,
    new_password: str = Form(""),
    session: SessionPayload = Depends(require_user),
):
    if len(new_password) < 12:
        return await _render_list(
            request, session, error="New password must be at least 12 characters."
        )

    async with session_scope() as s:
        user = await s.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404)
        user.password_hash = hash_password(new_password)
        user.must_change_password = True
        await audit_config_change(
            s, session, request,
            details={
                "section": "users",
                "action": "reset_password",
                "target_username": user.username,
            },
        )
    return RedirectResponse("/config/users?password_reset=1", status_code=303)


# -----------------------------------------------------------------------------
# Reset TOTP enrolment
# -----------------------------------------------------------------------------

@router.post(
    "/{user_id}/reset-totp",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def reset_totp(
    user_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        user = await s.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404)
        user.totp_secret = None
        user.totp_enrolled_at = None
        await audit_config_change(
            s, session, request,
            details={
                "section": "users",
                "action": "reset_totp",
                "target_username": user.username,
            },
        )
    return RedirectResponse("/config/users?totp_reset=1", status_code=303)


# -----------------------------------------------------------------------------
# Delete
# -----------------------------------------------------------------------------

@router.post(
    "/{user_id}/delete",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def delete(
    user_id: int,
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        user = await s.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404)
        # Never allow deleting oneself.
        if user.id == session.user_id:
            return await _render_list(
                request, session, error="You cannot delete your own account."
            )
        # Never allow removing the last active user.
        active_count = await s.scalar(
            select(func.count(User.id)).where(User.is_active.is_(True))
        )
        if user.is_active and (active_count or 0) <= 1:
            return await _render_list(
                request, session,
                error="Refusing to delete the last active user.",
            )
        target = user.username
        await s.delete(user)
        await audit_config_change(
            s, session, request,
            details={
                "section": "users",
                "action": "delete",
                "target_username": target,
            },
        )
    return RedirectResponse("/config/users", status_code=303)


# -----------------------------------------------------------------------------
# Self-service account page (the logged-in user manages their own creds)
# -----------------------------------------------------------------------------

account_router = APIRouter(prefix="/account")


@account_router.get("", include_in_schema=False)
async def account_view(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        user = await s.get(User, session.user_id)
    return render(
        request,
        "account.html",
        {
            "session": session,
            "user": user,
            "error": None,
            "flash": None,
        },
    )


@account_router.post(
    "/reset-totp",
    include_in_schema=False,
    dependencies=[Depends(require_csrf), Depends(require_user)],
)
async def account_reset_totp(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        user = await s.get(User, session.user_id)
        if user is None:
            raise HTTPException(status_code=404)
        user.totp_secret = None
        user.totp_enrolled_at = None
        await audit_config_change(
            s, session, request,
            details={
                "section": "account",
                "action": "self_reset_totp",
            },
        )
    # Invalidate the current session so the user has to re-enrol.
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("smtprelay_session", path="/")
    return response


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

async def _render_list(request: Request, session: SessionPayload, error: str):
    async with session_scope() as s:
        rows = (await s.scalars(select(User).order_by(User.username))).all()
    return render(
        request,
        "config_users.html",
        {"session": session, "rows": rows, "error": error, "flash": None},
        status_code=400,
    )
