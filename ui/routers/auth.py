"""Login, TOTP enrolment & verification, logout, password change.

Login is a two-step flow:

    1. POST /login with username + password.
       On success we set a session cookie marked as NOT yet TOTP-
       passed, and redirect to /login/totp (if already enrolled) or
       /login/totp/enrol (first login).

    2. POST /login/totp with a 6-digit code. On success we reissue
       the session cookie with totp_passed=True.

Once authenticated, every state-changing request must include a valid
CSRF token (see `ui.security.require_csrf`).

`must_change_password` forces a detour through /account/password
before the dashboard unlocks.
"""

from __future__ import annotations

import io
import logging

import pyotp
import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from slowapi.util import get_remote_address

from common.audit import record as audit_record
from common.bans import is_banned, record_failure
from common.db import session_scope
from common.models import (
    AuditEventType,
    AuditOutcome,
    BanKind,
    BanScope,
    User,
)
from common.passwords import hash_password, verify_password

from ..config import get_settings
from ..security import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    SessionPayload,
    current_session,
    encode_session,
    issue_csrf_token,
    require_csrf,
    require_user,
)
from ..templating import render


router = APIRouter()
_log = logging.getLogger("ui.auth")


# -----------------------------------------------------------------------------
# Cookie helpers
# -----------------------------------------------------------------------------

def _set_session_cookies(
    response: Response, payload: SessionPayload
) -> None:
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        encode_session(payload),
        max_age=settings.session_lifetime_seconds,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        issue_csrf_token(),
        max_age=settings.session_lifetime_seconds,
        # HttpOnly is fine for our threat model: the templates render
        # the token directly into a hidden form input server-side,
        # so JavaScript never needs to read the cookie. Setting
        # HttpOnly hardens against XSS-driven CSRF token theft.
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/")


def _client_ip(request: Request) -> str:
    return get_remote_address(request) or ""


# -----------------------------------------------------------------------------
# Login (step 1: password)
# -----------------------------------------------------------------------------

@router.get("/login", include_in_schema=False)
async def login_form(
    request: Request,
    session: SessionPayload | None = Depends(current_session),
):
    if session is not None and session.totp_passed:
        return RedirectResponse("/dashboard", status_code=303)

    # Re-use an existing valid CSRF cookie rather than regenerating one
    # on every GET. If we overwrite the cookie at each load, a
    # concurrent second load (prefetcher, reopened tab, refresh) will
    # replace the token and the HTML form of the first load will no
    # longer match its own cookie on POST -> 403.
    from ..security import verify_csrf_token
    existing = request.cookies.get(CSRF_COOKIE, "")
    token = existing if verify_csrf_token(existing) else issue_csrf_token()

    # The render() helper pulls the CSRF token from the request cookie
    # dict. Because at this point `request.cookies` may still reflect
    # an old / invalid value, force the template to see `token`
    # explicitly.
    response = render(request, "login.html", {"error": None, "csrf_token": token})
    if token != existing:
        # `token` originates from issue_csrf_token() (see security.py),
        # which uses itsdangerous + secrets.token_urlsafe(). It never
        # contains user-supplied data — CodeQL false positive.
        response.set_cookie(
            CSRF_COOKIE,
            token,  # noqa: S604
            max_age=get_settings().session_lifetime_seconds,
            httponly=True,
            secure=True,
            samesite="strict",
            path="/",
        )
    return response


@router.post("/login", include_in_schema=False)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
):
    # Manual CSRF check (we can't use the Depends variant because it
    # doesn't have the parsed form body yet).
    from ..security import verify_csrf_token
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    if not csrf_token or csrf_token != cookie_token or not verify_csrf_token(csrf_token):
        return render(
            request,
            "login.html",
            {"error": "Session expired, please try again."},
            status_code=403,
        )

    settings = get_settings()
    ip = _client_ip(request)

    async with session_scope() as s:
        if ip and await is_banned(
            s, kind=BanKind.UI, scope=BanScope.IP, value=ip
        ):
            return render(
                request,
                "login.html",
                {"error": "Too many failed attempts. Try again later."},
                status_code=429,
            )
        if username and await is_banned(
            s, kind=BanKind.UI, scope=BanScope.USERNAME, value=username
        ):
            return render(
                request,
                "login.html",
                {"error": "Too many failed attempts. Try again later."},
                status_code=429,
            )

        user = await s.scalar(select(User).where(User.username == username))
        ok = (
            user is not None
            and user.is_active
            and verify_password(password, user.password_hash)
        )

        if not ok:
            banned_ip = False
            banned_user = False
            if ip:
                banned_ip = await record_failure(
                    s,
                    kind=BanKind.UI,
                    scope=BanScope.IP,
                    value=ip,
                    source_ip=ip,
                    threshold=settings.ui_login_ban_threshold,
                    duration_min=settings.ui_login_ban_duration_min,
                )
            if username:
                banned_user = await record_failure(
                    s,
                    kind=BanKind.UI,
                    scope=BanScope.USERNAME,
                    value=username,
                    source_ip=ip,
                    threshold=settings.ui_login_ban_threshold,
                    duration_min=settings.ui_login_ban_duration_min,
                )
            await audit_record(
                s,
                event_type=AuditEventType.LOGIN_FAIL,
                outcome=AuditOutcome.FAILURE,
                source_ip=ip,
                username=username,
                details={
                    "banned_ip": banned_ip,
                    "banned_user": banned_user,
                },
            )
            if banned_ip or banned_user:
                await audit_record(
                    s,
                    event_type=AuditEventType.USER_BAN,
                    outcome=AuditOutcome.SUCCESS,
                    source_ip=ip,
                    username=username,
                    details={"kind": "ui"},
                )
            return render(
                request,
                "login.html",
                {"error": "Invalid credentials."},
                status_code=401,
            )

        # Password OK. Issue a partially-authenticated session cookie.
        assert user is not None
        payload = SessionPayload(
            user_id=user.id, username=user.username, totp_passed=False
        )

    # Decide redirect target.
    # TOTP comes first in every case: require_user() refuses any session
    # with totp_passed=False, so any page protected by that dependency
    # (including /account/password) would redirect back to /login and
    # create a loop. Only after the TOTP challenge do we honor
    # must_change_password.
    if user.totp_secret is None:
        target = "/login/totp/enrol"
    else:
        target = "/login/totp"
    response = RedirectResponse(target, status_code=303)
    _set_session_cookies(response, payload)
    return response


# -----------------------------------------------------------------------------
# TOTP — enrolment (step 1.5)
# -----------------------------------------------------------------------------

@router.get("/login/totp/enrol", include_in_schema=False)
async def totp_enrol_form(
    request: Request,
    session: SessionPayload | None = Depends(current_session),
):
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if session.totp_passed:
        return RedirectResponse("/dashboard", status_code=303)

    async with session_scope() as s:
        user = await s.get(User, session.user_id)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.totp_secret is None:
            user.totp_secret = pyotp.random_base32()
            await s.flush()
        secret = user.totp_secret
        username = user.username

    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=get_settings().app_name
    )
    svg = _qr_svg(uri)
    return render(
        request,
        "totp_enrol.html",
        {"secret": secret, "qr_svg": svg, "error": None},
    )


@router.post("/login/totp/enrol", include_in_schema=False)
async def totp_enrol_submit(
    request: Request,
    code: str = Form(...),
    csrf_token: str = Form(""),
    session: SessionPayload | None = Depends(current_session),
):
    from ..security import verify_csrf_token
    if not verify_csrf_token(csrf_token) or csrf_token != request.cookies.get(CSRF_COOKIE, ""):
        return RedirectResponse("/login", status_code=303)
    if session is None:
        return RedirectResponse("/login", status_code=303)

    async with session_scope() as s:
        user = await s.get(User, session.user_id)
        if user is None or user.totp_secret is None:
            return RedirectResponse("/login", status_code=303)
        if not pyotp.TOTP(user.totp_secret).verify(code.strip(), valid_window=1):
            await audit_record(
                s,
                event_type=AuditEventType.TOTP_FAIL,
                outcome=AuditOutcome.FAILURE,
                username=user.username,
                source_ip=_client_ip(request),
                details={"stage": "enrolment"},
            )
            import datetime as _dt
            # Reshow the form with the same QR.
            uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
                name=user.username, issuer_name=get_settings().app_name
            )
            return render(
                request,
                "totp_enrol.html",
                {
                    "secret": user.totp_secret,
                    "qr_svg": _qr_svg(uri),
                    "error": "Incorrect code. Try again.",
                },
                status_code=400,
            )

        import datetime as _dt
        user.totp_enrolled_at = _dt.datetime.utcnow()
        payload = SessionPayload(
            user_id=user.id, username=user.username, totp_passed=True
        )
        await audit_record(
            s,
            event_type=AuditEventType.LOGIN_OK,
            outcome=AuditOutcome.SUCCESS,
            username=user.username,
            source_ip=_client_ip(request),
            details={"stage": "enrolment"},
        )

    target = "/account/password" if (
        await _user_must_change_password(session.user_id)
    ) else "/dashboard"
    response = RedirectResponse(target, status_code=303)
    _set_session_cookies(response, payload)
    return response


# -----------------------------------------------------------------------------
# TOTP — verification (step 2)
# -----------------------------------------------------------------------------

@router.get("/login/totp", include_in_schema=False)
async def totp_form(
    request: Request,
    session: SessionPayload | None = Depends(current_session),
):
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if session.totp_passed:
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "totp.html", {"error": None})


@router.post("/login/totp", include_in_schema=False)
async def totp_submit(
    request: Request,
    code: str = Form(...),
    csrf_token: str = Form(""),
    session: SessionPayload | None = Depends(current_session),
):
    from ..security import verify_csrf_token
    if not verify_csrf_token(csrf_token) or csrf_token != request.cookies.get(CSRF_COOKIE, ""):
        return RedirectResponse("/login", status_code=303)
    if session is None:
        return RedirectResponse("/login", status_code=303)

    ip = _client_ip(request)
    settings = get_settings()

    async with session_scope() as s:
        user = await s.get(User, session.user_id)
        if user is None or user.totp_secret is None:
            return RedirectResponse("/login", status_code=303)

        valid = pyotp.TOTP(user.totp_secret).verify(code.strip(), valid_window=1)
        if not valid:
            await audit_record(
                s,
                event_type=AuditEventType.TOTP_FAIL,
                outcome=AuditOutcome.FAILURE,
                username=user.username,
                source_ip=ip,
            )
            if ip:
                await record_failure(
                    s,
                    kind=BanKind.UI,
                    scope=BanScope.IP,
                    value=ip,
                    source_ip=ip,
                    threshold=settings.ui_login_ban_threshold,
                    duration_min=settings.ui_login_ban_duration_min,
                )
            return render(
                request,
                "totp.html",
                {"error": "Incorrect code."},
                status_code=400,
            )

        payload = SessionPayload(
            user_id=user.id, username=user.username, totp_passed=True
        )
        await audit_record(
            s,
            event_type=AuditEventType.LOGIN_OK,
            outcome=AuditOutcome.SUCCESS,
            username=user.username,
            source_ip=ip,
        )
        must_change = user.must_change_password

    target = "/account/password" if must_change else "/dashboard"
    response = RedirectResponse(target, status_code=303)
    _set_session_cookies(response, payload)
    return response


# -----------------------------------------------------------------------------
# Logout
# -----------------------------------------------------------------------------

@router.post("/logout", include_in_schema=False, dependencies=[Depends(require_csrf)])
async def logout(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    async with session_scope() as s:
        await audit_record(
            s,
            event_type=AuditEventType.LOGIN_OK,
            outcome=AuditOutcome.SUCCESS,
            username=session.username,
            source_ip=_client_ip(request),
            details={"event": "logout"},
        )
    response = RedirectResponse("/login", status_code=303)
    _clear_session_cookies(response)
    return response


# -----------------------------------------------------------------------------
# Password change (enforced when must_change_password=True)
# -----------------------------------------------------------------------------

@router.get("/account/password", include_in_schema=False)
async def password_form(
    request: Request,
    session: SessionPayload = Depends(require_user),
):
    return render(request, "account_password.html", {"error": None})


@router.post(
    "/account/password",
    include_in_schema=False,
    dependencies=[Depends(require_csrf)],
)
async def password_submit(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    session: SessionPayload = Depends(require_user),
):
    if new_password != confirm_password:
        return render(
            request,
            "account_password.html",
            {"error": "New passwords do not match."},
            status_code=400,
        )
    if len(new_password) < 12:
        return render(
            request,
            "account_password.html",
            {"error": "New password must be at least 12 characters."},
            status_code=400,
        )

    async with session_scope() as s:
        user = await s.get(User, session.user_id)
        if user is None or not verify_password(current_password, user.password_hash):
            return render(
                request,
                "account_password.html",
                {"error": "Current password is incorrect."},
                status_code=400,
            )
        user.password_hash = hash_password(new_password)
        user.must_change_password = False
        # NB: kept as raw audit_record because _client_ip() respects the
        # X-Forwarded-For header (via slowapi.get_remote_address), while
        # audit_config_change() always uses request.client.host directly.
        # Swapping would lose proxy-aware source IP recording for login
        # events — which is the one place we most care about it.
        await audit_record(
            s,
            event_type=AuditEventType.CONFIG_CHANGE,
            outcome=AuditOutcome.SUCCESS,
            username=session.username,
            source_ip=_client_ip(request),
            details={"event": "password_change"},
        )
    return RedirectResponse("/account?saved=1", status_code=303)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

async def _user_must_change_password(user_id: int) -> bool:
    async with session_scope() as s:
        u = await s.get(User, user_id)
        return bool(u and u.must_change_password)


def _qr_svg(uri: str) -> str:
    """Return an inline SVG (str) encoding the provisioning URI.

    We use the SVG factory so the QR code renders crisply at any
    zoom level without bringing in a rasteriser dependency.
    """
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(uri, image_factory=factory, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")
