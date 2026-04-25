"""Signed session cookies + CSRF tokens.

Sessions are stored as a serialised, HMAC-signed payload in a single
cookie. `itsdangerous.URLSafeTimedSerializer` handles expiry by
rejecting tokens older than `max_age`. No server-side session store is
needed; revocation is achieved by bumping `SECRET_KEY` or by marking
the user's TOTP unenrolled (which forces a re-login).

CSRF tokens are independent HMAC strings bound to the user id. A POST
handler must validate the submitted token via `require_csrf`.
"""

from __future__ import annotations

import hmac
import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Optional

from fastapi import Cookie, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import get_settings

SESSION_COOKIE = "smtprelay_session"
CSRF_COOKIE = "smtprelay_csrf"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"


def _secret_key() -> str:
    key = os.environ.get("SECRET_KEY", "").strip()
    if not key or len(key) < 32:
        raise RuntimeError(
            "SECRET_KEY is missing or too short (need at least 32 chars)."
        )
    return key


def _serializer(salt: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_secret_key(), salt=salt)


# -----------------------------------------------------------------------------
# Session payload
# -----------------------------------------------------------------------------

@dataclass(slots=True)
class SessionPayload:
    user_id: int
    username: str
    # True once the user has passed both password and TOTP challenges.
    totp_passed: bool = False


def encode_session(payload: SessionPayload) -> str:
    return _serializer("session").dumps(
        {
            "uid": payload.user_id,
            "un": payload.username,
            "t": 1 if payload.totp_passed else 0,
        }
    )


def decode_session(token: str) -> Optional[SessionPayload]:
    if not token:
        return None
    settings = get_settings()
    try:
        data = _serializer("session").loads(
            token, max_age=settings.session_lifetime_seconds
        )
    except (SignatureExpired, BadSignature):
        return None
    try:
        return SessionPayload(
            user_id=int(data["uid"]),
            username=str(data["un"]),
            totp_passed=bool(data.get("t", 0)),
        )
    except (KeyError, ValueError, TypeError):
        return None


# -----------------------------------------------------------------------------
# CSRF tokens
# -----------------------------------------------------------------------------

def _csrf_hmac(raw: str) -> str:
    return hmac.new(_secret_key().encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_csrf_token() -> str:
    """Create an opaque CSRF token, bound to SECRET_KEY.

    The token is `r.s` where `r` is 16 random bytes hex-encoded and `s`
    is an HMAC over `r`. Validation reconstructs the HMAC and compares
    in constant time.
    """
    r = secrets.token_hex(16)
    s = _csrf_hmac(r)
    return f"{r}.{s}"


def verify_csrf_token(token: str | None) -> bool:
    if not token or "." not in token:
        return False
    r, s = token.split(".", 1)
    expected = _csrf_hmac(r)
    return hmac.compare_digest(expected, s)


async def require_csrf(request: Request) -> None:
    """FastAPI dependency that validates CSRF on state-changing requests.

    Accepts the token via (in order): X-CSRF-Token header, form field,
    multipart field. The matching cookie must also be present —
    double-submit cookie pattern. All HEAD / GET / OPTIONS requests
    pass through without a check.
    """
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return

    # 1. Header first (cheap, used by XHR clients).
    token = request.headers.get(CSRF_HEADER)

    # 2. Form body. Reading request.form() here fully consumes the
    # body, but Starlette caches it — the route handler gets the same
    # parsed form back via its Form(...) parameters.
    if not token:
        content_type = (request.headers.get("content-type") or "").lower()
        if (
            content_type.startswith("application/x-www-form-urlencoded")
            or content_type.startswith("multipart/form-data")
        ):
            try:
                form = await request.form()
                token = form.get(CSRF_FORM_FIELD)
            except Exception:
                token = None

    cookie_token = request.cookies.get(CSRF_COOKIE)
    if not token or not cookie_token or token != cookie_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid.",
        )
    if not verify_csrf_token(token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token signature invalid.",
        )


# -----------------------------------------------------------------------------
# FastAPI dependencies
# -----------------------------------------------------------------------------

async def current_session(
    session_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> SessionPayload | None:
    return decode_session(session_cookie or "")


async def require_user(
    session_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> SessionPayload:
    payload = decode_session(session_cookie or "")
    if payload is None or not payload.totp_passed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return payload
