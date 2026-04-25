"""FastAPI application wiring.

This module only composes the app. All business logic lives in the
`ui.routers.*` modules.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.exceptions import HTTPException as StarletteHTTPException

from common.db import dispose_engine, enable_sqlite_wal, get_engine

from .config import get_settings
from .middleware import SecurityHeadersMiddleware
from .routers import (
    archive as archive_router,
    audit as audit_router,
    auth as auth_router,
    config as config_router,
    dashboard as dashboard_router,
    queue as queue_router,
    smtp_accounts as smtp_accounts_router,
    users as users_router,
)
from .templating import render


_log = logging.getLogger("ui")


# -----------------------------------------------------------------------------
# Rate limiter
# -----------------------------------------------------------------------------
# slowapi needs a callable that produces the key. We key on the remote
# address as exposed by the X-Forwarded-For header (nginx sets it).
limiter = Limiter(key_func=get_remote_address, default_limits=[])


# -----------------------------------------------------------------------------
# Lifespan
# -----------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    get_engine()
    await enable_sqlite_wal()
    _log.info("UI startup complete.")
    app.state.started_at_ns = time.monotonic_ns()
    try:
        yield
    finally:
        await dispose_engine()


# -----------------------------------------------------------------------------
# App
# -----------------------------------------------------------------------------

def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=f"{settings.app_name} — Management UI",
        docs_url=None,   # the admin UI is not a public API; disable /docs
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    # slowapi integration.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)

    # Middleware.
    app.add_middleware(SecurityHeadersMiddleware)

    # Static assets.
    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Routers.
    app.include_router(auth_router.router)
    app.include_router(dashboard_router.router)
    app.include_router(config_router.router)
    app.include_router(smtp_accounts_router.router)
    app.include_router(queue_router.router)
    app.include_router(archive_router.router)
    app.include_router(audit_router.router)
    app.include_router(users_router.router)
    app.include_router(users_router.account_router)

    # Root handler: decide between login and dashboard based on session.
    @app.get("/", include_in_schema=False)
    async def _root(request: Request):
        # The actual redirect target is handled by dashboard_router
        # which gates on require_user. Keep this trivial so unauthed
        # users land on the login page.
        if request.cookies.get("smtprelay_session"):
            return RedirectResponse("/dashboard", status_code=303)
        return RedirectResponse("/login", status_code=303)

    # Liveness probe for nginx / orchestrators — no auth, no DB call.
    @app.get("/healthz", include_in_schema=False)
    async def _healthz():
        return {"status": "ok"}

    # Uniform error pages for common statuses.
    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 401:
            return RedirectResponse("/login", status_code=303)
        if exc.status_code in (403, 404):
            return render(
                request,
                "error.html",
                {"code": exc.status_code, "message": exc.detail or ""},
                status_code=exc.status_code,
            )
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_exception(request: Request, exc: RequestValidationError):
        return render(
            request,
            "error.html",
            {"code": 400, "message": "Invalid input."},
            status_code=400,
        )

    return app


def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        {"detail": "Too many requests. Please slow down."},
        status_code=429,
    )


app = create_app()
