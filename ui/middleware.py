"""HTTP response middleware applying security headers.

Nginx is the TLS terminator, so HSTS is safe even when uvicorn talks
HTTP internally — the browser only ever sees the nginx-facing scheme.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# Strict CSP: self-hosted CSS and JS only, no inline scripts, no third
# party origins. The UI serves no external assets by design.
_CSP = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "connect-src 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)
        h = response.headers
        # NB: Strict-Transport-Security is intentionally NOT set here.
        # nginx is the TLS terminator and emits HSTS itself; setting it
        # also in this middleware would result in a duplicated header
        # in the response (see ZAP rule 10035).
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Content-Security-Policy", _CSP)
        h.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # Make sure caches never store authenticated content.
        h.setdefault("Cache-Control", "no-store")
        return response
