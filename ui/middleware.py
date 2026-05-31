"""HTTP response middleware applying security headers.

Nginx is the TLS terminator, so HSTS is safe even when uvicorn talks
HTTP internally — the browser only ever sees the nginx-facing scheme.
"""

from __future__ import annotations

import ipaddress

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response


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


class PrivateNetworkOnlyMiddleware(BaseHTTPMiddleware):
    """Reject requests whose client IP is not loopback or RFC1918 private.

    Used by the native-Windows build, where uvicorn binds to all interfaces so
    the panel is reachable from the LAN. If the host is ever accidentally
    exposed to the internet, public clients are refused with 403 — the panel
    only answers private/loopback addresses. This is a connection-source guard,
    NOT a replacement for the login: authentication still applies on top.

    It is NOT used in the Docker deployment (there the panel sits behind nginx
    and the real client IP is not the socket peer); the launcher enables it only
    when binding beyond loopback.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        client = request.client
        host = client.host if client else None
        if not _is_private_or_loopback(host):
            return PlainTextResponse("Forbidden", status_code=403)
        return await call_next(request)


def _is_private_or_loopback(host: str | None) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # is_private covers RFC1918 (10/8, 172.16/12, 192.168/16), unique-local
    # IPv6 (fc00::/7) and link-local; is_loopback covers 127/8 and ::1.
    return ip.is_loopback or ip.is_private or ip.is_link_local
