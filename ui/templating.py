"""Jinja2 environment shared by all routers.

The single environment provides:
  - autoescape on .html / .xml
  - a `csrf_token` context variable (pulled from the request cookie)
  - formatting filters used by the templates
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import get_settings
from .security import CSRF_COOKIE


_templates_dir = Path(__file__).resolve().parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_templates_dir)),
    autoescape=select_autoescape(("html", "xml")),
    trim_blocks=True,
    lstrip_blocks=True,
)


# -----------------------------------------------------------------------------
# Filters
# -----------------------------------------------------------------------------

def _fmt_dt(value: _dt.datetime | None) -> str:
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.timezone.utc)
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_bytes(n: int | float | None) -> str:
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def _pretty_json(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return value
    try:
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


_env.filters["dt"] = _fmt_dt
_env.filters["bytes"] = _fmt_bytes
_env.filters["pretty_json"] = _pretty_json


# -----------------------------------------------------------------------------
# Rendering
# -----------------------------------------------------------------------------

def render(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
) -> HTMLResponse:
    ctx = {
        "request": request,
        "app_name": get_settings().app_name,
        "csrf_token": request.cookies.get(CSRF_COOKIE, ""),
        "now": _dt.datetime.now(_dt.timezone.utc),
        # The session payload (if any) is attached to the request by
        # a dependency in `dashboard.py`; routers also pass their own
        # context keys. This default prevents KeyError in the base
        # template when no user is authenticated (e.g., the login page).
        "session": None,
        "flash": None,
    }
    if context:
        ctx.update(context)
    tpl = _env.get_template(template)
    html = tpl.render(**ctx)
    return HTMLResponse(html, status_code=status_code)
