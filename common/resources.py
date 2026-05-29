"""Resource-path resolution that works both in-source and when frozen.

The project is normally run straight from the source tree (Docker, local
``python -m ...``). It is *also* packaged into a single Windows executable
with PyInstaller (see ``windows/``). A frozen PyInstaller bundle unpacks its
data files under ``sys._MEIPASS`` instead of next to the ``.py`` files, so any
code that locates a bundled asset (Jinja2 templates, static files, the alembic
migration scripts, the uvicorn log config) must go through here.

In source mode the base directory is the repository root (the parent of the
``common`` package), so ``resource_path("ui", "templates")`` resolves to the
exact same place as the old ``Path(__file__).parent / "templates"`` did. This
keeps Docker and local runs behaving identically — the helper is a no-op there.
"""

from __future__ import annotations

import sys
from pathlib import Path


def resource_base() -> Path:
    """Return the directory that bundled resources are rooted at."""
    if getattr(sys, "frozen", False):
        # PyInstaller extracts datas under this temp dir (onedir: the app
        # folder; onefile: a per-run temp dir). ``_MEIPASS`` covers both.
        return Path(getattr(sys, "_MEIPASS"))
    # Source tree: repo root == parent of the ``common`` package directory.
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str) -> Path:
    """Join ``parts`` onto the resource base directory."""
    return resource_base().joinpath(*parts)
