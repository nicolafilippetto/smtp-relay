# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the native-Windows SMTP Relay.

Builds a single ``smtp-relay.exe`` (onedir) that drives every Windows action
via a sub-command (see ``windows/launcher.py``). onedir — not onefile — keeps
startup fast, avoids per-run temp extraction (kinder to AV and to long-running
services), and gives the installer a stable folder to drop in place.

Run from the repository root:

    pyinstaller windows/smtp-relay.spec
"""

import os

from PyInstaller.utils.hooks import collect_submodules

# SPECPATH is injected by PyInstaller and points at this file's directory.
ROOT = os.path.dirname(SPECPATH)  # noqa: F821 (SPECPATH is provided by PyInstaller)


def _p(*parts):
    return os.path.join(ROOT, *parts)


# -----------------------------------------------------------------------------
# Bundled data files.
# -----------------------------------------------------------------------------
# (source_on_disk, destination_inside_bundle). The destination layout mirrors
# the source tree so ``common.resources.resource_path("ui", "templates")``
# resolves identically whether frozen or not. The alembic migration scripts
# are loaded *by filename* at runtime, so they ship as data, not as imports.
datas = [
    (_p("ui", "templates"), "ui/templates"),
    (_p("ui", "static"), "ui/static"),
    (_p("ui", "log_config.json"), "ui"),
    (_p("ui", "alembic.ini"), "ui"),
    (_p("ui", "alembic", "env.py"), "ui/alembic"),
    (_p("ui", "alembic", "script.py.mako"), "ui/alembic"),
    (_p("ui", "alembic", "versions"), "ui/alembic/versions"),
]

# -----------------------------------------------------------------------------
# Hidden imports.
# -----------------------------------------------------------------------------
# Modules resolved dynamically (by string) that static analysis misses:
#   - the aiosqlite SQLAlchemy dialect (loaded via the DATABASE_URL scheme)
#   - uvicorn's loop/http/websocket/lifespan implementations (chosen at runtime)
#   - aiosmtpd's controller/smtp submodules
hiddenimports = [
    "aiosqlite",
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.dialects.sqlite.aiosqlite",
    "aiosmtpd",
    "aiosmtpd.smtp",
    "aiosmtpd.controller",
    "msal",
    "httpx",
    # System-tray controller (lazy-imported by launcher's `tray` subcommand).
    "windows.tray",
    "pystray._win32",
    "PIL.Image",
    "PIL.ImageDraw",
]
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("pystray")

block_cipher = None

a = Analysis(
    [_p("windows", "launcher.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="smtp-relay",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,  # services run headless; console output is captured to logs
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="smtp-relay",
)
