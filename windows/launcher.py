"""Native-Windows entry point for the SMTP Relay.

A single executable (``smtp-relay.exe``, built by ``windows/smtp-relay.spec``)
exposes every Windows-side action through a sub-command:

    smtp-relay.exe relay      # run the SMTP relay (aiosmtpd) — a Windows service
    smtp-relay.exe ui         # run the admin web UI (uvicorn on 127.0.0.1) — a service
    smtp-relay.exe migrate    # apply DB migrations + bootstrap the admin user (one-shot)
    smtp-relay.exe genkey     # print fresh ENCRYPTION_KEY / SECRET_KEY (used by install.ps1)

Why a launcher at all? Almost every module reads its configuration straight
from ``os.environ`` (``common.db`` -> DATABASE_URL, ``common.crypto`` ->
ENCRYPTION_KEY, ``common.archive`` -> ARCHIVE_PATH, ``ui.security`` ->
SECRET_KEY, ``relay.smtp_handler`` -> SMTP_LISTEN_*). On Windows there is no
docker-compose to inject those, so this launcher loads them from a
``config.env`` file into ``os.environ`` **before** any of those modules are
imported. That is why the heavy imports below are deliberately lazy (inside
the sub-command functions), never at module top level.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


# -----------------------------------------------------------------------------
# Install layout
# -----------------------------------------------------------------------------
# Everything mutable (DB, archive, logs, config.env) lives under one "home"
# directory. On Windows that defaults to C:\ProgramData\smtp-relay. The
# SMTP_RELAY_HOME env var overrides it (used by tests and for non-default
# installs); on non-Windows hosts it falls back to a local directory so the
# launcher can be smoke-tested from the Linux source tree.

APP_DIR_NAME = "smtp-relay"


def default_home() -> Path:
    override = os.environ.get("SMTP_RELAY_HOME", "").strip()
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / APP_DIR_NAME
    # Non-Windows fallback (development / smoke tests only).
    return Path.home() / ".local" / "share" / APP_DIR_NAME


def config_env_path(home: Path) -> Path:
    return home / "config.env"


# -----------------------------------------------------------------------------
# config.env loading
# -----------------------------------------------------------------------------

def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a minimal KEY=VALUE file (same shape as .env.example).

    Blank lines and ``#`` comments are ignored. Surrounding single/double
    quotes around a value are stripped. Lines without ``=`` are skipped.
    """
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if (len(value) >= 2) and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def load_config_env(home: Path) -> None:
    """Load config.env into os.environ.

    Keys already present in the real process environment win (so a value set
    on the Windows service definition overrides config.env). Missing file is
    not an error — ``genkey`` runs before the file exists, and defaults cover
    the rest.
    """
    path = config_env_path(home)
    if not path.is_file():
        return
    for key, value in _parse_env_file(path).items():
        os.environ.setdefault(key, value)


def apply_windows_defaults(home: Path) -> None:
    """Fill in DB/archive/SMTP defaults rooted under the home directory.

    Only sets a variable when it is not already defined (config.env or the
    service environment take precedence). The Linux default archive path
    (/data/archive) and the absence of a DATABASE_URL would otherwise break a
    native Windows run.
    """
    data_dir = home / "data"
    db_path = (data_dir / "relay.db").as_posix()  # forward slashes for the URL
    os.environ.setdefault(
        "DATABASE_URL", f"sqlite+aiosqlite:///{db_path}"
    )
    os.environ.setdefault("ARCHIVE_PATH", str(data_dir / "archive"))
    os.environ.setdefault("SMTP_LISTEN_HOST", "0.0.0.0")  # nosec B104 - LAN relay default; user-overridable
    os.environ.setdefault("SMTP_LISTEN_PORT", "2525")


def _ensure_data_dirs(home: Path) -> None:
    (home / "data" / "archive").mkdir(parents=True, exist_ok=True)


# -----------------------------------------------------------------------------
# Sub-commands
# -----------------------------------------------------------------------------

def cmd_genkey(_args: argparse.Namespace) -> int:
    """Print a fresh Fernet ENCRYPTION_KEY and a SECRET_KEY.

    Used by install.ps1 to populate config.env on first install without
    requiring a separate Python interpreter on PATH.
    """
    import secrets

    from cryptography.fernet import Fernet

    print(f"ENCRYPTION_KEY={Fernet.generate_key().decode('ascii')}")
    print(f"SECRET_KEY={secrets.token_urlsafe(64)}")
    return 0


def cmd_migrate(_args: argparse.Namespace) -> int:
    """Apply DB migrations then bootstrap the singleton rows + admin user."""
    from alembic import command
    from alembic.config import Config

    from common.resources import resource_path

    alembic_ini = resource_path("ui", "alembic.ini")
    script_location = resource_path("ui", "alembic")

    cfg = Config(str(alembic_ini))
    # The ini ships a *relative* script_location (ui/alembic) which does not
    # resolve from a frozen bundle's _MEIPASS; override with the absolute path.
    cfg.set_main_option("script_location", str(script_location))
    command.upgrade(cfg, "head")

    # Bootstrap (idempotent): create the singleton rows and, on a fresh DB,
    # the admin user with a one-time password printed to stdout.
    import ui.bootstrap

    ui.bootstrap.main()
    return 0


def cmd_relay(_args: argparse.Namespace) -> int:
    import relay.main

    relay.main.main()
    return 0


def cmd_ui(_args: argparse.Namespace) -> int:
    # LAN access is on by default: bind to all interfaces and let the
    # private-network guard reject anything that is not loopback/RFC1918, so an
    # accidental internet exposure still answers only to private clients. Set
    # SMTP_UI_ALLOW_LAN=0 to keep the panel strictly on loopback.
    allow_lan = os.environ.get("SMTP_UI_ALLOW_LAN", "1").strip().lower() not in (
        "0", "false", "no", "",
    )
    default_host = "0.0.0.0" if allow_lan else "127.0.0.1"  # nosec B104 - guarded by PrivateNetworkOnlyMiddleware
    host = os.environ.get("SMTP_UI_HOST", default_host)
    port = int(os.environ.get("SMTP_UI_PORT", "8000"))

    listens_beyond_loopback = host not in ("127.0.0.1", "::1", "localhost")

    # Keep panel.url in sync with the port we actually serve, so the tray and the
    # Start-Menu "Open admin panel" shortcut always point at the right port —
    # even when the user changed SMTP_UI_PORT in config.env by hand and restarted
    # the service. panel.url lives next to the install (the exe's grandparent
    # dir); the service runs as SYSTEM and can write there. Best-effort only.
    if getattr(sys, "frozen", False):
        try:
            panel_file = Path(sys.executable).resolve().parent.parent / "panel.url"
            panel_file.write_text(
                "[InternetShortcut]\nURL=http://127.0.0.1:%d\n" % port,
                encoding="ascii",
            )
        except Exception:
            pass

    # The native-Windows panel is plain HTTP. Browsers only send Secure cookies
    # over HTTPS (localhost excepted), so when we serve the LAN we must NOT mark
    # the session/CSRF cookies Secure — otherwise non-localhost clients lose
    # their cookie and every POST fails with "session expired". Set this BEFORE
    # importing ui.main, because get_settings() caches the value at import time.
    if listens_beyond_loopback:
        os.environ.setdefault("SMTP_UI_COOKIE_SECURE", "0")

    import uvicorn

    from common.resources import resource_path
    from ui.main import app
    from ui.middleware import PrivateNetworkOnlyMiddleware

    # Guard by client IP whenever we listen beyond loopback.
    if listens_beyond_loopback:
        app.add_middleware(PrivateNetworkOnlyMiddleware)

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_config=str(resource_path("ui", "log_config.json")),
        server_header=False,  # do not advertise the server software
        # No SSL and no proxy headers (no nginx on Windows). The real client IP
        # is the socket peer, which is exactly what the private-network guard
        # needs — so we must NOT trust X-Forwarded-* here.
    )
    uvicorn.Server(config).run()
    return 0


def cmd_tray(_args: argparse.Namespace) -> int:
    import windows.tray

    return windows.tray.main()


def cmd_reset_admin(_args: argparse.Namespace) -> int:
    """Reset the admin password (and clear its TOTP) interactively.

    Reuses the same mechanism as the Docker ADMIN_RESET flow, but without
    editing config.env: it prompts for a new password, sets the reset env vars
    in-process, and runs the bootstrap. The admin must change this password and
    re-enrol TOTP on the next login.
    """
    import getpass

    pw1 = getpass.getpass("New admin password (min 12 chars): ")
    pw2 = getpass.getpass("Confirm new password: ")
    if pw1 != pw2:
        print("Passwords do not match. Nothing changed.")
        return 1
    if len(pw1) < 12:
        print("Password must be at least 12 characters. Nothing changed.")
        return 1

    os.environ["ADMIN_RESET"] = "1"
    os.environ["ADMIN_NEW_PASSWORD"] = pw1

    import ui.bootstrap

    ui.bootstrap.main()
    print("")
    print("Admin password reset. Open http://127.0.0.1:8000 and log in as 'admin'")
    print("with the new password; you will be asked to change it and re-enrol TOTP.")
    return 0


# -----------------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smtp-relay",
        description="SMTP Relay — native Windows launcher.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("relay", help="run the SMTP relay service")
    sub.add_parser("ui", help="run the admin web UI (uvicorn, localhost)")
    sub.add_parser("migrate", help="apply DB migrations and bootstrap admin")
    sub.add_parser("genkey", help="print a fresh ENCRYPTION_KEY and SECRET_KEY")
    sub.add_parser("tray", help="run the system-tray status/controller")
    sub.add_parser("reset-admin", help="reset the admin password and clear its TOTP")
    return parser


_COMMANDS = {
    "relay": cmd_relay,
    "ui": cmd_ui,
    "migrate": cmd_migrate,
    "genkey": cmd_genkey,
    "tray": cmd_tray,
    "reset-admin": cmd_reset_admin,
}

# Commands that do not touch the database/config and so must not load config.env.
_NO_CONFIG_COMMANDS = {"genkey", "tray"}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Most commands load config.env and the Windows defaults into os.environ
    # *before* importing app modules. genkey/tray need none of that.
    if args.command not in _NO_CONFIG_COMMANDS:
        home = default_home()
        load_config_env(home)
        apply_windows_defaults(home)
        _ensure_data_dirs(home)

    return _COMMANDS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
