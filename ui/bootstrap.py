"""One-shot bootstrap run by the UI container entrypoint.

Ordering:

    1. Ensure `settings` row with id=1 exists.
    2. Ensure `tenant_config` row with id=1 exists.
    3. If there is no admin user at all, create `admin` with a
       one-time random password and print it to the container log.
       The operator picks it up from `docker logs`.
    4. If ADMIN_RESET=1 and ADMIN_NEW_PASSWORD is set:
         - Reset the admin password
         - Clear any TOTP enrolment
         - Set must_change_password=True
         - Record an `admin_reset` audit event
       The README explains that these env vars must be unset and the
       container restarted before normal operation.

This script is idempotent and safe to re-run.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import sys

from sqlalchemy import select

from common.audit import record as audit_record
from common.db import dispose_engine, enable_sqlite_wal, get_engine, session_scope
from common.models import (
    AuditEventType,
    AuditOutcome,
    Settings,
    TenantConfig,
    User,
)
from common.passwords import hash_password

from .config import get_settings


_log = logging.getLogger("ui.bootstrap")


DEFAULT_ADMIN_USERNAME = "admin"


async def _ensure_singleton_rows() -> None:
    async with session_scope() as session:
        settings = await session.scalar(select(Settings).where(Settings.id == 1))
        if settings is None:
            session.add(Settings(id=1))
        cfg = await session.scalar(select(TenantConfig).where(TenantConfig.id == 1))
        if cfg is None:
            session.add(TenantConfig(id=1))


async def _ensure_admin_user() -> None:
    async with session_scope() as session:
        any_user = await session.scalar(select(User).limit(1))
        if any_user is not None:
            return
        # Generate a strong random password. The operator reads it from
        # the container logs and must rotate it on first login.
        generated = secrets.token_urlsafe(24)
        admin = User(
            username=DEFAULT_ADMIN_USERNAME,
            password_hash=hash_password(generated),
            must_change_password=True,
            is_active=True,
        )
        session.add(admin)
        _log.warning(
            "No admin user found. Created %r with temporary password:\n"
            "    %s\n"
            "Change it on first login; TOTP enrolment will also be "
            "enforced on that first login.",
            DEFAULT_ADMIN_USERNAME,
            generated,
        )


async def _apply_admin_reset() -> None:
    cfg = get_settings()
    if not cfg.admin_reset:
        return
    new_password = (cfg.admin_new_password or "").strip()
    if not new_password:
        _log.error(
            "ADMIN_RESET=1 but ADMIN_NEW_PASSWORD is empty. Refusing to reset."
        )
        return
    if len(new_password) < 12:
        _log.error(
            "ADMIN_RESET refused: ADMIN_NEW_PASSWORD must be at least 12 characters."
        )
        return

    async with session_scope() as session:
        admin = await session.scalar(
            select(User).where(User.username == DEFAULT_ADMIN_USERNAME)
        )
        if admin is None:
            admin = User(username=DEFAULT_ADMIN_USERNAME, password_hash="", is_active=True)
            session.add(admin)
            await session.flush()
        admin.password_hash = hash_password(new_password)
        admin.totp_secret = None
        admin.totp_enrolled_at = None
        admin.must_change_password = True
        admin.is_active = True

        await audit_record(
            session,
            event_type=AuditEventType.ADMIN_RESET,
            outcome=AuditOutcome.SUCCESS,
            username=DEFAULT_ADMIN_USERNAME,
            details={"reason": "ADMIN_RESET env var"},
        )

    _log.warning(
        "ADMIN_RESET applied: user %r password replaced and TOTP cleared. "
        "UNSET the ADMIN_RESET and ADMIN_NEW_PASSWORD environment variables "
        "and restart the container before resuming normal operation.",
        DEFAULT_ADMIN_USERNAME,
    )


async def _run() -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=logging.INFO,
    )
    get_engine()
    await enable_sqlite_wal()
    await _ensure_singleton_rows()
    await _ensure_admin_user()
    await _apply_admin_reset()
    await dispose_engine()


def main() -> None:
    try:
        asyncio.run(_run())
    except Exception as exc:
        _log.exception("bootstrap failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
