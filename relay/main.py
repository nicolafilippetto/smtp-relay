"""Relay entrypoint.

Responsibilities:
  1. Initialise the async SQLAlchemy engine (shared volume DB).
  2. Bootstrap WAL mode and wait for the UI to have run migrations
     (we retry a short loop before giving up).
  3. Start the aiosmtpd controller.
  4. Start the background queue worker.
  5. Start the periodic housekeeper (heartbeat + pruners + ban cleanup).
  6. Run until a SIGTERM / SIGINT, then shut down cleanly.

The UI runs `alembic upgrade head` at startup, so the schema is always
present by the time the relay boots. If the relay wins the race we back
off and retry.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
import signal
from contextlib import suppress

from aiosmtpd.controller import Controller
from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError

from common import admin_alerts, archive
from common.bans import prune_expired_bans, prune_old_attempts
from common.db import dispose_engine, enable_sqlite_wal, get_engine, session_scope
from common.models import (
    FailedAttempt,
    RelayHeartbeat,
    Settings,
)

from .queue_manager import QueueWorker, prune_sent
from .smtp_handler import (
    CaseInsensitiveAuthSMTP,
    RelayAuthenticator,
    RelayHandler,
    build_controller_kwargs,
)

_log = logging.getLogger("relay")


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

def _configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=level,
    )
    # aiosmtpd is chatty at DEBUG; keep it at the user-requested level.


# -----------------------------------------------------------------------------
# DB bootstrap
# -----------------------------------------------------------------------------

async def _wait_for_schema(max_attempts: int = 30, delay_s: float = 2.0) -> None:
    """Retry until the UI has run migrations and the `settings` table exists."""
    engine = get_engine()
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            await enable_sqlite_wal()
            async with session_scope() as session:
                await session.execute(select(Settings).limit(1))
            _log.info("Schema ready after %d attempt(s).", attempt)
            return
        except OperationalError as exc:
            last_exc = exc
            _log.info(
                "Schema not ready yet (attempt %d/%d); waiting %.1fs",
                attempt,
                max_attempts,
                delay_s,
            )
            await asyncio.sleep(delay_s)
    # Final attempt failed.
    raise RuntimeError(
        f"Schema not ready after {max_attempts} attempts; "
        f"last error: {last_exc}"
    )


async def _ensure_seed_rows() -> None:
    """Make sure the single-row config tables exist."""
    from common.models import Settings, TenantConfig  # local import

    async with session_scope() as session:
        settings = await session.scalar(select(Settings).where(Settings.id == 1))
        if settings is None:
            session.add(Settings(id=1))
        cfg = await session.scalar(select(TenantConfig).where(TenantConfig.id == 1))
        if cfg is None:
            session.add(TenantConfig(id=1))


# -----------------------------------------------------------------------------
# Heartbeat + housekeeping
# -----------------------------------------------------------------------------

def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


async def _heartbeat_loop(started_at: _dt.datetime, stop: asyncio.Event) -> None:
    interval = 10.0
    async with session_scope() as session:
        hb = await session.get(RelayHeartbeat, 1)
        if hb is None:
            hb = RelayHeartbeat(
                id=1, started_at=started_at, status="running"
            )
            session.add(hb)
        else:
            hb.started_at = started_at
            hb.status = "running"
            hb.last_error = None

    while not stop.is_set():
        try:
            async with session_scope() as session:
                hb = await session.get(RelayHeartbeat, 1)
                if hb is not None:
                    hb.last_seen_at = _utcnow()
                    hb.status = "running"
        except Exception as exc:
            _log.warning("heartbeat update failed: %s", exc)
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval)


async def _alert_loop(stop: asyncio.Event) -> None:
    """Tick every 60s.

    On each tick we run the realtime scanner; once per day at the
    configured time the digest is also sent. Both helpers update their
    own watermarks in the DB.
    """
    interval = 60.0

    # Initialise the realtime watermark to "now" so we don't fire alerts
    # on historical audit rows the first time the relay starts.
    try:
        async with session_scope() as session:
            settings = await session.scalar(
                select(Settings).where(Settings.id == 1)
            )
            if settings is not None and settings.alert_last_realtime_scan_at is None:
                settings.alert_last_realtime_scan_at = _utcnow()
    except Exception as exc:  # pragma: no cover - defensive
        _log.warning("alert loop init failed: %s", exc)

    while not stop.is_set():
        try:
            now = _utcnow()
            await admin_alerts.dispatch_realtime(now)
            await admin_alerts.dispatch_digest(now)
        except Exception as exc:  # pragma: no cover - defensive
            _log.exception("alert loop tick failed: %s", exc)
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval)


async def _pruner_loop(stop: asyncio.Event) -> None:
    interval = 3600.0  # hourly
    while not stop.is_set():
        try:
            async with session_scope() as session:
                settings = await session.scalar(
                    select(Settings).where(Settings.id == 1)
                )
                archive_days = settings.archive_retention_days if settings else 30
                audit_days = settings.audit_retention_days if settings else 90
                queue_days = (
                    settings.queue_sent_retention_days if settings else 30
                )
                ban_duration_min = (
                    settings.smtp_ban_duration_min if settings else 30
                )

            removed = archive.prune(archive_days)
            if removed:
                _log.info("Pruned %d archive files.", removed)

            # Audit log prune (floor enforced in the UI settings
            # saver; this is defense in depth: we still clamp here).
            from common.constants import AUDIT_RETENTION_MIN_DAYS

            effective_audit = max(audit_days, AUDIT_RETENTION_MIN_DAYS)
            cutoff = _utcnow() - _dt.timedelta(days=effective_audit)
            from common.models import AuditLog

            async with session_scope() as session:
                res = await session.execute(
                    delete(AuditLog).where(AuditLog.timestamp < cutoff)
                )
                if res.rowcount:
                    _log.info("Pruned %d audit rows.", res.rowcount)

            # Sent-queue prune.
            sent_pruned = await prune_sent(queue_days)
            if sent_pruned:
                _log.info("Pruned %d sent-queue rows.", sent_pruned)

            # Ban + failed-attempt table cleanup.
            async with session_scope() as session:
                await prune_expired_bans(session)
                await prune_old_attempts(
                    session, older_than_min=ban_duration_min * 2
                )

            # Rate-limit event cleanup.
            from .rate_limit import prune_old_events as prune_rate_events
            rate_pruned = await prune_rate_events()
            if rate_pruned:
                _log.info("Pruned %d rate-limit event rows.", rate_pruned)
        except Exception as exc:  # pragma: no cover - defensive
            _log.exception("pruner loop failed: %s", exc)

        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

async def _run() -> None:
    _configure_logging()
    started_at = _utcnow()
    stop = asyncio.Event()

    # Initialise engine (no connection yet).
    get_engine()

    await _wait_for_schema()
    await _ensure_seed_rows()

    # Build and start the SMTP controller.
    handler = RelayHandler(
        max_message_size=int(os.environ.get("SMTP_MAX_MESSAGE_SIZE", "31457280"))
    )
    authenticator = RelayAuthenticator()
    controller_kwargs = build_controller_kwargs()

    # Custom Controller that instantiates our SMTP subclass
    # (case-insensitive AUTH mechanism parsing). Without this, Windows
    # clients that send `AUTH login ...` (lowercase) get a 504 from
    # aiosmtpd 1.4.6 because its mechanism lookup is case-sensitive.
    class _Controller(Controller):
        def factory(self):
            return CaseInsensitiveAuthSMTP(self.handler, **self.SMTP_kwargs)

    controller = _Controller(
        handler,
        hostname=controller_kwargs["hostname"],
        port=controller_kwargs["port"],
        authenticator=authenticator,
        auth_required=False,  # whitelisted IPs skip AUTH; we gate in handlers
        auth_require_tls=False,  # caller-facing TLS is optional on internal LAN
    )
    controller.start()
    _log.info(
        "SMTP listener on %s:%s (max message size %d bytes)",
        controller_kwargs["hostname"],
        controller_kwargs["port"],
        controller_kwargs["max_size"],
    )

    # Background tasks.
    worker = QueueWorker(poll_interval_seconds=5.0)
    worker.start()
    hb_task = asyncio.create_task(_heartbeat_loop(started_at, stop), name="heartbeat")
    prune_task = asyncio.create_task(_pruner_loop(stop), name="pruner")
    alert_task = asyncio.create_task(_alert_loop(stop), name="alerts")

    # Signal handling.
    loop = asyncio.get_running_loop()

    def _handle_stop() -> None:
        _log.info("Stop signal received.")
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        with suppress(NotImplementedError):
            loop.add_signal_handler(sig, _handle_stop)

    try:
        await stop.wait()
    finally:
        _log.info("Shutting down...")
        # Controller.stop is synchronous; run it in a thread so we don't
        # block the event loop while asyncio is unwinding.
        await asyncio.to_thread(controller.stop)
        await worker.stop()
        hb_task.cancel()
        prune_task.cancel()
        alert_task.cancel()
        for t in (hb_task, prune_task, alert_task):
            with suppress(Exception):
                await t
        await dispose_engine()
        _log.info("Bye.")


def main() -> None:
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
