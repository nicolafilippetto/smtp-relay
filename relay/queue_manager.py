"""Persistent mail queue and background sender.

Enqueues messages handed off by the aiosmtpd handler, then processes
them asynchronously. A separate asyncio task polls the queue at a
small interval, picks up rows whose `next_attempt_at` has passed, and
sends them through the Graph client.

Retry policy:

    attempt 1 failure -> +60 s
    attempt 2 failure -> +5 min
    attempt 3 failure -> +15 min (or the last configured step)
    attempts >= max    -> status = DEAD
"""

from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import json
import logging
from email import message_from_bytes
from email.policy import compat32

from sqlalchemy import select, update

from common import archive
from common.audit import record as audit_record
from common.constants import QUEUE_BACKOFF_SECONDS, QUEUE_MAX_ATTEMPTS_DEFAULT
from common.crypto import decrypt_str
from common.db import session_scope
from common.graph_client import GraphClient, GraphError
from common.models import (
    AuditEventType,
    AuditOutcome,
    MailQueue,
    MailStatus,
    Settings,
    TenantConfig,
)

_log = logging.getLogger("relay.queue")


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


# -----------------------------------------------------------------------------
# Enqueue
# -----------------------------------------------------------------------------

async def enqueue(
    *,
    sender: str,
    recipients: list[str],
    raw_mime: bytes,
    source_ip: str | None,
    source_username: str | None,
) -> int:
    """Persist one incoming message. Returns the new queue id."""
    subject = _extract_subject(raw_mime)
    encoded = base64.b64encode(raw_mime).decode("ascii")

    async with session_scope() as session:
        row = MailQueue(
            sender=sender,
            recipients_json=json.dumps(recipients),
            subject=subject,
            raw_mime_b64=encoded,
            status=MailStatus.PENDING,
            attempts=0,
            next_attempt_at=_utcnow(),
            source_ip=source_ip,
            source_username=source_username,
        )
        session.add(row)
        await session.flush()
        return row.id


def _extract_subject(raw_mime: bytes) -> str | None:
    try:
        msg = message_from_bytes(raw_mime, policy=compat32)
        subj = msg.get("Subject")
        if subj:
            return str(subj)[:998]
    except Exception:
        return None
    return None


# -----------------------------------------------------------------------------
# Background worker
# -----------------------------------------------------------------------------

class QueueWorker:
    """Polls the queue, sends due messages, applies backoff on failure."""

    def __init__(self, *, poll_interval_seconds: float = 5.0) -> None:
        self._poll = poll_interval_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # Cache a GraphClient per (tenant_id, client_id). Rebuilt when
        # the tenant config changes.
        self._graph: GraphClient | None = None

    # Lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="queue-worker")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except asyncio.TimeoutError:
                self._task.cancel()

    # Main loop ---------------------------------------------------------

    async def _run(self) -> None:
        _log.info("Queue worker started (poll=%.1fs)", self._poll)
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception as exc:  # pragma: no cover - defensive
                _log.exception("Queue worker tick failed: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._poll)
            except asyncio.TimeoutError:
                pass
        _log.info("Queue worker stopped.")

    async def _tick(self) -> None:
        # Pick one pending message at a time. Serialising keeps memory
        # bounded and makes Graph throttling easy to reason about.
        row_id = await self._lease_one()
        if row_id is None:
            return
        await self._process(row_id)

    async def _lease_one(self) -> int | None:
        """Transition one due PENDING row to SENDING; return its id."""
        now = _utcnow()
        async with session_scope() as session:
            stmt = (
                select(MailQueue)
                .where(
                    MailQueue.status == MailStatus.PENDING,
                    MailQueue.next_attempt_at <= now,
                )
                .order_by(MailQueue.next_attempt_at)
                .limit(1)
                .with_for_update(skip_locked=True)  # no-op on SQLite, fine
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None
            row.status = MailStatus.SENDING
            row.last_attempt = now
            await session.flush()
            return row.id

    # Per-message processing -------------------------------------------

    async def _graph_client(self) -> GraphClient:
        """Return a cached GraphClient for the currently-configured tenant."""
        async with session_scope() as session:
            cfg = await session.scalar(
                select(TenantConfig).where(TenantConfig.id == 1)
            )
            if (
                cfg is None
                or not cfg.tenant_id
                or not cfg.client_id
                or not cfg.client_secret_enc
            ):
                raise GraphError(
                    "Entra tenant configuration is missing. Configure it "
                    "in the UI before enabling the relay."
                )
            secret = decrypt_str(cfg.client_secret_enc)

        if self._graph is not None and self._graph.is_for(
            cfg.tenant_id, cfg.client_id
        ):
            return self._graph

        self._graph = GraphClient(cfg.tenant_id, cfg.client_id, secret)
        return self._graph

    async def _process(self, row_id: int) -> None:
        # 1. Load the row.
        async with session_scope() as session:
            row = await session.get(MailQueue, row_id)
            if row is None:
                return
            raw = base64.b64decode(row.raw_mime_b64.encode("ascii"))
            sender = row.sender
            subject = row.subject
            attempts = row.attempts + 1
            max_attempts = (
                await session.scalar(
                    select(Settings.queue_max_attempts).where(Settings.id == 1)
                )
                or QUEUE_MAX_ATTEMPTS_DEFAULT
            )
            source_ip = row.source_ip
            source_username = row.source_username

        # 2. Try to send via Graph. Token acquisition errors + Graph
        # errors both surface as GraphError.
        graph_error: str | None = None
        try:
            client = await self._graph_client()
            await asyncio.to_thread(client.send_mime, sender, raw)
        except GraphError as exc:
            graph_error = str(exc)
        except Exception as exc:
            graph_error = f"Unexpected error: {exc!r}"

        # 3. Record the result.
        now = _utcnow()
        async with session_scope() as session:
            row = await session.get(MailQueue, row_id)
            if row is None:
                return
            row.attempts = attempts
            row.last_attempt = now

            if graph_error is None:
                # Success: write .eml, record archive path, mark SENT.
                try:
                    path = await asyncio.to_thread(
                        archive.write_eml,
                        message_id=row.id,
                        subject=subject,
                        raw_mime=raw,
                        when=now,
                    )
                    row.archive_path = str(path)
                except Exception as exc:
                    _log.warning("Archive write failed for id=%s: %s", row.id, exc)

                row.status = MailStatus.SENT
                row.last_error = None
                row.next_attempt_at = None
                await audit_record(
                    session,
                    event_type=AuditEventType.SMTP_RELAY_OK,
                    outcome=AuditOutcome.SUCCESS,
                    source_ip=source_ip,
                    username=source_username,
                    details={
                        "queue_id": row.id,
                        "sender": sender,
                        "recipients": json.loads(row.recipients_json),
                    },
                )

                # Refresh the tenant-config token metadata on success
                # so the dashboard reflects a healthy Graph connection.
                try:
                    info = client.acquire_token()
                    cfg = await session.scalar(
                        select(TenantConfig).where(TenantConfig.id == 1)
                    )
                    if cfg is not None:
                        cfg.last_token_acquired_at = now
                        cfg.last_token_expires_at = info.expires_at.replace(
                            tzinfo=None
                        )
                except Exception:
                    # Don't let token metadata refresh break a successful send.
                    pass
                return

            # Failure path.
            row.last_error = graph_error[:4000]
            await audit_record(
                session,
                event_type=AuditEventType.SMTP_RELAY_FAIL,
                outcome=AuditOutcome.FAILURE,
                source_ip=source_ip,
                username=source_username,
                details={
                    "queue_id": row.id,
                    "sender": sender,
                    "attempts": attempts,
                    "error": graph_error[:500],
                },
            )

            if attempts >= max_attempts:
                row.status = MailStatus.DEAD
                row.next_attempt_at = None
                _log.warning(
                    "Queue id=%s moved to DEAD after %d attempts: %s",
                    row.id,
                    attempts,
                    graph_error,
                )
                return

            # Schedule the next attempt.
            step_idx = min(attempts - 1, len(QUEUE_BACKOFF_SECONDS) - 1)
            delay = QUEUE_BACKOFF_SECONDS[step_idx]
            row.status = MailStatus.PENDING
            row.next_attempt_at = now + _dt.timedelta(seconds=delay)


# -----------------------------------------------------------------------------
# Manual retries (invoked by the UI when an operator clicks "retry")
# -----------------------------------------------------------------------------

async def requeue_row(row_id: int, *, reset_attempts: bool = False) -> bool:
    """Move a DEAD or FAILED row back to PENDING with next_attempt_at=now."""
    now = _utcnow()
    async with session_scope() as session:
        row = await session.get(MailQueue, row_id)
        if row is None:
            return False
        row.status = MailStatus.PENDING
        row.next_attempt_at = now
        row.last_error = None
        if reset_attempts:
            row.attempts = 0
        await audit_record(
            session,
            event_type=AuditEventType.QUEUE_RETRY,
            outcome=AuditOutcome.SUCCESS,
            username=None,
            details={"queue_id": row_id, "reset_attempts": reset_attempts},
        )
    return True


async def requeue_all_dead() -> int:
    """Move every DEAD row back to PENDING. Returns how many rows were touched."""
    now = _utcnow()
    async with session_scope() as session:
        stmt = (
            update(MailQueue)
            .where(MailQueue.status == MailStatus.DEAD)
            .values(status=MailStatus.PENDING, next_attempt_at=now, last_error=None)
            .execution_options(synchronize_session=False)
        )
        res = await session.execute(stmt)
        await audit_record(
            session,
            event_type=AuditEventType.QUEUE_RETRY,
            outcome=AuditOutcome.SUCCESS,
            username=None,
            details={"scope": "all_dead", "count": res.rowcount or 0},
        )
    return res.rowcount or 0


async def prune_sent(retention_days: int) -> int:
    """Delete SENT rows older than retention. DEAD rows are kept."""
    if retention_days is None or retention_days < 1:
        retention_days = 30
    cutoff = _utcnow() - _dt.timedelta(days=retention_days)
    from sqlalchemy import delete  # local to keep top tidy

    async with session_scope() as session:
        res = await session.execute(
            delete(MailQueue).where(
                MailQueue.status == MailStatus.SENT,
                MailQueue.timestamp_received < cutoff,
            )
        )
    return res.rowcount or 0
