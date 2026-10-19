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
import re
from email import message_from_bytes
from email.parser import BytesHeaderParser
from email.policy import compat32
from email.utils import getaddresses

from sqlalchemy import select, update

from common import archive
from common.audit import record as audit_record
from common.constants import QUEUE_BACKOFF_SECONDS, QUEUE_MAX_ATTEMPTS_DEFAULT
from common.db import session_scope
from common.graph_client import GraphClient, GraphError, credential_fingerprint
from common.routing import resolve_route
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
    app_id: int | None = None,
) -> int:
    """Persist one incoming message. Returns the new queue id.

    `app_id` is the enterprise app chosen at MAIL FROM; None leaves the
    choice to the worker (routed by sender domain at send time).
    """
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
            tenant_config_id=app_id,
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
# Envelope-only recipients (BCC)
# -----------------------------------------------------------------------------

# A bare addr-spec we are willing to write into a header: no whitespace,
# control characters or address-list/header syntax that could break out of
# the Bcc field. Anything else is skipped (and logged), never written.
_SAFE_ADDR = re.compile(r'^[^\s\x00-\x1f\x7f@<>,;:"()\[\]\\]+@[^\s\x00-\x1f\x7f@<>,;:"()\[\]\\]+$')
_BCC_FIELD = re.compile(rb"^bcc[ \t]*:", re.IGNORECASE)


def _split_headers(raw_mime: bytes) -> tuple[bytes, bytes]:
    """Split raw MIME into (header block, rest) at the first blank line.

    The header block keeps its trailing line ending; `rest` starts with the
    blank line, so `head + rest == raw_mime`.
    """
    candidates = [i for i in (raw_mime.find(b"\r\n\r\n"), raw_mime.find(b"\n\n")) if i >= 0]
    if not candidates:
        return raw_mime, b""
    cut = min(candidates)
    # Keep the header block's own final line ending with the headers.
    cut += 2 if raw_mime.startswith(b"\r\n", cut) else 1
    return raw_mime[:cut], raw_mime[cut:]


def with_envelope_bcc(raw_mime: bytes, recipients: list[str]) -> bytes:
    """Return `raw_mime` with envelope-only recipients added as a Bcc header.

    An SMTP client sends a blind copy by listing the address in RCPT TO and
    leaving it out of the headers. Graph's MIME sendMail takes recipients
    from the To/Cc/Bcc headers and has no notion of the SMTP envelope, so
    such addresses would be silently dropped. Every envelope recipient not
    already named in To/Cc/Bcc is therefore added to a single Bcc header
    (merged with any Bcc the client wrote); Exchange delivers to it and
    strips it from the copies recipients receive. The rest of the message
    is left byte-for-byte untouched.
    """
    head, rest = _split_headers(raw_mime)
    try:
        msg = BytesHeaderParser(policy=compat32).parsebytes(head)
        listed = getaddresses(
            [str(v) for name in ("To", "Cc", "Bcc") for v in (msg.get_all(name) or [])]
        )
        existing_bcc = [
            addr for _, addr in getaddresses([str(v) for v in (msg.get_all("Bcc") or [])])
        ]
    except Exception as exc:
        _log.warning("Could not parse headers to add BCC recipients: %s", exc)
        return raw_mime

    seen = {addr.casefold() for _, addr in listed if addr}
    missing: list[str] = []
    for rcpt in recipients:
        key = rcpt.casefold()
        if key in seen:
            continue
        seen.add(key)
        if _SAFE_ADDR.match(rcpt):
            missing.append(rcpt)
        else:
            _log.warning("Skipping envelope recipient unsafe for a Bcc header: %r", rcpt)
    if not missing:
        return raw_mime

    eol = b"\r\n" if b"\r\n" in head else b"\n"
    bcc = [a for a in existing_bcc if _SAFE_ADDR.match(a)] + missing

    # Drop any existing Bcc field (with its folded continuation lines) so the
    # result carries exactly one, as RFC 5322 requires.
    kept: list[bytes] = []
    skipping = False
    for line in head.splitlines(keepends=True):
        if line[:1] in (b" ", b"\t"):
            if not skipping:
                kept.append(line)
            continue
        skipping = bool(_BCC_FIELD.match(line))
        if not skipping:
            kept.append(line)

    field = b"Bcc: " + (b"," + eol + b" ").join(a.encode("utf-8") for a in bcc) + eol
    return field + b"".join(kept) + rest


# -----------------------------------------------------------------------------
# Startup recovery
# -----------------------------------------------------------------------------

async def recover_orphaned_sending() -> int:
    """Return rows stuck in SENDING back to PENDING. Returns the count.

    A row is left in SENDING only when the worker was interrupted
    mid-send: an ungraceful stop, a crash, or the shutdown cancel in
    ``QueueWorker.stop()``. Because ``_lease_one()`` only ever leases
    PENDING rows, such a row would otherwise never be retried and the
    mail would sit stranded forever. Run this once at startup, before
    the worker starts, so at-least-once delivery survives a restart.
    """
    now = _utcnow()
    async with session_scope() as session:
        res = await session.execute(
            update(MailQueue)
            .where(MailQueue.status == MailStatus.SENDING)
            .values(status=MailStatus.PENDING, next_attempt_at=now)
            .execution_options(synchronize_session=False)
        )
    count = res.rowcount or 0
    if count:
        _log.warning(
            "Recovered %d message(s) stranded in SENDING -> PENDING.", count
        )
    return count


# -----------------------------------------------------------------------------
# Background worker
# -----------------------------------------------------------------------------

class QueueWorker:
    """Polls the queue, sends due messages, applies backoff on failure."""

    def __init__(self, *, poll_interval_seconds: float = 5.0) -> None:
        self._poll = poll_interval_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # One cached GraphClient per enterprise app id, each rebuilt when
        # that app's credential changes.
        self._graph: dict[int, GraphClient] = {}

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

    async def _graph_client(self, app_id: int) -> GraphClient:
        """Return a cached GraphClient for enterprise app `app_id`.

        The client is rebuilt whenever the app's active credential changes —
        a secret rotation, a certificate activation, or a different tenant/
        client id — detected via `credential_fingerprint` without decrypting
        anything. Building happens inside the session so the row's encrypted
        material is still loaded.
        """
        async with session_scope() as session:
            cfg = await session.get(TenantConfig, app_id)
            if cfg is None:
                self._graph.pop(app_id, None)
                raise GraphError(
                    f"Enterprise app #{app_id} no longer exists."
                )
            if not cfg.tenant_id or not cfg.client_id:
                raise GraphError(
                    f"Enterprise app {cfg.name!r} is not configured. "
                    "Configure it in the UI before sending through it."
                )
            cached = self._graph.get(app_id)
            if cached is not None and cached.fingerprint == credential_fingerprint(cfg):
                return cached
            # Raises GraphError if the selected credential has no material.
            client = GraphClient.from_tenant_config(cfg)
            self._graph[app_id] = client
        return client

    async def _route_row(self, row_id: int, sender: str) -> int:
        """Pick (and remember) the app for a row queued without one."""
        async with session_scope() as session:
            route = await resolve_route(session, sender)
            if not route.ok:
                raise GraphError(
                    "No enterprise app for this sender: its domain is not "
                    "mapped and unmapped domains are refused."
                    if route.via == "unmapped"
                    else "No default enterprise app is configured."
                )
            row = await session.get(MailQueue, row_id)
            if row is not None:
                row.tenant_config_id = route.app.id
            return route.app.id

    async def _process(self, row_id: int) -> None:
        # 1. Load the row.
        async with session_scope() as session:
            row = await session.get(MailQueue, row_id)
            if row is None:
                return
            raw = base64.b64decode(row.raw_mime_b64.encode("ascii"))
            # Done at send time (not enqueue) so the stored message stays as
            # received, and rows queued before this fix also get their BCCs.
            raw = with_envelope_bcc(raw, json.loads(row.recipients_json or "[]"))
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
            app_id = row.tenant_config_id

        # 2. Try to send via Graph. Token acquisition errors + Graph
        # errors both surface as GraphError.
        graph_error: str | None = None
        graph_exc: GraphError | None = None
        try:
            if app_id is None:
                app_id = await self._route_row(row_id, sender)
            client = await self._graph_client(app_id)
            await asyncio.to_thread(client.send_mime, sender, raw)
        except GraphError as exc:
            graph_error = str(exc)
            graph_exc = exc
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
                # Success: write .eml, record archive path, mark SENT. The
                # archived copy is what Graph received, Bcc header included,
                # so the evidence (and an archive resend) keeps blind copies.
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
                    # The mail WAS delivered via Graph, so we must not
                    # retry (that would double-send). But the local
                    # archive/evidence copy is missing — surface it in
                    # the audit trail instead of only a log line. A
                    # dedicated event type keeps this out of the
                    # send-failure alert path.
                    _log.error(
                        "Archive write failed for id=%s (mail was sent): %s",
                        row.id,
                        exc,
                    )
                    await audit_record(
                        session,
                        event_type=AuditEventType.ARCHIVE_WRITE_FAIL,
                        outcome=AuditOutcome.FAILURE,
                        source_ip=source_ip,
                        username=source_username,
                        details={
                            "queue_id": row.id,
                            "sender": sender,
                            "error": str(exc)[:500],
                        },
                    )

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
                        "app_id": app_id,
                    },
                )

                # Refresh the tenant-config token metadata on success
                # so the dashboard reflects a healthy Graph connection.
                try:
                    info = client.acquire_token()
                    cfg = await session.get(TenantConfig, app_id)
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
            transient = graph_exc is not None and graph_exc.transient
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
                    "app_id": app_id,
                    "attempts": attempts,
                    "transient": transient,
                    "error": graph_error[:500],
                },
            )

            # Permanent failures burn the retry budget and go DEAD once
            # exhausted. Transient failures (throttling / 5xx / network)
            # are retried indefinitely so a Microsoft 365 outage never
            # silently drops mail.
            if not transient and attempts >= max_attempts:
                row.status = MailStatus.DEAD
                row.next_attempt_at = None
                _log.warning(
                    "Queue id=%s moved to DEAD after %d attempts: %s",
                    row.id,
                    attempts,
                    graph_error,
                )
                return

            # Schedule the next attempt. Honour a server-advised
            # Retry-After on throttling; otherwise use the backoff step.
            if (
                transient
                and graph_exc is not None
                and graph_exc.retry_after is not None
            ):
                delay = max(graph_exc.retry_after, QUEUE_BACKOFF_SECONDS[0])
            else:
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
