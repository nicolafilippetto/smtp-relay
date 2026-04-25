"""aiosmtpd handler classes.

Wiring:
  - `RelayAuthenticator` implements the authentication callback used
    by aiosmtpd's SMTP protocol. Returns AuthResult based on local
    credentials.
  - `RelayHandler` implements the HELO/MAIL/RCPT/DATA hooks. It
    enforces:
      * ban checks on HELO
      * IP whitelist bypass (no AUTH required when source_ip matches)
      * sender whitelist on MAIL FROM
      * size limit on DATA
      * enqueue on DATA accept

All DB work goes through the async session factory in common.db.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
from typing import Any

from aiosmtpd.smtp import (
    AuthResult,
    Envelope,
    LoginPassword,
    SMTP,
    Session,
)


class CaseInsensitiveAuthSMTP(SMTP):
    """SMTP protocol subclass that accepts case-insensitive AUTH mechanism.

    aiosmtpd 1.4.6's `smtp_AUTH` compares the mechanism name with a
    case-sensitive `in self._auth_methods` check, where the dict keys
    are uppercase. A client that sends `AUTH login ...` (as
    Send-MailMessage and SwithMail do on Windows) is rejected with
    504 even though RFC 5321 requires commands to be case-insensitive.

    Workaround: normalise the mechanism portion of the AUTH command
    to uppercase before delegating to the parent implementation.
    """

    async def smtp_AUTH(self, arg):  # type: ignore[override]
        if arg:
            parts = arg.split(None, 1)
            parts[0] = parts[0].upper()
            arg = " ".join(parts)
        return await super().smtp_AUTH(arg)

from common.audit import record as audit_record
from common.db import session_scope
from common.models import AuditEventType, AuditOutcome

from .auth import (
    ip_or_user_banned,
    is_ip_whitelisted,
    is_sender_authorised,
    verify_smtp_credentials,
)
from .queue_manager import enqueue

_log = logging.getLogger("relay.smtp")


def _peer_ip(session: Session) -> str | None:
    peer = getattr(session, "peer", None)
    if not peer:
        return None
    try:
        return peer[0]
    except (IndexError, TypeError):
        return None


class RelayAuthenticator:
    """Callable used by aiosmtpd for SMTP AUTH.

    IMPORTANT: aiosmtpd 1.4.6 invokes the authenticator SYNCHRONOUSLY
    from inside an `async` method (see SMTP._authenticate in
    aiosmtpd/smtp.py line ~1084). `__call__` must therefore be a plain
    `def`, not `async def` — an async callable would return a coroutine
    that aiosmtpd coerces to a truthy object and accepts as success.

    Our database checks are async, so we run them in a dedicated
    event loop on a worker thread. This is safe even though aiosmtpd's
    own loop is currently running: we never touch it, we spawn our
    own.
    """

    def __init__(self) -> None:
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="smtp-auth"
        )

    def __call__(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        mechanism: str,
        auth_data: Any,
    ) -> AuthResult:
        ip = _peer_ip(session)

        if not isinstance(auth_data, LoginPassword):
            _log.info("AUTH mech=%s rejected: unsupported auth type", mechanism)
            return AuthResult(success=False, message="Unsupported auth type.")

        try:
            username = auth_data.login.decode("utf-8", errors="replace")
            password = auth_data.password.decode("utf-8", errors="replace")
        except Exception:
            return AuthResult(success=False, message="Malformed credentials.")

        # Run the async DB work in a dedicated loop on a worker thread.
        # We block the calling (SMTP) thread for the duration but the
        # parent loop keeps servicing other connections — aiosmtpd's
        # handler pattern already expects the authenticator to block.
        future = self._executor.submit(
            _run_auth_check, ip, username, password
        )
        try:
            outcome = future.result(timeout=15)
        except Exception as exc:
            _log.exception("auth check crashed: %s", exc)
            return AuthResult(success=False, message="Authentication failed.")

        if outcome.ok:
            _log.info("AUTH user=%s ip=%s: success", username, ip)
            return AuthResult(success=True, handled=True, auth_data=username)
        _log.info("AUTH user=%s ip=%s: failure (%s)", username, ip, outcome.reason)
        return AuthResult(success=False, message="Authentication failed.")


def _run_auth_check(ip: str | None, username: str, password: str):
    """Run the async auth checks in a brand-new event loop (worker thread)."""
    return asyncio.run(_async_auth_check(ip, username, password))


async def _async_auth_check(ip: str | None, username: str, password: str):
    """Ban checks then credential verification."""
    from collections import namedtuple
    Outcome = namedtuple("Outcome", ["ok", "username", "reason"])
    if ip and await ip_or_user_banned(ip, None):
        return Outcome(False, None, "IP banned")
    if await ip_or_user_banned(ip, username):
        return Outcome(False, None, "User banned")
    return await verify_smtp_credentials(username, password, ip)


class RelayHandler:
    """aiosmtpd handler; one instance serves the lifetime of the process."""

    def __init__(self, *, max_message_size: int) -> None:
        self._max_size = max_message_size

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    async def handle_EHLO(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        hostname: str,
        responses: list[str],
    ) -> list[str]:
        # Gate on IP-level bans as early as possible.
        ip = _peer_ip(session)
        if ip and await ip_or_user_banned(ip, None):
            # Polite, not overly informative.
            await server.push("421 4.7.0 Connection refused.")
            raise RuntimeError("banned")
        session.host_name = hostname
        return responses

    async def handle_MAIL(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        mail_options: list[str],
    ) -> str:
        ip = _peer_ip(session)
        username = getattr(session, "auth_data", None)

        # Require auth OR a whitelist match.
        if not username and not await is_ip_whitelisted(ip or ""):
            return "530 5.7.0 Authentication required"

        if not await is_sender_authorised(address):
            async with session_scope() as s:
                await audit_record(
                    s,
                    event_type=AuditEventType.SMTP_RELAY_FAIL,
                    outcome=AuditOutcome.FAILURE,
                    source_ip=ip,
                    username=username,
                    details={"reason": "sender not authorised", "sender": address},
                )
            return "550 5.7.1 Sender not authorized"

        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        # Allow any recipient — Graph will enforce tenant-level rules.
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    async def handle_DATA(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
    ) -> str:
        ip = _peer_ip(session)
        username = getattr(session, "auth_data", None)

        raw = envelope.original_content or envelope.content or b""
        if not raw:
            return "554 5.6.0 Empty message"
        if self._max_size and len(raw) > self._max_size:
            return "552 5.3.4 Message too big"
        if not envelope.mail_from:
            return "554 5.5.1 No sender"
        if not envelope.rcpt_tos:
            return "554 5.5.1 No recipients"

        # Rate limit check: counts accepted DATAs in the sliding window.
        # If the cap is hit, refuse with 452 (temporary failure — well-
        # behaved clients will retry after a delay).
        from .rate_limit import check_and_record
        rate = await check_and_record(source_ip=ip, username=username)
        if not rate.allowed:
            _log.warning(
                "rate limit hit: %s (retry after %ds)",
                rate.reason, rate.retry_after_sec,
            )
            async with session_scope() as s:
                await audit_record(
                    s,
                    event_type=AuditEventType.SMTP_RELAY_FAIL,
                    outcome=AuditOutcome.FAILURE,
                    source_ip=ip,
                    username=username,
                    details={
                        "reason": "rate_limit_exceeded",
                        "detail": rate.reason,
                    },
                )
            return (
                f"452 4.7.1 Rate limit exceeded, "
                f"please retry in {rate.retry_after_sec}s"
            )

        try:
            qid = await enqueue(
                sender=envelope.mail_from,
                recipients=list(envelope.rcpt_tos),
                raw_mime=raw,
                source_ip=ip,
                source_username=username,
            )
        except Exception as exc:
            _log.exception("enqueue failed: %s", exc)
            return "451 4.3.0 Temporary failure"

        _log.info(
            "Queued mail id=%s from=%s rcpt=%d size=%d ip=%s user=%s",
            qid,
            envelope.mail_from,
            len(envelope.rcpt_tos),
            len(raw),
            ip or "-",
            username or "-",
        )
        return f"250 2.0.0 Queued as {qid}"

    # aiosmtpd will call this if an unhandled exception bubbles up.
    async def handle_exception(self, error: Exception) -> str:  # pragma: no cover
        _log.exception("SMTP handler error: %s", error)
        return "451 4.3.0 Temporary failure"


def build_controller_kwargs() -> dict[str, Any]:
    """Configuration used by the aiosmtpd Controller."""
    host = os.environ.get("SMTP_LISTEN_HOST", "0.0.0.0")  # nosec B104
    port = int(os.environ.get("SMTP_LISTEN_PORT", "2525"))
    max_size = int(os.environ.get("SMTP_MAX_MESSAGE_SIZE", "31457280"))
    return {
        "hostname": host,
        "port": port,
        "max_size": max_size,
    }
