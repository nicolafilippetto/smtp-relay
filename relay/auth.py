"""SMTP authentication for the relay.

Two coexisting modes, both toggleable in Settings:

    A) Credentials (username+password) — bcrypt-verified against
       `smtp_accounts`.
    B) IP whitelist — CIDR entries in `ip_whitelist` get in without
       AUTH.

Bans are tracked per-IP and per-username independently, so an IP
hammering with one bad password won't lock out a legitimate user of
that username from a different host, and vice versa.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select

from common.audit import record as audit_record
from common.bans import is_banned, record_failure
from common.db import session_scope
from common.models import (
    AuditEventType,
    AuditOutcome,
    BanKind,
    BanScope,
    IpWhitelistEntry,
    Settings,
    SmtpAccount,
)
from common.netutils import ip_matches_any
from common.passwords import verify_password

_log = logging.getLogger("relay.auth")


@dataclass(slots=True)
class AuthOutcome:
    ok: bool
    username: str | None = None
    reason: str | None = None


async def is_ip_whitelisted(source_ip: str) -> bool:
    if not source_ip:
        return False
    async with session_scope() as session:
        settings = await session.scalar(select(Settings).where(Settings.id == 1))
        if settings is None or not settings.smtp_whitelist_enabled:
            return False
        cidrs = (
            await session.scalars(
                select(IpWhitelistEntry.cidr).where(
                    IpWhitelistEntry.is_enabled.is_(True)
                )
            )
        ).all()
    return ip_matches_any(source_ip, cidrs)


async def ip_or_user_banned(source_ip: str | None, username: str | None) -> bool:
    """True iff either the IP or the username is currently banned (SMTP kind)."""
    async with session_scope() as session:
        if source_ip:
            if await is_banned(
                session,
                kind=BanKind.SMTP,
                scope=BanScope.IP,
                value=source_ip,
            ):
                return True
        if username:
            if await is_banned(
                session,
                kind=BanKind.SMTP,
                scope=BanScope.USERNAME,
                value=username,
            ):
                return True
    return False


async def verify_smtp_credentials(
    username: str, password: str, source_ip: str | None
) -> AuthOutcome:
    """Verify SMTP credentials; record success/failure and bans.

    This function owns its own DB session and commits on exit.
    """
    if not username or not password:
        return AuthOutcome(ok=False, reason="Missing username or password.")

    async with session_scope() as session:
        settings = await session.scalar(select(Settings).where(Settings.id == 1))
        if settings is None or not settings.smtp_auth_local_enabled:
            # Mode A disabled -> refuse every AUTH attempt, regardless
            # of whether the credentials are valid.
            await audit_record(
                session,
                event_type=AuditEventType.SMTP_AUTH_FAIL,
                outcome=AuditOutcome.FAILURE,
                source_ip=source_ip,
                username=username,
                details={"reason": "local auth disabled"},
            )
            return AuthOutcome(ok=False, reason="Local SMTP auth is disabled.")

        threshold = settings.smtp_ban_threshold
        duration = settings.smtp_ban_duration_min

        account = await session.scalar(
            select(SmtpAccount).where(SmtpAccount.username == username)
        )

        ok = (
            account is not None
            and account.is_enabled
            and verify_password(password, account.password_hash)
        )

        if ok:
            # Per-account IP binding: if the account has a non-empty
            # `allowed_cidrs` list, the source IP MUST fall inside one
            # of those CIDRs, otherwise the login is refused despite
            # the password being correct. Checked AFTER the password
            # check so a wrong password and a wrong IP both look the
            # same to the client (no username enumeration).
            allowed = _parse_cidr_list(account.allowed_cidrs or "")
            if allowed:
                from common.netutils import ip_matches_any
                if not (source_ip and ip_matches_any(source_ip, allowed)):
                    await audit_record(
                        session,
                        event_type=AuditEventType.SMTP_AUTH_FAIL,
                        outcome=AuditOutcome.FAILURE,
                        source_ip=source_ip,
                        username=username,
                        details={
                            "reason": "ip_not_allowed_for_user",
                            "allowed_cidrs": allowed,
                        },
                    )
                    # Fall through to the failure-counting path below,
                    # just like a bad password.
                    ok = False

        if ok:
            await audit_record(
                session,
                event_type=AuditEventType.SMTP_AUTH_OK,
                outcome=AuditOutcome.SUCCESS,
                source_ip=source_ip,
                username=username,
            )
            return AuthOutcome(ok=True, username=username)

        # Record failure for both IP and username independently.
        banned_ip = banned_user = False
        if source_ip:
            banned_ip = await record_failure(
                session,
                kind=BanKind.SMTP,
                scope=BanScope.IP,
                value=source_ip,
                source_ip=source_ip,
                threshold=threshold,
                duration_min=duration,
                reason="Too many failed SMTP AUTH attempts",
            )
        banned_user = await record_failure(
            session,
            kind=BanKind.SMTP,
            scope=BanScope.USERNAME,
            value=username,
            source_ip=source_ip,
            threshold=threshold,
            duration_min=duration,
            reason="Too many failed SMTP AUTH attempts",
        )

        await audit_record(
            session,
            event_type=AuditEventType.SMTP_AUTH_FAIL,
            outcome=AuditOutcome.FAILURE,
            source_ip=source_ip,
            username=username,
            details={
                "reason": "invalid credentials",
                "banned_ip": banned_ip,
                "banned_user": banned_user,
            },
        )
        if banned_ip or banned_user:
            await audit_record(
                session,
                event_type=AuditEventType.USER_BAN,
                outcome=AuditOutcome.SUCCESS,
                source_ip=source_ip,
                username=username,
                details={"kind": "smtp", "ip": banned_ip, "user": banned_user},
            )
        return AuthOutcome(ok=False, reason="Invalid credentials.")


async def is_sender_authorised(sender: str) -> bool:
    """True iff `sender` is in the authorised-senders list (enabled)."""
    from common.models import AuthorisedSender  # local import to keep top clean

    if not sender:
        return False
    norm = sender.strip().lower()
    async with session_scope() as session:
        row = await session.scalar(
            select(AuthorisedSender).where(
                AuthorisedSender.is_enabled.is_(True),
                # store lowercased on insert; compare case-insensitively here too
                AuthorisedSender.address == norm,
            )
        )
    return row is not None


def _parse_cidr_list(text: str) -> list[str]:
    """Split `text` (newline- and/or comma-separated CIDRs) into a list.

    Returns an empty list if the input is blank — callers treat empty
    as "no restriction".
    """
    if not text:
        return []
    out: list[str] = []
    for chunk in text.replace(",", "\n").splitlines():
        c = chunk.strip()
        if c:
            out.append(c)
    return out
