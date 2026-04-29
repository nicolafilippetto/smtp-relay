"""Admin alert dispatcher.

Two flows:

1. **Real-time** — every minute the relay scans `audit_log` for rows
   newer than `Settings.alert_last_realtime_scan_at` whose event type
   maps to a configured alert, builds a single email per scan, then
   advances the watermark. Discrete events: ban, admin reset, admin
   password change, SMTP account password change.

2. **Daily digest** — once per day at `Settings.alert_daily_time` the
   relay assembles all currently-true continuous conditions (secret
   expiry, dead queue, relay down, etc.) and sends them as one mail.
   The send is gated by `Settings.alert_last_digest_at` so a long-
   running relay never doubles up.

Both flows share `_send_mail()`, which builds an RFC 5322 message and
delivers it through the configured Graph tenant. Failures are recorded
in the audit log and never raise — alerts are best-effort.

Tests: covered by integration tests against a fake Graph endpoint;
unit tests focus on the digest section assembly because that is the
only piece with non-trivial branching.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import html as _html
import json
import logging
import re
from dataclasses import dataclass
import email.policy
from email.message import EmailMessage
from email.utils import formataddr

from sqlalchemy import func, select

from . import archive
from .audit import record as audit_record
from .crypto import decrypt_str
from .db import session_scope
from .graph_client import GraphClient, GraphError
from .models import (
    AuditEventType,
    AuditLog,
    AuditOutcome,
    AuthorisedSender,
    MailQueue,
    MailStatus,
    RelayHeartbeat,
    Settings,
    TenantConfig,
)


_log = logging.getLogger("admin_alerts")


# =============================================================================
# Continuous conditions for the daily digest
# =============================================================================

@dataclass(slots=True)
class DigestSection:
    title: str
    body: str
    severity: str  # "info" | "warn" | "err"
    # Optional secondary line shown under the title in the HTML render
    # (e.g. timestamp + actor for real-time events). Plain-text rendering
    # places it on its own line below the title.
    meta: str | None = None


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def _today_utc() -> _dt.date:
    return _utcnow().date()


def secret_expiry_section(
    tenant: TenantConfig | None,
    today: _dt.date,
    threshold_days: int,
) -> DigestSection | None:
    """Return a section if the secret is within the warning window or past due."""
    if tenant is None or tenant.secret_expires_at is None:
        return None
    days = (tenant.secret_expires_at - today).days
    if days > threshold_days:
        return None
    if days < 0:
        return DigestSection(
            title="Azure AD client secret EXPIRED",
            body=(
                f"The configured expiry date for the Azure AD client secret "
                f"({tenant.secret_expires_at.isoformat()}) is in the past "
                f"({-days} day(s) ago).\n\n"
                f"Either the secret has actually expired and outbound mail is "
                f"failing, or you rotated the secret without updating the date "
                f"on the Tenant page. Verify and either update the date or "
                f"rotate the secret in the Azure portal.\n"
            ),
            severity="err",
        )
    if days == 0:
        return DigestSection(
            title="Azure AD client secret expires TODAY",
            body=(
                f"The configured expiry date for the Azure AD client secret "
                f"is today ({tenant.secret_expires_at.isoformat()}). Rotate "
                f"the secret in the Azure portal and update the date on the "
                f"Tenant page.\n"
            ),
            severity="err",
        )
    return DigestSection(
        title=f"Azure AD client secret expires in {days} day(s)",
        body=(
            f"The configured expiry date for the Azure AD client secret is "
            f"{tenant.secret_expires_at.isoformat()} ({days} day(s) from "
            f"today). Plan the rotation; once rotated, update the expiry "
            f"date on the Tenant page.\n"
        ),
        severity="warn",
    )


async def _dead_queue_section(s) -> DigestSection | None:
    n = await s.scalar(
        select(func.count(MailQueue.id)).where(
            MailQueue.status == MailStatus.DEAD
        )
    )
    if not n:
        return None
    return DigestSection(
        title=f"{n} mail(s) in DEAD queue",
        body=(
            f"{n} message(s) have exhausted their retry budget and are "
            f"sitting in the DEAD state. Review them on the Queue page "
            f"and either requeue or discard.\n"
        ),
        severity="warn",
    )


async def _relay_down_section(s, now: _dt.datetime) -> DigestSection | None:
    hb = await s.get(RelayHeartbeat, 1)
    if hb is None:
        return DigestSection(
            title="Relay never started",
            body="No heartbeat row found. The relay process appears to have "
                 "never started.\n",
            severity="err",
        )
    lag = (now - hb.last_seen_at).total_seconds()
    if lag <= 60 and hb.status != "error":
        return None
    if hb.status == "error":
        return DigestSection(
            title="Relay reports error state",
            body=f"Last error: {hb.last_error or '(none)'}\n",
            severity="err",
        )
    return DigestSection(
        title="Relay heartbeat stale",
        body=(
            f"Last heartbeat was {int(lag)} second(s) ago "
            f"(at {hb.last_seen_at.isoformat()} UTC). The relay process "
            f"is presumed down.\n"
        ),
        severity="err",
    )


async def _graph_test_failed_section(s) -> DigestSection | None:
    cfg = await s.get(TenantConfig, 1)
    if cfg is None or cfg.last_test_ok is not False:
        return None
    return DigestSection(
        title="Last Graph connection test failed",
        body=(
            f"Last test at {cfg.last_test_at.isoformat() if cfg.last_test_at else '?'} UTC.\n"
            f"Error: {cfg.last_test_error or '(none)'}\n"
        ),
        severity="err",
    )


def _disk_usage_section() -> DigestSection | None:
    used = archive.archive_disk_usage_bytes()
    total = _volume_total_bytes("/data")
    if not total:
        return None
    pct = used / total * 100
    if pct < 80:
        return None
    return DigestSection(
        title=f"Archive volume at {pct:.0f}% capacity",
        body=(
            f"Used: {used} bytes / Total: {total} bytes.\n"
            f"Increase retention reduction or expand the volume.\n"
        ),
        severity="warn",
    )


async def _send_failures_section(s, now: _dt.datetime) -> DigestSection | None:
    cutoff = now - _dt.timedelta(hours=24)
    n = await s.scalar(
        select(func.count(AuditLog.id)).where(
            AuditLog.timestamp >= cutoff,
            AuditLog.event_type == AuditEventType.SMTP_RELAY_FAIL,
        )
    )
    if not n or n < 5:
        return None
    return DigestSection(
        title=f"{n} mail send failure(s) in the last 24h",
        body=(
            "Sustained Graph send failures usually mean the client secret "
            "has expired, the app permissions were revoked, or Graph is "
            "throttling. Check the Audit page and the Tenant test.\n"
        ),
        severity="warn",
    )


async def _failed_login_spike_section(s, now: _dt.datetime) -> DigestSection | None:
    cutoff = now - _dt.timedelta(hours=24)
    n = await s.scalar(
        select(func.count(AuditLog.id)).where(
            AuditLog.timestamp >= cutoff,
            AuditLog.event_type.in_(
                [
                    AuditEventType.LOGIN_FAIL,
                    AuditEventType.TOTP_FAIL,
                    AuditEventType.SMTP_AUTH_FAIL,
                ]
            ),
        )
    )
    if not n or n < 10:
        return None
    return DigestSection(
        title=f"{n} failed authentication attempt(s) in the last 24h",
        body=(
            "Possible brute-force activity. Review the Audit page; "
            "consider lowering the ban threshold or adding the offending "
            "IPs to the deny set if the bans are not catching them.\n"
        ),
        severity="warn",
    )


def _volume_total_bytes(path: str) -> int:
    import os
    try:
        st = os.statvfs(path)
        return st.f_blocks * st.f_frsize
    except OSError:
        return 0


# =============================================================================
# Real-time scanner
# =============================================================================

async def collect_realtime_events(
    s,
    settings: Settings,
    now: _dt.datetime,
) -> list[tuple[AuditLog, str]]:
    """Return audit rows of interest emitted since the last scan watermark.

    Each tuple is (row, alert_kind) where alert_kind is one of:
      "user_ban", "admin_reset", "admin_password_change",
      "smtp_password_change".
    """
    since = settings.alert_last_realtime_scan_at or now
    rows = (
        await s.scalars(
            select(AuditLog)
            .where(AuditLog.timestamp > since, AuditLog.timestamp <= now)
            .order_by(AuditLog.timestamp)
        )
    ).all()

    out: list[tuple[AuditLog, str]] = []
    for row in rows:
        kind = _classify_realtime(row, settings)
        if kind is not None:
            out.append((row, kind))
    return out


def _classify_realtime(row: AuditLog, settings: Settings) -> str | None:
    et = row.event_type
    if et == AuditEventType.USER_BAN and settings.alert_user_banned:
        return "user_ban"
    if et == AuditEventType.ADMIN_RESET and settings.alert_admin_reset:
        return "admin_reset"
    if et != AuditEventType.CONFIG_CHANGE:
        return None
    details = _parse_details(row.details_json)
    section = details.get("section")
    action = details.get("action")
    if section == "users" and action == "reset_password" and settings.alert_admin_password_change:
        return "admin_password_change"
    if section == "account" and action == "change_password" and settings.alert_admin_password_change:
        return "admin_password_change"
    if section == "smtp_accounts" and action == "edit" and details.get("password_changed") and settings.alert_smtp_password_change:
        return "smtp_password_change"
    return None


def _parse_details(blob: str | None) -> dict:
    if not blob:
        return {}
    try:
        v = json.loads(blob)
        return v if isinstance(v, dict) else {}
    except (TypeError, ValueError):
        return {}


def realtime_summary(
    events: list[tuple[AuditLog, str]],
) -> tuple[str, str, list[DigestSection]]:
    """Build (subject, category, sections) for a real-time alert email."""
    sections = [_event_section(row, kind) for row, kind in events]
    if len(sections) == 1:
        subject = f"[smtp-relay] {sections[0].title}"
        category = "Real-time alert"
    else:
        subject = f"[smtp-relay] {len(sections)} alert event(s)"
        category = "Real-time alerts"
    return subject, category, sections


def _kind_title(kind: str) -> str:
    return {
        "user_ban": "User or IP banned",
        "admin_reset": "Admin password reset (env var)",
        "admin_password_change": "Admin password changed",
        "smtp_password_change": "SMTP account password changed",
    }.get(kind, kind)


def _event_severity(kind: str) -> str:
    # admin_reset is the strongest security signal of the lot; bans
    # and password changes are warnings-by-default.
    if kind == "admin_reset":
        return "err"
    return "warn"


def _event_section(row: AuditLog, kind: str) -> DigestSection:
    details = _parse_details(row.details_json)
    when = row.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    src = []
    if row.username:
        src.append(f"by {row.username}")
    if row.source_ip:
        src.append(f"from {row.source_ip}")
    meta = f"{when} UTC" + (" · " + " ".join(src) if src else "")

    if kind == "user_ban":
        # The audit detail shape varies (relay vs UI auth); cover both.
        kind_v = details.get("kind") or "?"
        banned_ip = details.get("ip") or details.get("banned_ip") or ""
        banned_user = details.get("user") or details.get("banned_user") or ""
        if not banned_ip and not banned_user:
            banned_ip = row.source_ip or ""
            banned_user = row.username or ""
        targets = []
        if banned_ip:
            targets.append(f"ip={banned_ip}")
        if banned_user:
            targets.append(f"user={banned_user}")
        body = f"Ban issued (source={kind_v})"
        if targets:
            body += " for " + ", ".join(targets)
        body += "."
    elif kind == "admin_reset":
        body = (
            "An ADMIN_RESET was applied via environment variables on "
            "relay/UI startup. If you did not initiate this reset, treat "
            "it as a security incident."
        )
    elif kind == "admin_password_change":
        target = details.get("target_username") or "(self)"
        body = f"Admin password changed for user {target}."
    elif kind == "smtp_password_change":
        target = details.get("username") or "?"
        body = f"SMTP account password changed for {target}."
    else:
        body = row.details_json or ""

    return DigestSection(
        title=_kind_title(kind),
        body=body,
        severity=_event_severity(kind),
        meta=meta,
    )


# =============================================================================
# Sending
# =============================================================================

async def _build_graph_client() -> GraphClient | None:
    """Return a GraphClient using the saved tenant config, or None if unconfigured."""
    async with session_scope() as s:
        cfg = await s.get(TenantConfig, 1)
        if (
            cfg is None
            or not cfg.tenant_id
            or not cfg.client_id
            or not cfg.client_secret_enc
        ):
            return None
        secret = decrypt_str(cfg.client_secret_enc)
    return GraphClient(cfg.tenant_id, cfg.client_id, secret)


async def _sender_is_authorised(s, address: str) -> bool:
    if not address:
        return False
    row = await s.scalar(
        select(AuthorisedSender).where(
            AuthorisedSender.address == address.lower()
        )
    )
    return bool(row and row.is_enabled)


async def _audit_send_failure(reason: str) -> None:
    async with session_scope() as s:
        await audit_record(
            s,
            event_type=AuditEventType.CONFIG_CHANGE,
            outcome=AuditOutcome.FAILURE,
            username=None,
            details={
                "section": "notifications",
                "action": "alert_send_failed",
                "reason": reason[:500],
            },
        )


# -----------------------------------------------------------------------------
# Mail rendering
# -----------------------------------------------------------------------------

_SEVERITY_COLOR = {
    "info": "#0969da",
    "warn": "#bf8700",
    "err": "#cf222e",
}
_SEVERITY_BG = {
    "info": "#ddf4ff",
    "warn": "#fff8c5",
    "err": "#ffebe9",
}
_SEVERITY_LABEL = {
    "info": "INFO",
    "warn": "WARNING",
    "err": "ALERT",
}


def _render_text(category: str, sections: list[DigestSection], now: _dt.datetime) -> str:
    """Plain-text body — used as the fallback alternative."""
    lines: list[str] = [f"smtp-relay · {category}", "=" * 60, ""]
    for sec in sections:
        lines.append(f"[{_SEVERITY_LABEL.get(sec.severity, sec.severity.upper())}] {sec.title}")
        if sec.meta:
            lines.append(sec.meta)
        lines.append("-" * 60)
        lines.append(sec.body.rstrip())
        lines.append("")
    lines.append(f"Sent at {now.strftime('%Y-%m-%d %H:%M:%S')} UTC by smtp-relay")
    return "\n".join(lines) + "\n"


def _render_html(category: str, sections: list[DigestSection], now: _dt.datetime) -> str:
    """HTML body — inline styles, table-based layout for mail-client compat."""
    rows: list[str] = []
    for i, sec in enumerate(sections):
        color = _SEVERITY_COLOR.get(sec.severity, "#656d76")
        bg = _SEVERITY_BG.get(sec.severity, "#f6f8fa")
        label = _SEVERITY_LABEL.get(sec.severity, sec.severity.upper())
        border_top = (
            "border-top:1px solid #d0d7de;"
            if i > 0 else ""
        )
        meta_html = (
            f'<div style="font-size:12px;color:#656d76;margin:0 0 10px;">'
            f"{_html.escape(sec.meta)}</div>"
            if sec.meta else ""
        )
        body_html = _html.escape(sec.body.rstrip()).replace("\n", "<br>")
        rows.append(
            f"""
            <tr><td style="padding:18px 24px;{border_top}">
              <div style="display:inline-block;font-size:11px;font-weight:700;
                          letter-spacing:.6px;color:{color};background:{bg};
                          padding:2px 8px;border-radius:4px;margin-bottom:8px;">
                {label}
              </div>
              <div style="font-size:16px;font-weight:600;color:#1f2328;
                          margin:0 0 6px;">{_html.escape(sec.title)}</div>
              {meta_html}
              <div style="font-size:14px;line-height:1.55;color:#1f2328;">
                {body_html}
              </div>
            </td></tr>
            """.strip()
        )

    return f"""<!doctype html>
<html><body style="margin:0;padding:0;background:#f6f8fa;
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,
  Helvetica,Arial,sans-serif;color:#1f2328;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0"
         style="background:#f6f8fa;padding:24px 12px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" border="0"
             style="max-width:600px;background:#ffffff;border-radius:8px;
                    overflow:hidden;border:1px solid #d0d7de;">
        <tr><td style="background:#1f2328;color:#ffffff;
                       padding:16px 24px;font-size:13px;font-weight:600;
                       letter-spacing:.5px;">
          smtp-relay
          <span style="opacity:.6;margin:0 6px;">·</span>
          {_html.escape(category)}
        </td></tr>
        {''.join(rows)}
        <tr><td style="background:#f6f8fa;color:#656d76;
                       padding:12px 24px;font-size:11px;text-align:center;
                       border-top:1px solid #d0d7de;">
          Sent at {now.strftime('%Y-%m-%d %H:%M:%S')} UTC by smtp-relay
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""


# -----------------------------------------------------------------------------
# Sending
# -----------------------------------------------------------------------------

def _format_from(address: str, display_name: str | None) -> str:
    """Return RFC 5322 From header value, with display name when set."""
    name = (display_name or "").strip()
    if not name:
        return address
    return formataddr((name, address))


async def send_mail(
    *,
    sender_addr: str,
    sender_name: str | None,
    recipient: str,
    subject: str,
    category: str,
    sections: list[DigestSection],
    now: _dt.datetime | None = None,
) -> bool:
    """Send a multipart (text + HTML) alert via Graph. Returns True on success."""
    when = now or _utcnow()
    text = _render_text(category, sections, when)
    html = _render_html(category, sections, when)

    msg = EmailMessage()
    msg["From"] = _format_from(sender_addr, sender_name)
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    raw = msg.as_bytes(policy=email.policy.SMTP)

    client = await _build_graph_client()
    if client is None:
        await _audit_send_failure("Tenant configuration is incomplete.")
        return False
    try:
        # Graph's sendMail uses the bare address as the path segment;
        # the display name only lives in the MIME header.
        await asyncio.to_thread(client.send_mime, sender_addr, raw)
        return True
    except GraphError as exc:
        _log.warning("Admin alert send failed: %s", exc)
        await _audit_send_failure(str(exc))
        return False
    except Exception as exc:  # pragma: no cover - defensive
        _log.exception("Admin alert send failed unexpectedly")
        await _audit_send_failure(f"Unexpected error: {exc!r}")
        return False


async def can_send(settings: Settings) -> tuple[bool, str | None]:
    """Cheap pre-flight: are recipient/sender configured and sender authorised?"""
    if not settings.admin_email_to:
        return False, "admin_email_to is not set"
    if not settings.admin_email_from:
        return False, "admin_email_from is not set"
    async with session_scope() as s:
        if not await _sender_is_authorised(s, settings.admin_email_from):
            return False, (
                f"Sender {settings.admin_email_from!r} is not in the enabled "
                "Authorised Senders list."
            )
    return True, None


# =============================================================================
# Public dispatcher entry points
# =============================================================================

async def dispatch_realtime(now: _dt.datetime) -> int:
    """Find new realtime events and send a single email if any. Updates watermark.

    Returns the number of events covered.
    """
    async with session_scope() as s:
        settings = await s.get(Settings, 1)
        if settings is None:
            return 0
        events = await collect_realtime_events(s, settings, now)
        # Always advance the watermark — even on send failure — so we don't
        # spam the same events forever. Audit-log captures the failure.
        settings.alert_last_realtime_scan_at = now

    if not events:
        return 0

    ok, why = await can_send(await _reload_settings())
    if not ok:
        _log.info("Realtime alerts not sent (%s); %d event(s) skipped.", why, len(events))
        return 0

    settings = await _reload_settings()
    subject, category, sections = realtime_summary(events)
    await send_mail(
        sender_addr=settings.admin_email_from,
        sender_name=settings.admin_email_from_name,
        recipient=settings.admin_email_to,
        subject=subject,
        category=category,
        sections=sections,
        now=now,
    )
    return len(events)


async def dispatch_digest(now: _dt.datetime) -> bool:
    """Send the daily digest if it's the configured time and not already sent today.

    Returns True if a mail was sent.
    """
    today = now.date()
    async with session_scope() as s:
        settings = await s.get(Settings, 1)
        if settings is None:
            return False
        if settings.alert_last_digest_at == today:
            return False
        if not _is_digest_time(settings.alert_daily_time, now):
            return False

    sections = await _collect_digest_sections(now)
    # Mark today as sent regardless of whether we have sections — that
    # prevents the loop from re-checking every minute. If there's nothing
    # to report, no mail goes out.
    async with session_scope() as s:
        settings = await s.get(Settings, 1)
        if settings is not None:
            settings.alert_last_digest_at = today

    if not sections:
        return False

    settings = await _reload_settings()
    ok, why = await can_send(settings)
    if not ok:
        _log.info("Digest not sent (%s); %d section(s) suppressed.", why, len(sections))
        return False

    subject = f"[smtp-relay] Daily alert digest — {len(sections)} item(s)"
    return await send_mail(
        sender_addr=settings.admin_email_from,
        sender_name=settings.admin_email_from_name,
        recipient=settings.admin_email_to,
        subject=subject,
        category="Daily digest",
        sections=sections,
        now=now,
    )


def _is_digest_time(hhmm: str, now: _dt.datetime) -> bool:
    """True iff `now` is within 60s after `hhmm` (UTC).

    The match is one-shot per minute; combined with the date watermark
    above, that is enough.
    """
    if not hhmm or not re.match(r"^[0-2]\d:[0-5]\d$", hhmm):
        return False
    h, m = (int(p) for p in hhmm.split(":"))
    target = now.replace(hour=h, minute=m, second=0, microsecond=0)
    delta = (now - target).total_seconds()
    return 0 <= delta < 60


async def _collect_digest_sections(now: _dt.datetime) -> list[DigestSection]:
    today = now.date()
    sections: list[DigestSection] = []
    async with session_scope() as s:
        settings = await s.get(Settings, 1)
        if settings is None:
            return []
        tenant = await s.get(TenantConfig, 1)

        if settings.alert_secret_expiry:
            sec = secret_expiry_section(
                tenant, today, settings.alert_secret_expiry_days
            )
            if sec:
                sections.append(sec)
        if settings.alert_dead_queue:
            sec = await _dead_queue_section(s)
            if sec:
                sections.append(sec)
        if settings.alert_relay_down:
            sec = await _relay_down_section(s, now)
            if sec:
                sections.append(sec)
        if settings.alert_graph_test_failed:
            sec = await _graph_test_failed_section(s)
            if sec:
                sections.append(sec)
        if settings.alert_send_failures:
            sec = await _send_failures_section(s, now)
            if sec:
                sections.append(sec)
        if settings.alert_failed_login_spike:
            sec = await _failed_login_spike_section(s, now)
            if sec:
                sections.append(sec)

    if settings.alert_disk_usage:
        # Disk usage doesn't need a session; keep it outside.
        sec = _disk_usage_section()
        if sec:
            sections.append(sec)

    return sections


async def _reload_settings() -> Settings:
    async with session_scope() as s:
        return await s.get(Settings, 1)


# =============================================================================
# Test-alert (used by the "Send test alert" button on the UI)
# =============================================================================

async def send_test_alert() -> tuple[bool, str | None]:
    settings = await _reload_settings()
    if settings is None:
        return False, "Settings row missing."
    ok, why = await can_send(settings)
    if not ok:
        return False, why
    sample = DigestSection(
        title="Test alert",
        body=(
            "This is a test alert from the smtp-relay UI. If you "
            "received this mail, admin notifications are wired up "
            "correctly."
        ),
        severity="info",
        meta="Triggered manually from /config/notifications",
    )
    sent = await send_mail(
        sender_addr=settings.admin_email_from,
        sender_name=settings.admin_email_from_name,
        recipient=settings.admin_email_to,
        subject="[smtp-relay] Test alert",
        category="Test",
        sections=[sample],
    )
    if sent:
        return True, None
    return False, "Graph send failed; see Audit page for details."
