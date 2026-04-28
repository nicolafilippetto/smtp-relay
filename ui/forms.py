"""Pydantic v2 models for form-body validation.

FastAPI's Form() does field-level validation but lets us collect related
fields into a Pydantic model via Depends(). These models are used as
the authoritative input-validation layer for every state-changing
endpoint.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from typing import Annotated, Optional

from fastapi import Form
from pydantic import BaseModel, ConfigDict, Field, field_validator


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _clean(value: str | None) -> str:
    return (value or "").strip()


class TenantConfigIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    tenant_id: Annotated[str, Field(min_length=1, max_length=64)]
    client_id: Annotated[str, Field(min_length=1, max_length=64)]
    # Empty string means "leave existing secret untouched".
    client_secret: str = ""
    # Optional secret expiry date; pair with `clear_secret_expires_at`
    # to wipe the value.
    secret_expires_at: Optional[_dt.date] = None
    clear_secret_expires_at: bool = False
    # Operator confirmation that the date in `secret_expires_at` reflects
    # the new secret. Required only when a new client_secret is being
    # submitted (enforced in the router, not here).
    expiry_verified: bool = False


class AdminNotificationsIn(BaseModel):
    """Settings → Notifications page form."""
    model_config = ConfigDict(str_strip_whitespace=True)

    admin_email_from_name: str = ""
    admin_email_from: str = ""
    admin_email_to: str = ""
    alert_secret_expiry_days: int = Field(ge=1, le=365, default=30)
    alert_daily_time: str = "09:00"

    alert_secret_expiry: bool = False
    alert_dead_queue: bool = False
    alert_relay_down: bool = False
    alert_graph_test_failed: bool = False
    alert_disk_usage: bool = False
    alert_send_failures: bool = False
    alert_failed_login_spike: bool = False
    alert_user_banned: bool = False
    alert_admin_reset: bool = False
    alert_admin_password_change: bool = False
    alert_smtp_password_change: bool = False

    @field_validator("admin_email_to", "admin_email_from")
    @classmethod
    def _valid_email_or_blank(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if not v:
            return ""
        if not _EMAIL_RE.match(v):
            raise ValueError("Not a valid email address.")
        return v

    @field_validator("alert_daily_time")
    @classmethod
    def _valid_time(cls, v: str) -> str:
        v = (v or "").strip()
        if not _HHMM_RE.match(v):
            raise ValueError("Time must be in HH:MM 24h format (UTC).")
        return v

    @field_validator("admin_email_from_name")
    @classmethod
    def _valid_display_name(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            return ""
        # Reject CR/LF (header injection) and newlines.
        if any(c in v for c in "\r\n"):
            raise ValueError("Sender name cannot contain newlines.")
        return v[:128]


class SettingsIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    smtp_auth_local_enabled: bool = False
    smtp_whitelist_enabled: bool = False
    smtp_ban_threshold: int = Field(ge=1, le=100)
    smtp_ban_duration_min: int = Field(ge=1, le=10_000)
    queue_max_attempts: int = Field(ge=1, le=50)
    archive_retention_days: int = Field(ge=1, le=3650)
    audit_retention_days: int = Field(ge=1, le=3650)
    queue_sent_retention_days: int = Field(ge=1, le=3650)
    log_mail_contents: bool = False

    # Rate limiting
    rate_limit_enabled: bool = False
    rate_limit_scope: Annotated[str, Field(pattern="^(ip|username|both)$")] = "both"
    rate_limit_threshold: int = Field(ge=1, le=100_000, default=10)
    rate_limit_window_sec: int = Field(ge=1, le=86_400, default=60)


class CidrIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    cidr: Annotated[str, Field(min_length=1, max_length=64)]
    description: str = ""

    @field_validator("cidr")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR or IP: {exc}") from exc
        return str(net)


class SenderIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    address: Annotated[str, Field(min_length=3, max_length=320)]
    description: str = ""

    @field_validator("address")
    @classmethod
    def _valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Not a valid email address.")
        return v


class SmtpAccountIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: Annotated[str, Field(min_length=1, max_length=128)]
    # Empty on update = keep existing password.
    password: str = ""
    # Newline- or comma-separated CIDRs. Empty = any IP.
    allowed_cidrs: str = ""
    description: str = ""

    @field_validator("allowed_cidrs")
    @classmethod
    def _valid_cidrs(cls, v: str) -> str:
        if not v:
            return ""
        parsed: list[str] = []
        for chunk in v.replace(",", "\n").splitlines():
            c = chunk.strip()
            if not c:
                continue
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid CIDR {c!r}: {exc}"
                ) from exc
            parsed.append(str(net))
        # Canonicalise: one per line, trimmed.
        return "\n".join(parsed)


# -----------------------------------------------------------------------------
# FastAPI adapters
# -----------------------------------------------------------------------------

def tenant_form(
    tenant_id: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    secret_expires_at: str = Form(""),
    clear_secret_expires_at: bool = Form(False),
    expiry_verified: bool = Form(False),
) -> TenantConfigIn:
    parsed_date: Optional[_dt.date] = None
    raw = (secret_expires_at or "").strip()
    if raw and not clear_secret_expires_at:
        try:
            parsed_date = _dt.date.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid expiry date: {exc}. Expected YYYY-MM-DD."
            ) from exc
    return TenantConfigIn(
        tenant_id=_clean(tenant_id),
        client_id=_clean(client_id),
        client_secret=client_secret,  # secret is not stripped: preserve leading/trailing chars
        secret_expires_at=parsed_date,
        clear_secret_expires_at=clear_secret_expires_at,
        expiry_verified=expiry_verified,
    )


def notifications_form(
    admin_email_from_name: str = Form(""),
    admin_email_from: str = Form(""),
    admin_email_to: str = Form(""),
    alert_secret_expiry_days: int = Form(30),
    alert_daily_time: str = Form("09:00"),
    alert_secret_expiry: bool = Form(False),
    alert_dead_queue: bool = Form(False),
    alert_relay_down: bool = Form(False),
    alert_graph_test_failed: bool = Form(False),
    alert_disk_usage: bool = Form(False),
    alert_send_failures: bool = Form(False),
    alert_failed_login_spike: bool = Form(False),
    alert_user_banned: bool = Form(False),
    alert_admin_reset: bool = Form(False),
    alert_admin_password_change: bool = Form(False),
    alert_smtp_password_change: bool = Form(False),
) -> AdminNotificationsIn:
    return AdminNotificationsIn(
        admin_email_from_name=admin_email_from_name,
        admin_email_from=admin_email_from,
        admin_email_to=admin_email_to,
        alert_secret_expiry_days=alert_secret_expiry_days,
        alert_daily_time=alert_daily_time,
        alert_secret_expiry=alert_secret_expiry,
        alert_dead_queue=alert_dead_queue,
        alert_relay_down=alert_relay_down,
        alert_graph_test_failed=alert_graph_test_failed,
        alert_disk_usage=alert_disk_usage,
        alert_send_failures=alert_send_failures,
        alert_failed_login_spike=alert_failed_login_spike,
        alert_user_banned=alert_user_banned,
        alert_admin_reset=alert_admin_reset,
        alert_admin_password_change=alert_admin_password_change,
        alert_smtp_password_change=alert_smtp_password_change,
    )


def settings_form(
    smtp_auth_local_enabled: bool = Form(False),
    smtp_whitelist_enabled: bool = Form(False),
    smtp_ban_threshold: int = Form(5),
    smtp_ban_duration_min: int = Form(30),
    queue_max_attempts: int = Form(3),
    archive_retention_days: int = Form(30),
    audit_retention_days: int = Form(90),
    queue_sent_retention_days: int = Form(30),
    log_mail_contents: bool = Form(False),
    rate_limit_enabled: bool = Form(False),
    rate_limit_scope: str = Form("both"),
    rate_limit_threshold: int = Form(10),
    rate_limit_window_sec: int = Form(60),
) -> SettingsIn:
    return SettingsIn(
        smtp_auth_local_enabled=smtp_auth_local_enabled,
        smtp_whitelist_enabled=smtp_whitelist_enabled,
        smtp_ban_threshold=smtp_ban_threshold,
        smtp_ban_duration_min=smtp_ban_duration_min,
        queue_max_attempts=queue_max_attempts,
        archive_retention_days=archive_retention_days,
        audit_retention_days=audit_retention_days,
        queue_sent_retention_days=queue_sent_retention_days,
        log_mail_contents=log_mail_contents,
        rate_limit_enabled=rate_limit_enabled,
        rate_limit_scope=rate_limit_scope,
        rate_limit_threshold=rate_limit_threshold,
        rate_limit_window_sec=rate_limit_window_sec,
    )


def cidr_form(
    cidr: str = Form(""),
    description: str = Form(""),
) -> CidrIn:
    return CidrIn(cidr=_clean(cidr), description=_clean(description))


def sender_form(
    address: str = Form(""),
    description: str = Form(""),
) -> SenderIn:
    return SenderIn(address=_clean(address), description=_clean(description))


def smtp_account_form(
    username: str = Form(""),
    password: str = Form(""),
    allowed_cidrs: str = Form(""),
    description: str = Form(""),
) -> SmtpAccountIn:
    return SmtpAccountIn(
        username=_clean(username),
        password=password,
        allowed_cidrs=allowed_cidrs,
        description=_clean(description),
    )
