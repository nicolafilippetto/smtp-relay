"""Pydantic v2 models for form-body validation.

FastAPI's Form() does field-level validation but lets us collect related
fields into a Pydantic model via Depends(). These models are used as
the authoritative input-validation layer for every state-changing
endpoint.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated

from fastapi import Form
from pydantic import BaseModel, ConfigDict, Field, field_validator


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _clean(value: str | None) -> str:
    return (value or "").strip()


class TenantConfigIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    tenant_id: Annotated[str, Field(min_length=1, max_length=64)]
    client_id: Annotated[str, Field(min_length=1, max_length=64)]
    # Empty string means "leave existing secret untouched".
    client_secret: str = ""


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
) -> TenantConfigIn:
    return TenantConfigIn(
        tenant_id=_clean(tenant_id),
        client_id=_clean(client_id),
        client_secret=client_secret,  # secret is not stripped: preserve leading/trailing chars
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
