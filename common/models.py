"""SQLAlchemy ORM models.

Single source of truth for the database schema. Both the relay and
the UI import these classes. Alembic migrations live in the UI
service only (the UI runs `alembic upgrade head` on startup); the
relay waits on the UI via the compose `depends_on` clause.

All timestamps are stored as timezone-naive UTC datetimes. Helper
properties return aware datetimes where convenient.
"""

from __future__ import annotations

import datetime as _dt
import enum
from typing import Optional

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum as SAEnum,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> _dt.datetime:
    """UTC now as a naive datetime (SQLite doesn't round-trip tzinfo)."""
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    """Declarative base for all ORM classes."""


# =============================================================================
# Enums
# =============================================================================

class MailStatus(str, enum.Enum):
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    DEAD = "dead"


class AuditOutcome(str, enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class AuditEventType(str, enum.Enum):
    LOGIN_OK = "login_ok"
    LOGIN_FAIL = "login_fail"
    TOTP_FAIL = "totp_fail"
    SMTP_AUTH_OK = "smtp_auth_ok"
    SMTP_AUTH_FAIL = "smtp_auth_fail"
    SMTP_RELAY_OK = "smtp_relay_ok"
    SMTP_RELAY_FAIL = "smtp_relay_fail"
    CONFIG_CHANGE = "config_change"
    USER_BAN = "user_ban"
    USER_UNBAN = "user_unban"
    QUEUE_RETRY = "queue_retry"
    ARCHIVE_DELETE = "archive_delete"
    ADMIN_RESET = "admin_reset"


class BanScope(str, enum.Enum):
    """Whether a ban row targets an IP or a username."""
    IP = "ip"
    USERNAME = "username"


class BanKind(str, enum.Enum):
    """Whether a ban was issued by the UI or by the SMTP relay."""
    UI = "ui"
    SMTP = "smtp"


# =============================================================================
# Users (UI admin accounts)
# =============================================================================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # TOTP: secret is stored in cleartext (it is already a shared secret
    # with the authenticator app; encrypting would not add value because
    # we need plain access to validate on every login).
    totp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    totp_enrolled_at: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True
    )

    # Force-rotate password on next login (used after ADMIN_RESET).
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )
    updated_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, onupdate=_utcnow
    )


# =============================================================================
# SMTP local accounts
# =============================================================================

class SmtpAccount(Base):
    __tablename__ = "smtp_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    # Newline- or comma-separated CIDRs the user may connect from.
    # Empty string = no restriction (any IP allowed with correct password).
    allowed_cidrs: Mapped[str] = mapped_column(Text, nullable=False, default="")
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )


# =============================================================================
# IP whitelist (CIDR entries allowed to skip SMTP AUTH)
# =============================================================================

class IpWhitelistEntry(Base):
    __tablename__ = "ip_whitelist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Stored as a CIDR string, e.g. "10.0.0.0/8" or "192.168.1.10/32".
    cidr: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )


# =============================================================================
# Authorised senders (From: whitelist for the Graph API)
# =============================================================================

class AuthorisedSender(Base):
    __tablename__ = "authorised_senders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )


# =============================================================================
# Tenant (Entra ID) configuration — single row, pk=1
# =============================================================================

class TenantConfig(Base):
    __tablename__ = "tenant_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Fernet-encrypted value; never logged, never returned by the API.
    client_secret_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps from the last test-connection attempt.
    last_test_at: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True
    )
    last_test_ok: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    last_test_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Informational cache of the last token we saw (for the dashboard).
    last_token_acquired_at: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True
    )
    last_token_expires_at: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True
    )

    # Operator-supplied expiry date of the Azure AD client secret.
    # Optional. When set, drives the secret-expiry admin alert.
    secret_expires_at: Mapped[Optional[_dt.date]] = mapped_column(
        Date, nullable=True
    )

    updated_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, onupdate=_utcnow
    )


# =============================================================================
# Global settings — single row, pk=1
# =============================================================================

class Settings(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Auth modes (can coexist).
    smtp_auth_local_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    smtp_whitelist_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    # SMTP ban policy.
    smtp_ban_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    smtp_ban_duration_min: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30
    )

    # Queue retry policy.
    queue_max_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3
    )

    # Retention (days). Floors are enforced in Python, not in the DB.
    archive_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30
    )
    audit_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90
    )
    queue_sent_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30
    )

    # Whether the relay is allowed to log raw mail bodies at DEBUG.
    # Off by default. Even when on, passwords and tokens are still
    # scrubbed.
    log_mail_contents: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    # Rate-limit (inbound DATA accepted per time window).
    rate_limit_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    # One of: "ip" | "username" | "both"
    rate_limit_scope: Mapped[str] = mapped_column(
        String(16), nullable=False, default="both"
    )
    rate_limit_threshold: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10
    )
    rate_limit_window_sec: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60
    )

    # ---------------------------------------------------------------
    # Admin notifications
    # ---------------------------------------------------------------
    # Recipient + sender for alert mails. Sender must be an enabled
    # AuthorisedSender, otherwise Graph will reject the send.
    admin_email_to: Mapped[Optional[str]] = mapped_column(
        String(320), nullable=True
    )
    admin_email_from: Mapped[Optional[str]] = mapped_column(
        String(320), nullable=True
    )

    # Tunables for the digest scheduler.
    alert_secret_expiry_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30
    )
    # HH:MM (24h, UTC). Default 09:00.
    alert_daily_time: Mapped[str] = mapped_column(
        String(5), nullable=False, default="09:00"
    )

    # Per-type toggles.
    alert_secret_expiry: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_dead_queue: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_relay_down: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_graph_test_failed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_disk_usage: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_send_failures: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_failed_login_spike: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_user_banned: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_admin_reset: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_admin_password_change: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    alert_smtp_password_change: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    # Bookkeeping for the dispatcher loop.
    alert_last_realtime_scan_at: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True
    )
    alert_last_digest_at: Mapped[Optional[_dt.date]] = mapped_column(
        Date, nullable=True
    )

    updated_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, onupdate=_utcnow
    )


# =============================================================================
# Mail queue
# =============================================================================

class MailQueue(Base):
    __tablename__ = "mail_queue"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp_received: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, index=True
    )
    sender: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    # JSON-encoded list of recipient addresses.
    recipients_json: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[Optional[str]] = mapped_column(String(998), nullable=True)
    # Base64-encoded raw MIME, kept in the DB so retries do not depend
    # on the filesystem archive being present.
    raw_mime_b64: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[MailStatus] = mapped_column(
        SAEnum(MailStatus, native_enum=False, length=16),
        nullable=False,
        default=MailStatus.PENDING,
        index=True,
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_attempt: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True
    )
    next_attempt_at: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True, index=True
    )
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Populated when status becomes SENT so the UI can link to the file.
    archive_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # Which SMTP account or IP submitted the mail (for audit correlation).
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    source_username: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )


# =============================================================================
# Audit log
# =============================================================================

class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, index=True
    )
    event_type: Mapped[AuditEventType] = mapped_column(
        SAEnum(AuditEventType, native_enum=False, length=32),
        nullable=False,
        index=True,
    )
    outcome: Mapped[AuditOutcome] = mapped_column(
        SAEnum(AuditOutcome, native_enum=False, length=16),
        nullable=False,
        index=True,
    )
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# =============================================================================
# Bans
# =============================================================================

class Ban(Base):
    __tablename__ = "bans"
    __table_args__ = (
        UniqueConstraint("scope", "kind", "value", name="uq_bans_scope_kind_value"),
        Index("ix_bans_until", "until"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[BanScope] = mapped_column(
        SAEnum(BanScope, native_enum=False, length=16), nullable=False
    )
    kind: Mapped[BanKind] = mapped_column(
        SAEnum(BanKind, native_enum=False, length=8), nullable=False
    )
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )
    until: Mapped[_dt.datetime] = mapped_column(DateTime, nullable=False)


# =============================================================================
# Failed-login counters (sliding window for ban decisions)
# =============================================================================

class FailedAttempt(Base):
    """Individual failed login / SMTP AUTH attempts.

    Rows older than the current ban window are pruned by a periodic
    task; the table is the evidence trail feeding ban decisions.
    """

    __tablename__ = "failed_attempts"
    __table_args__ = (
        Index("ix_failed_attempts_lookup", "kind", "scope", "value", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[BanKind] = mapped_column(
        SAEnum(BanKind, native_enum=False, length=8), nullable=False
    )
    scope: Mapped[BanScope] = mapped_column(
        SAEnum(BanScope, native_enum=False, length=16), nullable=False
    )
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, index=True
    )


# =============================================================================
# Relay heartbeat — the relay upserts a row here so the UI can
# display liveness on the dashboard.
# =============================================================================

class RelayHeartbeat(Base):
    __tablename__ = "relay_heartbeat"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[_dt.datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, onupdate=_utcnow
    )
    # "running" | "starting" | "error"
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class SmtpRateEvent(Base):
    """One row per accepted DATA command.

    Used by the rate limiter in relay.smtp_handler to count recent
    messages per IP or per username within a sliding window. Rows are
    pruned periodically by the relay's housekeeper loop.
    """

    __tablename__ = "smtp_rate_events"
    __table_args__ = (
        Index("ix_smtp_rate_events_ip_ts", "source_ip", "timestamp"),
        Index("ix_smtp_rate_events_user_ts", "username", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[_dt.datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, index=True
    )
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)


__all__ = [
    "Base",
    "User",
    "SmtpAccount",
    "IpWhitelistEntry",
    "AuthorisedSender",
    "TenantConfig",
    "Settings",
    "MailQueue",
    "MailStatus",
    "AuditLog",
    "AuditEventType",
    "AuditOutcome",
    "Ban",
    "BanScope",
    "BanKind",
    "FailedAttempt",
    "RelayHeartbeat",
    "SmtpRateEvent",
]
