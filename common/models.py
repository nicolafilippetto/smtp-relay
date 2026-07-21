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
    BigInteger,
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
    ARCHIVE_WRITE_FAIL = "archive_write_fail"
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

    # TOTP shared secret, Fernet-encrypted at rest and decrypted only at
    # verification time. Stored as Text because a Fernet token is much longer
    # than the raw base32 secret.
    totp_secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    totp_enrolled_at: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True
    )
    # Last consumed TOTP step (Unix time // 30). A submitted code whose step is
    # <= this value is rejected, so each code is single-use within its validity
    # window (anti-replay). NULL until the first successful TOTP verification.
    totp_last_counter: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True
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

    # Which credential the relay authenticates with: "secret" or
    # "certificate". Exactly one is live at a time; the other's material may
    # remain stored (unused) so the operator can switch back without re-entry.
    auth_method: Mapped[str] = mapped_column(
        String(16), nullable=False, default="secret", server_default="secret"
    )

    # Fernet-encrypted value; never logged, never returned by the API.
    client_secret_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ---- Certificate credential (active) -------------------------------
    # Fernet-encrypted PKCS#8 private key. Never logged, never downloadable.
    cert_private_key_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # PEM public certificate — the part the operator uploads to Entra. Safe
    # to expose; offered as a `.cer` download in the UI.
    cert_public_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Uppercase, colon-free hex SHA-1 fingerprint (matches Entra + MSAL).
    cert_thumbprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # notAfter of the active certificate. Known at generation time, so it
    # drives the expiry alert without operator transcription.
    cert_not_after: Mapped[Optional[_dt.date]] = mapped_column(Date, nullable=True)
    cert_created_at: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True
    )
    cert_subject: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # ---- Certificate credential (pending / staged) ---------------------
    # A newly generated certificate that is NOT yet used for signing. It is
    # promoted to the active slot only when the operator activates it — after
    # uploading its public `.cer` to Entra — so rotation never breaks live
    # sends (the active private key keeps signing until the swap).
    cert_pending_private_key_enc: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    cert_pending_public_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cert_pending_thumbprint: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    cert_pending_not_after: Mapped[Optional[_dt.date]] = mapped_column(
        Date, nullable=True
    )
    cert_pending_created_at: Mapped[Optional[_dt.datetime]] = mapped_column(
        DateTime, nullable=True
    )

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

    # ---- Convenience accessors for the *active* credential -------------
    # Both the UI (dashboard/config indicators) and the alert digest read
    # these so the expiry logic lives in one place regardless of method.

    @property
    def uses_certificate(self) -> bool:
        return (self.auth_method or "secret") == "certificate"

    @property
    def has_active_credential(self) -> bool:
        """True when the *selected* method has usable material stored."""
        if self.uses_certificate:
            return bool(self.cert_private_key_enc and self.cert_thumbprint)
        return bool(self.client_secret_enc)

    @property
    def credential_label(self) -> str:
        return "certificate" if self.uses_certificate else "client secret"

    @property
    def credential_expires_at(self) -> Optional[_dt.date]:
        """Expiry date of whichever credential is currently active."""
        return self.cert_not_after if self.uses_certificate else self.secret_expires_at


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

    # Authorised-senders enforcement. When True (default) the relay only
    # accepts mail whose From: address is an enabled AuthorisedSender.
    # When False the check is bypassed and ANY sender is accepted — a
    # deliberately risky operation exposed in the UI with a warning.
    # NB: this never bypasses SMTP authentication / IP whitelisting; it
    # only relaxes the From: address allow-list.
    smtp_sender_check_enabled: Mapped[bool] = mapped_column(
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

    # Rate-limit (inbound DATA accepted per time window). On by default with a
    # generous threshold: an anti-spam/anti-bombing backstop that does not
    # throttle typical legacy batch senders. Tunable from the UI.
    rate_limit_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    # One of: "ip" | "username" | "both"
    rate_limit_scope: Mapped[str] = mapped_column(
        String(16), nullable=False, default="both"
    )
    rate_limit_threshold: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60
    )
    rate_limit_window_sec: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60
    )

    # ---------------------------------------------------------------
    # Admin notifications
    # ---------------------------------------------------------------
    # Recipient(s) + sender for alert mails. Sender must be an enabled
    # AuthorisedSender, otherwise Graph will reject the send. The
    # recipient field accepts several addresses separated by ';' and is
    # therefore sized generously.
    admin_email_to: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True
    )
    admin_email_from: Mapped[Optional[str]] = mapped_column(
        String(320), nullable=True
    )
    # Optional display name shown to the recipient as `Name <email>`.
    admin_email_from_name: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
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
