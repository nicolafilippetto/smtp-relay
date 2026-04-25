"""initial schema

Revision ID: 20260424_0000_init
Revises:
Create Date: 2026-04-24 00:00:00

Creates every table backing `common.models`.

Fields on Enum columns are stored as VARCHAR with explicit lengths so
SQLite handles them without needing CHECK constraints. The relay and
the UI both agree on the string values via `common.models`.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260424_0000_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("totp_secret", sa.String(length=64), nullable=True),
        sa.Column("totp_enrolled_at", sa.DateTime, nullable=True),
        sa.Column(
            "must_change_password",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "is_active", sa.Boolean, nullable=False, server_default=sa.true()
        ),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )

    # ------------------------------------------------------------------
    # smtp_accounts
    # ------------------------------------------------------------------
    op.create_table(
        "smtp_accounts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(length=128), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column(
            "is_enabled", sa.Boolean, nullable=False, server_default=sa.true()
        ),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # ------------------------------------------------------------------
    # ip_whitelist
    # ------------------------------------------------------------------
    op.create_table(
        "ip_whitelist",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("cidr", sa.String(length=64), nullable=False, unique=True),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column(
            "is_enabled", sa.Boolean, nullable=False, server_default=sa.true()
        ),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # ------------------------------------------------------------------
    # authorised_senders
    # ------------------------------------------------------------------
    op.create_table(
        "authorised_senders",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("address", sa.String(length=320), nullable=False, unique=True),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column(
            "is_enabled", sa.Boolean, nullable=False, server_default=sa.true()
        ),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # ------------------------------------------------------------------
    # tenant_config — single-row table (id=1 by convention)
    # ------------------------------------------------------------------
    op.create_table(
        "tenant_config",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.String(length=64), nullable=True),
        sa.Column("client_id", sa.String(length=64), nullable=True),
        sa.Column("client_secret_enc", sa.Text, nullable=True),
        sa.Column("last_test_at", sa.DateTime, nullable=True),
        sa.Column("last_test_ok", sa.Boolean, nullable=True),
        sa.Column("last_test_error", sa.Text, nullable=True),
        sa.Column("last_token_acquired_at", sa.DateTime, nullable=True),
        sa.Column("last_token_expires_at", sa.DateTime, nullable=True),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )

    # ------------------------------------------------------------------
    # settings — single-row table (id=1 by convention)
    # ------------------------------------------------------------------
    op.create_table(
        "settings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "smtp_auth_local_enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column(
            "smtp_whitelist_enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("smtp_ban_threshold", sa.Integer, nullable=False, server_default="5"),
        sa.Column(
            "smtp_ban_duration_min", sa.Integer, nullable=False, server_default="30"
        ),
        sa.Column(
            "queue_max_attempts", sa.Integer, nullable=False, server_default="3"
        ),
        sa.Column(
            "archive_retention_days",
            sa.Integer,
            nullable=False,
            server_default="30",
        ),
        sa.Column(
            "audit_retention_days",
            sa.Integer,
            nullable=False,
            server_default="90",
        ),
        sa.Column(
            "queue_sent_retention_days",
            sa.Integer,
            nullable=False,
            server_default="30",
        ),
        sa.Column(
            "log_mail_contents",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )

    # ------------------------------------------------------------------
    # mail_queue
    # ------------------------------------------------------------------
    op.create_table(
        "mail_queue",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("timestamp_received", sa.DateTime, nullable=False, index=True),
        sa.Column("sender", sa.String(length=320), nullable=False, index=True),
        sa.Column("recipients_json", sa.Text, nullable=False),
        sa.Column("subject", sa.String(length=998), nullable=True),
        sa.Column("raw_mime_b64", sa.Text, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, index=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_attempt", sa.DateTime, nullable=True),
        sa.Column("next_attempt_at", sa.DateTime, nullable=True, index=True),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("archive_path", sa.String(length=512), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("source_username", sa.String(length=128), nullable=True),
    )

    # ------------------------------------------------------------------
    # audit_log
    # ------------------------------------------------------------------
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("timestamp", sa.DateTime, nullable=False, index=True),
        sa.Column("event_type", sa.String(length=32), nullable=False, index=True),
        sa.Column("outcome", sa.String(length=16), nullable=False, index=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("details_json", sa.Text, nullable=True),
    )

    # ------------------------------------------------------------------
    # bans
    # ------------------------------------------------------------------
    op.create_table(
        "bans",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("until", sa.DateTime, nullable=False),
        sa.UniqueConstraint(
            "scope", "kind", "value", name="uq_bans_scope_kind_value"
        ),
    )
    op.create_index("ix_bans_until", "bans", ["until"])

    # ------------------------------------------------------------------
    # failed_attempts
    # ------------------------------------------------------------------
    op.create_table(
        "failed_attempts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, index=True),
    )
    op.create_index(
        "ix_failed_attempts_lookup",
        "failed_attempts",
        ["kind", "scope", "value", "created_at"],
    )

    # ------------------------------------------------------------------
    # relay_heartbeat — single-row table (id=1 by convention)
    # ------------------------------------------------------------------
    op.create_table(
        "relay_heartbeat",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("last_seen_at", sa.DateTime, nullable=False),
        sa.Column(
            "status", sa.String(length=16), nullable=False, server_default="running"
        ),
        sa.Column("last_error", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("relay_heartbeat")
    op.drop_index("ix_failed_attempts_lookup", table_name="failed_attempts")
    op.drop_table("failed_attempts")
    op.drop_index("ix_bans_until", table_name="bans")
    op.drop_table("bans")
    op.drop_table("audit_log")
    op.drop_table("mail_queue")
    op.drop_table("settings")
    op.drop_table("tenant_config")
    op.drop_table("authorised_senders")
    op.drop_table("ip_whitelist")
    op.drop_table("smtp_accounts")
    op.drop_table("users")
