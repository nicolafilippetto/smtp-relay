"""rate limit and per-account IP binding

Revision ID: 20260424_0001_ratelimit
Revises: 20260424_0000_init
Create Date: 2026-04-24 13:00:00

Adds:
  - settings.rate_limit_enabled (bool, default false)
  - settings.rate_limit_scope (str, 'ip' | 'username' | 'both', default 'both')
  - settings.rate_limit_threshold (int, default 10)
  - settings.rate_limit_window_sec (int, default 60)
  - smtp_accounts.allowed_cidrs (text, default empty)
  - smtp_rate_events table for counting accepted messages per window
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260424_0001_ratelimit"
down_revision = "20260424_0000_init"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ---- settings ----
    with op.batch_alter_table("settings") as batch:
        batch.add_column(
            sa.Column(
                "rate_limit_enabled",
                sa.Boolean,
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch.add_column(
            sa.Column(
                "rate_limit_scope",
                sa.String(length=16),
                nullable=False,
                server_default="both",
            )
        )
        batch.add_column(
            sa.Column(
                "rate_limit_threshold",
                sa.Integer,
                nullable=False,
                server_default="10",
            )
        )
        batch.add_column(
            sa.Column(
                "rate_limit_window_sec",
                sa.Integer,
                nullable=False,
                server_default="60",
            )
        )

    # ---- smtp_accounts ----
    with op.batch_alter_table("smtp_accounts") as batch:
        batch.add_column(
            sa.Column(
                "allowed_cidrs",
                sa.Text,
                nullable=False,
                server_default="",
            )
        )

    # ---- smtp_rate_events ----
    op.create_table(
        "smtp_rate_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("timestamp", sa.DateTime, nullable=False, index=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("username", sa.String(length=128), nullable=True),
    )
    op.create_index(
        "ix_smtp_rate_events_ip_ts",
        "smtp_rate_events",
        ["source_ip", "timestamp"],
    )
    op.create_index(
        "ix_smtp_rate_events_user_ts",
        "smtp_rate_events",
        ["username", "timestamp"],
    )


def downgrade() -> None:
    op.drop_index("ix_smtp_rate_events_user_ts", table_name="smtp_rate_events")
    op.drop_index("ix_smtp_rate_events_ip_ts", table_name="smtp_rate_events")
    op.drop_table("smtp_rate_events")

    with op.batch_alter_table("smtp_accounts") as batch:
        batch.drop_column("allowed_cidrs")

    with op.batch_alter_table("settings") as batch:
        batch.drop_column("rate_limit_window_sec")
        batch.drop_column("rate_limit_threshold")
        batch.drop_column("rate_limit_scope")
        batch.drop_column("rate_limit_enabled")
