"""admin notifications + secret expiry tracking

Revision ID: 20260427_0002_admin_alerts
Revises: 20260424_0001_ratelimit
Create Date: 2026-04-27 00:00:00

Adds:
  - tenant_config.secret_expires_at (date, nullable)
  - settings.admin_email_to / admin_email_from (str, nullable)
  - settings.alert_secret_expiry_days (int, default 30)
  - settings.alert_daily_time (str, default '09:00')
  - 11 settings.alert_* booleans (default true) — per-type toggles
  - settings.alert_last_realtime_scan_at (datetime, nullable)
  - settings.alert_last_digest_at (date, nullable)
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260427_0002_admin_alerts"
down_revision = "20260424_0001_ratelimit"
branch_labels = None
depends_on = None


_BOOL_TOGGLES = (
    "alert_secret_expiry",
    "alert_dead_queue",
    "alert_relay_down",
    "alert_graph_test_failed",
    "alert_disk_usage",
    "alert_send_failures",
    "alert_failed_login_spike",
    "alert_user_banned",
    "alert_admin_reset",
    "alert_admin_password_change",
    "alert_smtp_password_change",
)


def upgrade() -> None:
    with op.batch_alter_table("tenant_config") as batch:
        batch.add_column(sa.Column("secret_expires_at", sa.Date, nullable=True))

    with op.batch_alter_table("settings") as batch:
        batch.add_column(sa.Column("admin_email_to", sa.String(length=320), nullable=True))
        batch.add_column(sa.Column("admin_email_from", sa.String(length=320), nullable=True))
        batch.add_column(
            sa.Column(
                "alert_secret_expiry_days",
                sa.Integer,
                nullable=False,
                server_default="30",
            )
        )
        batch.add_column(
            sa.Column(
                "alert_daily_time",
                sa.String(length=5),
                nullable=False,
                server_default="09:00",
            )
        )
        for name in _BOOL_TOGGLES:
            batch.add_column(
                sa.Column(
                    name,
                    sa.Boolean,
                    nullable=False,
                    server_default=sa.true(),
                )
            )
        batch.add_column(
            sa.Column("alert_last_realtime_scan_at", sa.DateTime, nullable=True)
        )
        batch.add_column(sa.Column("alert_last_digest_at", sa.Date, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("settings") as batch:
        batch.drop_column("alert_last_digest_at")
        batch.drop_column("alert_last_realtime_scan_at")
        for name in reversed(_BOOL_TOGGLES):
            batch.drop_column(name)
        batch.drop_column("alert_daily_time")
        batch.drop_column("alert_secret_expiry_days")
        batch.drop_column("admin_email_from")
        batch.drop_column("admin_email_to")

    with op.batch_alter_table("tenant_config") as batch:
        batch.drop_column("secret_expires_at")
