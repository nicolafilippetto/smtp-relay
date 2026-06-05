"""sender-check toggle + multi-recipient admin alerts

Revision ID: 20260605_0004_sender_check
Revises: 20260427_0003_admin_email_from_name
Create Date: 2026-06-05 00:00:00

Adds:
  - settings.smtp_sender_check_enabled (bool, default true) — when false
    the relay accepts ANY From: sender (the authorised-senders allow-list
    is bypassed). Exposed in the UI as a deliberately risky toggle.

Widens:
  - settings.admin_email_to (str 320 -> 1024) — the recipient field now
    accepts several addresses separated by ';'.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260605_0004_sender_check"
down_revision = "20260427_0003_admin_email_from_name"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("settings") as batch:
        batch.add_column(
            sa.Column(
                "smtp_sender_check_enabled",
                sa.Boolean,
                nullable=False,
                server_default=sa.true(),
            )
        )
        batch.alter_column(
            "admin_email_to",
            existing_type=sa.String(length=320),
            type_=sa.String(length=1024),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("settings") as batch:
        batch.alter_column(
            "admin_email_to",
            existing_type=sa.String(length=1024),
            type_=sa.String(length=320),
            existing_nullable=True,
        )
        batch.drop_column("smtp_sender_check_enabled")
