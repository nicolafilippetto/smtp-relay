"""admin_email_from_name display name

Revision ID: 20260427_0003_admin_email_from_name
Revises: 20260427_0002_admin_alerts
Create Date: 2026-04-27 21:00:00

Adds:
  - settings.admin_email_from_name (str(128), nullable) — optional
    display name used to build the RFC 5322 `From` header
    (`"Name" <email>`).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260427_0003_admin_email_from_name"
down_revision = "20260427_0002_admin_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("settings") as batch:
        batch.add_column(
            sa.Column("admin_email_from_name", sa.String(length=128), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("settings") as batch:
        batch.drop_column("admin_email_from_name")
