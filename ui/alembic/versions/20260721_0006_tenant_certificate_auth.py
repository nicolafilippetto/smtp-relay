"""tenant certificate auth: choose client secret OR certificate

Revision ID: 20260721_0006_tenant_certificate_auth
Revises: 20260611_0005_security_hardening
Create Date: 2026-07-21 00:00:00

Adds certificate-based authentication as an alternative to the client
secret on the single tenant_config row:

  - auth_method (String(16), NOT NULL, default 'secret') — which credential
    the relay authenticates with.
  - Active certificate slot: cert_private_key_enc (Fernet-encrypted PKCS#8
    key), cert_public_pem, cert_thumbprint (SHA-1 hex), cert_not_after,
    cert_created_at, cert_subject.
  - Pending/staged certificate slot (cert_pending_*): a freshly generated
    certificate not yet used for signing, so rotation never disrupts live
    sends — it is promoted to the active slot only on explicit activation
    (after the operator uploads its public .cer to Entra).

Existing deployments keep working unchanged: auth_method defaults to
'secret', and the client secret columns are untouched.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260721_0006_tenant_certificate_auth"
down_revision = "20260611_0005_security_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("tenant_config") as batch:
        batch.add_column(
            sa.Column(
                "auth_method",
                sa.String(length=16),
                nullable=False,
                server_default="secret",
            )
        )
        # Active certificate slot.
        batch.add_column(sa.Column("cert_private_key_enc", sa.Text, nullable=True))
        batch.add_column(sa.Column("cert_public_pem", sa.Text, nullable=True))
        batch.add_column(sa.Column("cert_thumbprint", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("cert_not_after", sa.Date, nullable=True))
        batch.add_column(sa.Column("cert_created_at", sa.DateTime, nullable=True))
        batch.add_column(sa.Column("cert_subject", sa.String(length=255), nullable=True))
        # Pending/staged certificate slot.
        batch.add_column(
            sa.Column("cert_pending_private_key_enc", sa.Text, nullable=True)
        )
        batch.add_column(sa.Column("cert_pending_public_pem", sa.Text, nullable=True))
        batch.add_column(
            sa.Column("cert_pending_thumbprint", sa.String(length=64), nullable=True)
        )
        batch.add_column(sa.Column("cert_pending_not_after", sa.Date, nullable=True))
        batch.add_column(
            sa.Column("cert_pending_created_at", sa.DateTime, nullable=True)
        )

    # Backfill the singleton row so auth_method is explicitly 'secret'
    # (the server_default already covers this, but be explicit/idempotent).
    op.get_bind().execute(
        sa.text(
            "UPDATE tenant_config SET auth_method = 'secret' "
            "WHERE auth_method IS NULL"
        )
    )


def downgrade() -> None:
    with op.batch_alter_table("tenant_config") as batch:
        batch.drop_column("cert_pending_created_at")
        batch.drop_column("cert_pending_not_after")
        batch.drop_column("cert_pending_thumbprint")
        batch.drop_column("cert_pending_public_pem")
        batch.drop_column("cert_pending_private_key_enc")
        batch.drop_column("cert_subject")
        batch.drop_column("cert_created_at")
        batch.drop_column("cert_not_after")
        batch.drop_column("cert_thumbprint")
        batch.drop_column("cert_public_pem")
        batch.drop_column("cert_private_key_enc")
        batch.drop_column("auth_method")
