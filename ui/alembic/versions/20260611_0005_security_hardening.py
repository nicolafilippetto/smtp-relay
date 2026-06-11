"""security hardening: TOTP one-time-use + encryption, rate-limit defaults

Revision ID: 20260611_0005_security_hardening
Revises: 20260605_0004_sender_check
Create Date: 2026-06-11 00:00:00

Changes:
  - users.totp_last_counter (BigInteger, nullable) — last consumed TOTP step
    (Unix time // 30). A submitted code whose step is <= this value is
    rejected, making each code single-use within its validity window
    (anti-replay).
  - users.totp_secret widened (String(64) -> Text) and any existing plaintext
    secret is encrypted at rest with the application ENCRYPTION_KEY (Fernet).
    Authenticator apps keep working — the underlying secret is unchanged, only
    its on-disk representation becomes ciphertext.
  - settings: enable rate limiting on the existing deployment and raise the
    legacy default threshold (10 -> 60) so it acts as an anti-bombing backstop
    without throttling typical legacy batch senders.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260611_0005_security_hardening"
down_revision = "20260605_0004_sender_check"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ---- users: anti-replay counter + widen secret column for ciphertext ----
    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column("totp_last_counter", sa.BigInteger, nullable=True)
        )
        batch.alter_column(
            "totp_secret",
            existing_type=sa.String(length=64),
            type_=sa.Text(),
            existing_nullable=True,
        )

    # ---- encrypt any existing plaintext TOTP secrets at rest ----
    # Runs only when there are enrolled users; a fresh install touches no
    # crypto here. ENCRYPTION_KEY is guaranteed present in the UI runtime
    # (the app fails fast without it), which is where migrations execute.
    conn = op.get_bind()
    rows = conn.execute(
        sa.text("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL")
    ).fetchall()
    if rows:
        from common.crypto import CryptoError, decrypt_str, encrypt_str

        for uid, secret in rows:
            if not secret:
                continue
            try:
                decrypt_str(secret)
                continue  # already a valid token -> idempotent re-run, skip
            except CryptoError:
                pass  # legacy plaintext -> encrypt below
            conn.execute(
                sa.text("UPDATE users SET totp_secret = :s WHERE id = :i"),
                {"s": encrypt_str(secret), "i": uid},
            )

    # ---- settings: turn rate limiting on for the existing deployment ----
    # Idempotent UPDATEs against the singleton row. The threshold is only
    # raised when it is still at the old default (10), preserving any value an
    # operator may have set deliberately.
    conn.execute(sa.text("UPDATE settings SET rate_limit_enabled = 1 WHERE id = 1"))
    conn.execute(
        sa.text(
            "UPDATE settings SET rate_limit_threshold = 60 "
            "WHERE id = 1 AND rate_limit_threshold = 10"
        )
    )


def downgrade() -> None:
    # Best-effort: re-narrow the column and drop the counter. Secrets that were
    # encrypted are NOT decrypted back (downgrade is a maintenance operation and
    # the app on this revision expects plaintext); SQLite's flexible typing
    # keeps the longer ciphertext intact in the narrowed column.
    conn = op.get_bind()
    conn.execute(sa.text("UPDATE settings SET rate_limit_enabled = 0 WHERE id = 1"))
    with op.batch_alter_table("users") as batch:
        batch.alter_column(
            "totp_secret",
            existing_type=sa.Text(),
            type_=sa.String(length=64),
            existing_nullable=True,
        )
        batch.drop_column("totp_last_counter")
