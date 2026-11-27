"""Smoke test: seed a freshly started stack with known test data.

Run INSIDE the ui container (cwd /app), after the UI has created the schema
and the admin user:

    docker compose exec -T -e SMOKE_ADMIN_PASSWORD=... -e SMOKE_TOTP_SECRET=... \
        ui python - < .github/smoke/seed.py

Sets a known admin password and TOTP secret (so check.py can log in through
the full password + TOTP flow), and adds an SMTP account, an authorised
sender and a default enterprise app with an encrypted client secret.
Test data only: used by .github/workflows/smoke-test.yml on a throwaway stack.
"""

import asyncio
import datetime as dt
import os

from sqlalchemy import select

from common.crypto import encrypt_str
from common.db import session_scope
from common.models import AuthorisedSender, SmtpAccount, TenantConfig, User
from common.passwords import hash_password


async def main() -> None:
    async with session_scope() as s:
        admin = await s.scalar(select(User).where(User.username == "admin"))
        assert admin is not None, "bootstrap did not create the admin user"
        admin.password_hash = hash_password(os.environ["SMOKE_ADMIN_PASSWORD"])
        admin.must_change_password = False
        admin.totp_secret = encrypt_str(os.environ["SMOKE_TOTP_SECRET"])
        admin.totp_enrolled_at = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)

        s.add(
            SmtpAccount(
                username="smoke",
                password_hash=hash_password(os.environ["SMOKE_SMTP_PASSWORD"]),
                allowed_cidrs="",
            )
        )
        s.add(AuthorisedSender(address="sender@example.com", is_enabled=True))

        app = await s.scalar(select(TenantConfig))
        if app is None:
            app = TenantConfig(name="smoke")
            s.add(app)
        app.is_default = True
        app.tenant_id = "00000000-0000-0000-0000-000000000001"
        app.client_id = "00000000-0000-0000-0000-000000000002"
        app.client_secret_enc = encrypt_str("smoke-client-secret")
    print("smoke seed: done")


asyncio.run(main())
