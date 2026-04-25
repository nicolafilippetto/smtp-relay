# SMTP Relay — on-premise, Graph API-backed

An SMTP relay packaged as Docker containers. Accepts RFC 5321 traffic on the
customer LAN and forwards each message to Microsoft 365 via Microsoft Graph
`POST /users/{sender}/sendMail` using the OAuth 2.0 **Client Credentials Grant**.
No SMTP connection to Office 365 is ever opened.

A minimalist web UI (HTTPS, local password + TOTP) covers configuration,
queue management, archive browsing, audit log, and ban handling.

---

## Table of contents

1. [Architecture](#architecture)
2. [Requirements](#requirements)
3. [Microsoft Entra ID setup](#microsoft-entra-id-setup)
4. [First run](#first-run)
5. [Day-to-day operation](#day-to-day-operation)
6. [Admin password reset](#admin-password-reset)
7. [Hardening](#hardening)
8. [Retention and the 3-day floor](#retention-and-the-3-day-floor)
9. [Backups and recovery](#backups-and-recovery)
10. [Troubleshooting](#troubleshooting)
11. [Project layout](#project-layout)

---

## Architecture

Three containers orchestrated via `docker-compose.yml`:

| Service | Purpose | Exposed to |
|---------|---------|------------|
| `relay` | aiosmtpd listener + MSAL Graph client + persistent queue + `.eml` archive | LAN (SMTP, default port 2525) |
| `ui`    | FastAPI management app (internal) | nginx only |
| `nginx` | TLS terminator, HTTP→HTTPS redirect, security headers | Operator network (80, 443) |

Shared state lives on two named Docker volumes:

- `smtp-relay-data` — SQLite DB (`/data/relay.db`) and the mail archive (`/data/archive/YYYY/MM/DD/`).
- `smtp-relay-certs` — nginx certificate and key.

Both application containers run as a non-root user (uid 1000), with
`read_only: true`, `cap_drop: ALL`, `no-new-privileges`, and tmpfs for `/tmp`.

---

## Requirements

- Docker Engine ≥ 24 and Docker Compose v2.
- A Microsoft 365 tenant where you can register an application and grant
  the `Mail.Send` **application** permission (Global Admin or Application
  Administrator role).
- At least one mailbox in that tenant that the relay is allowed to send
  *as*. This is the mailbox whose UPN goes into the Graph URL path and
  that you add to the **Authorised senders** list inside the UI.

### Runtime versions pinned in the images

The repository pins every Python dependency to exact versions current in
April 2026. Summary:

| Component | Version |
|-----------|---------|
| Python base image | `python:3.12-slim-bookworm` |
| aiosmtpd | 1.4.6 |
| msal | 1.36.0 |
| fastapi | 0.136.0 |
| uvicorn[standard] | 0.44.0 |
| pydantic / pydantic-settings | 2.13.0 / 2.14.0 |
| SQLAlchemy / aiosqlite / alembic | 2.0.49 / 0.22.1 / 1.18.4 |
| bcrypt | 5.0.0 |
| pyotp / qrcode | 2.9.0 / 8.2 |
| cryptography | 46.0.5 |
| itsdangerous / slowapi | 2.2.0 / 0.1.9 |
| nginx | 1.29-alpine |

---

## Microsoft Entra ID setup

You only need to touch the Entra ID portal. **No Exchange Online
configuration is required** — no connectors, no transport rules, no
authenticated SMTP: Graph `sendMail` is the only transport used.

1. **Register the application.**
   Entra admin center → *Applications* → *App registrations* → *New registration*.
   - Name: e.g. `smtp-relay-<customer>`.
   - Supported account types: *Accounts in this organizational directory only*.
   - Redirect URI: leave blank (CCG does not use one).

2. **Record the IDs.** On the Overview page copy:
   - *Directory (tenant) ID*
   - *Application (client) ID*

3. **Create a client secret.**
   *Certificates & secrets* → *Client secrets* → *New client secret*.
   - Description: `smtp-relay`.
   - Expiry: choose something matching your rotation policy (365 days is reasonable).
   - Copy the **Value** column immediately — it is only shown once.

4. **Grant the `Mail.Send` application permission.**
   *API permissions* → *Add a permission* → *Microsoft Graph* → *Application
   permissions* → expand *Mail* → check `Mail.Send` → *Add permissions*.
   Then click **Grant admin consent for <tenant>** and confirm. The
   permission row must show "Granted for <tenant>" with a green check.

   > `Mail.Send` granted tenant-wide lets the app send as any mailbox. If
   > you need to restrict it to specific mailboxes, also apply an
   > **Application Access Policy** in Exchange Online
   > (`New-ApplicationAccessPolicy`) scoping the app's principal to a
   > mail-enabled security group. That is optional; the relay does not
   > require it, and the UI-level *Authorised senders* list gives you an
   > independent second gate.

5. **No other changes are needed.** Do not configure SMTP AUTH on the
   mailbox. Do not configure a Graph API user account. Do not create a
   connector. The relay uses the application identity only.

---

## First run

1. **Clone and enter the repo.**

   ```sh
   git clone <this-repo> smtp-relay
   cd smtp-relay
   ```

2. **Generate infrastructure secrets.**

   ```sh
   cp .env.example .env

   # ENCRYPTION_KEY: Fernet key for application secrets at rest.
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

   # SECRET_KEY: cookie/CSRF signing key.
   python3 -c "import secrets; print(secrets.token_urlsafe(64))"
   ```

   Paste both values into `.env`. Do not commit this file.

3. **Build and start the stack.**

   ```sh
   docker compose up -d --build
   ```

   The UI container runs `alembic upgrade head`, seeds singleton config
   rows, and creates a default `admin` user with a **one-time random
   password** which is printed to its logs:

   ```sh
   docker compose logs ui | grep -A2 'temporary password'
   ```

   The relay container waits for the schema to appear, then starts its
   SMTP listener.

4. **Open the UI.**

   Browse to `https://<host>/`. The first-time self-signed certificate
   will trigger a browser warning; accept it and sign in as `admin`
   with the password from the logs.

5. **Complete the first-login flow.**

   - Change the admin password (minimum 12 characters).
   - Enrol TOTP in Google Authenticator / Aegis / Bitwarden / 1Password
     by scanning the QR on the page.
   - Enter the 6-digit code to confirm.

6. **Configure the Entra tenant.**

   *Config → Tenant* — paste the tenant ID, client ID, and client secret
   from the Entra app registration. Save, then click **Test connection**.
   You should see a green *OK* and a token expiry ~1 hour in the future.

7. **Add authorised senders.**

   *Config → Authorised senders* — add each mailbox address the relay is
   allowed to send *as*. Any `MAIL FROM` not on this list is rejected
   with `550 Sender not authorized`.

8. **Decide how the relay authenticates SMTP clients.**

   Two modes coexist; at least one must be enabled. Toggle from
   *Config → Settings*.

   - **Local credentials** — create users in *SMTP accounts* and configure
     your sending applications with those credentials. Passwords are
     stored bcrypt-hashed (cost factor 12).
   - **IP whitelist** — add CIDR entries in *Config → IP whitelist*. Mail
     from these sources requires no `AUTH`.

9. **Verify end to end.**

   From inside the LAN, point an SMTP client at `<host>:2525` and send
   a test message. It should land in *Queue* as `pending` → `sending` →
   `sent` and the `.eml` appears under *Archive*.

---

## Day-to-day operation

- **Dashboard.** Relay liveness, mail stats over 24h/7d/30d, Graph
  token state, disk usage, last 10 audit events, active alerts.
- **Queue.** Filter by status (`pending / sending / sent / failed /
  dead`). Retry a single row or every `dead` row with one click.
- **Archive.** Browse by year/month/day. View headers + body preview,
  download the raw `.eml`, or *Resend* to re-enqueue a copy.
- **Audit log.** Filter by event type, outcome, username, IP, date.
  Export the current filter as CSV.
- **SMTP accounts.** Create / edit / toggle / delete. Editing without
  a new password keeps the existing hash.
- **Config → Bans.** See active bans (IP and username, UI and SMTP
  kinds) and clear any of them immediately.

---

## Admin password reset

If you lose the admin password or TOTP device, reset via Docker env
vars. The procedure is deliberately tied to filesystem-level access to
the host so it cannot be exercised over the network.

1. Edit `.env`:

   ```
   ADMIN_RESET=1
   ADMIN_NEW_PASSWORD=<new strong password, min 12 chars>
   ```

2. Restart the UI container:

   ```sh
   docker compose up -d ui
   ```

3. The container:
   - replaces the admin password,
   - clears the TOTP secret,
   - sets `must_change_password = true`,
   - writes an `admin_reset` row into the audit log.

4. Sign in with the new password; the UI forces a password change and
   a fresh TOTP enrolment before unlocking the dashboard.

5. **Revert the env vars** and restart the stack:

   ```
   ADMIN_RESET=0
   ADMIN_NEW_PASSWORD=
   ```

   ```sh
   docker compose up -d
   ```

If `ADMIN_RESET=1` but `ADMIN_NEW_PASSWORD` is empty or shorter than 12
characters, the bootstrap refuses the reset and logs an error — no
partial state is written.

---

## Hardening

### Network exposure

- The UI is never published directly. In `docker-compose.yml` only
  `nginx` maps ports 80/443 and only `relay` maps the SMTP port.
- Bind SMTP to a specific interface (`SMTP_BIND_HOST=10.10.1.5` in
  `.env`) if the host has multiple NICs. Alternatively, publish to
  `127.0.0.1` and front with a host-level firewall that only allows
  the LAN ranges you trust.
- Expose the UI over a VPN or a bastion if you can; the UI is not
  designed to live on the public internet.

### TLS

- The first start generates a self-signed certificate with a 10-year
  lifetime. Replace it by mounting a real `fullchain.pem` and
  `privkey.pem` into the `smtp-relay-certs` volume:

  ```sh
  docker run --rm -v smtp-relay-certs:/certs -v /path/to/real:/real alpine \
      sh -c 'cp /real/fullchain.pem /certs/ && cp /real/privkey.pem /certs/'
  docker compose restart nginx
  ```

- HSTS is enabled (`max-age=31536000; includeSubDomains`). Bear in mind
  this pins the scheme in the browser; keep that in mind while you are
  still testing with a self-signed cert.

### At rest

- Every application secret in the DB is protected:
  - `tenant_config.client_secret_enc` — Fernet-encrypted with
    `ENCRYPTION_KEY`.
  - `smtp_accounts.password_hash`, `users.password_hash` — bcrypt,
    cost factor 12.
  - `users.totp_secret` — stored as the shared-secret string (there is
    nothing to encrypt: compromising the DB already compromises TOTP).
- Rotate `ENCRYPTION_KEY` only when you are prepared to re-enter every
  encrypted secret via the UI. Losing the key means losing the secrets.
- Rotate `SECRET_KEY` freely; the only consequence is that every
  active session cookie and CSRF token is invalidated — users must
  log back in.

### Container hardening

Already applied in `docker-compose.yml`:

- `read_only: true` on the filesystem, with a tmpfs mounted at `/tmp`.
- `cap_drop: ALL`, `no-new-privileges: true`, `security_opt: no-new-privileges`.
- Non-root process (`uid 1000`) inside every application image.
- Docker internal network `smtp-relay-internal`; only nginx and the
  relay publish ports.

Consider layering on top:

- A host-level firewall (iptables/nftables/UFW) pinning the published
  ports to exactly the interfaces they should be reachable on.
- `fail2ban` scanning the nginx and relay logs if you want an extra
  layer of IP-level blocking beyond the UI's built-in ban logic.

### Operational

- Audit log contents are sanitised — keys matching `password`, `secret`,
  `token`, `authorization`, `auth`, `totp` are redacted before being
  JSON-encoded. Do not log raw mail bodies unless you have a reason;
  the *Settings → Logging → Log mail contents at DEBUG* toggle defaults
  to *off*.
- The **Authorised senders** list is a hard gate independent of Entra.
  Even if the Graph app permission is scoped too broadly, the relay
  refuses any `MAIL FROM` not present in this list.

---

## Retention and the 3-day floor

Three retention knobs are exposed in *Config → Settings*:

| Setting | Default | Floor (enforced in code) |
|---------|---------|--------------------------|
| Archive retention | 30 days | **3 days** |
| Audit log retention | 90 days | **30 days** |
| Sent-queue-row retention | 30 days | none |

The floors exist because, in the event of a compromise, an attacker
who gains UI access must not be able to erase the historical record
immediately. The **3-day archive floor** gives the operations team
enough time to notice suspicious behaviour, copy the `smtp-relay-data`
volume off-host, and preserve the `.eml` files as evidence before
automatic pruning removes them.

The floor is applied in three independent places (defence in depth):

- `common/constants.py` defines the integer constants.
- The UI settings saver clamps any value below the floor to the floor
  before writing to the DB.
- `common/archive.effective_retention_days()` is the only function the
  pruner calls, and it clamps again.

No code path — the UI form, the REST handler, a cron job, an Alembic
data migration — can request retention shorter than the floor and have
it actually take effect.

---

## Backups and recovery

Everything that needs to be backed up lives in the two Docker volumes:

```sh
# Full hot snapshot (DB + archive):
docker run --rm \
    -v smtp-relay-data:/data:ro \
    -v "$PWD":/backup \
    alpine tar czf /backup/smtp-relay-data-$(date +%F).tgz -C / data

# Restore:
docker compose down
docker volume create smtp-relay-data
docker run --rm \
    -v smtp-relay-data:/data \
    -v "$PWD":/backup \
    alpine tar xzf /backup/smtp-relay-data-YYYY-MM-DD.tgz -C /
docker compose up -d
```

The DB is SQLite in WAL mode; the copy above is consistent because `tar`
reads the DB and WAL file together. For a guaranteed-quiesced snapshot,
`docker compose stop relay ui` first.

You will also need:

- `.env` — holds `ENCRYPTION_KEY` and `SECRET_KEY`. Without
  `ENCRYPTION_KEY` the backed-up `client_secret_enc` is unusable.

---

## Troubleshooting

### `docker compose logs ui` shows "ENCRYPTION_KEY is not set"
`.env` is not being read. Confirm the file is next to
`docker-compose.yml` and that you did not accidentally comment the
variable out.

### The UI container keeps restarting with "Schema not ready"
Only the relay waits on the schema; if the UI itself cannot migrate,
look a few lines above for the real alembic error. Most commonly:
the `smtp-relay-data` volume predates a model change — run
`docker compose down -v` on a test install and try again. In
production, take a backup first and then run
`docker compose run --rm ui alembic -c ui/alembic.ini upgrade head` by
hand.

### *Test connection* returns `AADSTS7000215: Invalid client secret`
The secret value you pasted is wrong or expired. Generate a new one
in Entra ID and paste it into *Config → Tenant → Client secret*.
Leaving the field blank keeps whatever is already stored.

### *Test connection* returns `AADSTS700016: Application was not found`
The client ID / tenant ID pair is wrong, or the app registration is in
a different tenant from the one you pointed at.

### A message stays in `pending` forever
Check *Config → Tenant* — if the last test failed, the relay cannot
send. Fix the tenant config, click *Test connection*, then hit *Retry
now* on the stuck row from *Queue → <message>*.

### SMTP clients get `530 Authentication required` from whitelisted IPs
The client's source IP as seen by the relay is the Docker bridge NAT
address, not the LAN IP. Check *Queue → <any row> → Source IP* to see
what the relay actually observes, then add that CIDR.

### SMTP clients get `550 Sender not authorized`
The `From:` address is missing from *Config → Authorised senders*, or
is present but disabled. The comparison is case-insensitive.

### I forgot both the admin password and TOTP
Follow [Admin password reset](#admin-password-reset).

---

## Project layout

```
smtp-relay/
├── docker-compose.yml
├── .env.example
├── README.md
├── common/                       # Shared Python package imported by both services
│   ├── archive.py                # .eml writer, 3-day retention floor
│   ├── audit.py                  # Audit writer (sanitised)
│   ├── bans.py                   # Ban bookkeeping
│   ├── constants.py              # All cross-service constants (retention floors)
│   ├── crypto.py                 # Fernet encrypt/decrypt
│   ├── db.py                     # Async engine / session scope / WAL pragma
│   ├── graph_client.py           # MSAL CCG + Graph sendMail
│   ├── models.py                 # Single source of truth for the schema
│   ├── netutils.py               # CIDR matching
│   └── passwords.py              # bcrypt wrapper (cost 12)
├── relay/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── auth.py                   # SMTP auth + IP whitelist + ban integration
│   ├── main.py                   # aiosmtpd controller + queue worker + heartbeat + pruner
│   ├── queue_manager.py          # Persistent queue, retry with backoff
│   └── smtp_handler.py           # aiosmtpd hooks (EHLO/MAIL/RCPT/DATA)
├── ui/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── alembic/
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions/20260424_0000_init.py
│   ├── bootstrap.py              # Admin seed + ADMIN_RESET
│   ├── config.py                 # pydantic-settings UISettings
│   ├── forms.py                  # Pydantic form validators
│   ├── log_config.json           # Uvicorn JSON logger
│   ├── main.py                   # FastAPI app
│   ├── middleware.py             # SecurityHeadersMiddleware
│   ├── security.py               # Session cookie + CSRF
│   ├── templating.py             # Jinja2 environment
│   ├── routers/
│   │   ├── archive.py
│   │   ├── audit.py
│   │   ├── auth.py               # Login + TOTP + logout + password change
│   │   ├── config.py             # Tenant / senders / whitelist / settings / bans
│   │   ├── dashboard.py
│   │   ├── queue.py
│   │   └── smtp_accounts.py
│   ├── static/
│   │   ├── app.css               # Minimal dark-mode-aware stylesheet
│   │   └── app.js                # Tiny CSP-safe confirm() helper
│   └── templates/                # 20+ Jinja2 templates
└── nginx/
    ├── Dockerfile
    ├── entrypoint.sh             # Generates self-signed cert on first start
    └── nginx.conf
```
