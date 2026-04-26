# SMTP Relay — on-premise, Microsoft 365

An on-premise SMTP relay that lets your applications and devices send email through Microsoft 365 **without needing SMTP AUTH**.

---

## Why does this project exist?

Microsoft is retiring Basic Authentication for SMTP AUTH (username + password over SMTP) in **Exchange Online at the end of December 2026** ([official announcement](https://techcommunity.microsoft.com/blog/exchange/updated-exchange-online-smtp-auth-basic-authentication-deprecation-timeline/4489835)). After that date, any printer, scanner, legacy application, or internal tool that sends email via `smtp.office365.com` with a username and password will stop working.

This project solves the problem cleanly: instead of connecting to Office 365 over SMTP, it relays mail through the **Microsoft Graph API** using OAuth 2.0 Client Credentials. Your devices and applications talk to this relay over plain SMTP on your LAN — no code changes needed on their side.

**In short:** your devices keep sending email exactly as they do today. The relay handles the modern authentication with Microsoft 365 on their behalf.

---

## How it works

Three Docker containers, built and published automatically via GitHub Actions:

| Service | Role |
|---------|------|
| `relay` | Accepts SMTP connections on your LAN (port 2525), queues messages, forwards them to Microsoft 365 via Graph API |
| `ui` | Web-based admin panel |
| `nginx` | TLS termination and reverse proxy for the UI |

All persistent data lives in Docker volumes — upgrades never touch your data.

---

## Quick start

You only need two files on your server. No git clone, no build.

### 1. Create `docker-compose.yml`

Create a file called `docker-compose.yml` and paste this content:

```yaml
services:

  ui:
    image: ghcr.io/nicolafilippetto/smtp-relay/ui:latest
    container_name: smtp-relay-ui
    restart: unless-stopped
    expose:
      - "8000"
    environment:
      ENCRYPTION_KEY: ${ENCRYPTION_KEY:?ENCRYPTION_KEY is required}
      SECRET_KEY: ${SECRET_KEY:?SECRET_KEY is required}
      DATABASE_URL: "sqlite+aiosqlite:////data/relay.db"
      ARCHIVE_PATH: "/data/archive"
      SESSION_LIFETIME_HOURS: ${SESSION_LIFETIME_HOURS:-8}
      UI_LOGIN_BAN_THRESHOLD: ${UI_LOGIN_BAN_THRESHOLD:-5}
      UI_LOGIN_BAN_DURATION_MIN: ${UI_LOGIN_BAN_DURATION_MIN:-30}
      ADMIN_RESET: ${ADMIN_RESET:-0}
      ADMIN_NEW_PASSWORD: ${ADMIN_NEW_PASSWORD:-}
      APP_NAME: ${APP_NAME:-SMTP Relay}
      PYTHONUNBUFFERED: "1"
      PYTHONDONTWRITEBYTECODE: "1"
    volumes:
      - data:/data
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
      - /var/tmp:size=16m,mode=1777
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    networks:
      - relay-internal

  relay:
    image: ghcr.io/nicolafilippetto/smtp-relay/relay:latest
    container_name: smtp-relay-smtp
    restart: unless-stopped
    ports:
      - "${SMTP_BIND_HOST:-0.0.0.0}:${SMTP_BIND_PORT:-2525}:2525"
    environment:
      ENCRYPTION_KEY: ${ENCRYPTION_KEY:?ENCRYPTION_KEY is required}
      DATABASE_URL: "sqlite+aiosqlite:////data/relay.db"
      ARCHIVE_PATH: "/data/archive"
      SMTP_LISTEN_HOST: "0.0.0.0"
      SMTP_LISTEN_PORT: "2525"
      SMTP_MAX_MESSAGE_SIZE: ${SMTP_MAX_MESSAGE_SIZE:-31457280}
      PYTHONUNBUFFERED: "1"
      PYTHONDONTWRITEBYTECODE: "1"
    volumes:
      - data:/data
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
      - /var/tmp:size=16m,mode=1777
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    depends_on:
      - ui
    networks:
      - relay-internal

  nginx:
    image: ghcr.io/nicolafilippetto/smtp-relay/nginx:latest
    container_name: smtp-relay-nginx
    restart: unless-stopped
    ports:
      - "${HTTP_BIND_HOST:-0.0.0.0}:${HTTP_PORT:-80}:80"
      - "${HTTPS_BIND_HOST:-0.0.0.0}:${HTTPS_PORT:-443}:443"
    volumes:
      - certs:/etc/nginx/certs
    depends_on:
      - ui
    networks:
      - relay-internal

volumes:
  data:
    name: smtp-relay-data
  certs:
    name: smtp-relay-certs

networks:
  relay-internal:
    name: smtp-relay-internal
    driver: bridge
```

### 2. Create `.env`

In the same folder, create a file called `.env` and paste this content:

```env
# Generate with:
#   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=

# Generate with:
#   python3 -c "import secrets; print(secrets.token_urlsafe(64))"
SECRET_KEY=

# Optional — defaults are shown
APP_NAME=SMTP Relay
SESSION_LIFETIME_HOURS=8
UI_LOGIN_BAN_THRESHOLD=5
UI_LOGIN_BAN_DURATION_MIN=30
SMTP_BIND_HOST=0.0.0.0
SMTP_BIND_PORT=2525
HTTP_PORT=80
HTTPS_PORT=443

# Leave these empty in normal operation (see Admin password reset)
ADMIN_RESET=0
ADMIN_NEW_PASSWORD=
```

Generate the two required values and fill them in:

```sh
# ENCRYPTION_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

> **Keep `.env` safe and never commit it.** `ENCRYPTION_KEY` encrypts secrets stored in the database — losing it means losing your saved credentials.

### 3. Start

```sh
docker compose up -d
```

On first boot the UI creates the database and generates a random `admin` password. Retrieve it with:

```sh
docker compose logs ui | grep -A2 'temporary password'
```

### 4. Open the UI

Browse to `https://<your-server-ip>/`. Accept the self-signed certificate warning and sign in as `admin`.

### 5. First-login setup

- Change the admin password (minimum 12 characters).
- Enrol TOTP (Google Authenticator, Aegis, Bitwarden, 1Password) by scanning the QR code.
- Enter the 6-digit code to confirm.

### 6. Configure Microsoft 365

*Config → Tenant* — paste the Tenant ID, Client ID, and Client Secret from your Entra app registration (see [Microsoft Entra ID setup](#microsoft-entra-id-setup) below). Save, then click **Test connection**.

### 7. Add authorised senders

*Config → Authorised senders* — add each mailbox address the relay is allowed to send *as*. Any `MAIL FROM` not on this list is rejected with `550 Sender not authorized`.

### 8. Configure SMTP client authentication

Two modes available under *Config → Settings* (at least one must be enabled):

- **Local credentials** — create SMTP accounts in the UI and configure your devices with those credentials.
- **IP whitelist** — add trusted CIDR ranges; devices from those IPs can send without credentials.

### 9. Send a test message

Point an SMTP client on your LAN at `<your-server-ip>:2525` and send a test email. Watch it move through *Queue* (`pending → sending → sent`) and appear under *Archive*.

---

## Updating

```sh
docker compose pull
docker compose up -d
```

Migrations run automatically. All data is preserved.

---

## Microsoft Entra ID setup

Everything happens in the Entra admin center. No Exchange Online configuration needed — no connectors, no transport rules.

1. **Register the application.**
   Entra admin center → *Applications* → *App registrations* → *New registration*.
   - Name: e.g. `smtp-relay`.
   - Supported account types: *Accounts in this organizational directory only*.
   - Redirect URI: leave blank.

2. **Copy the IDs.** From the Overview page, save:
   - *Directory (tenant) ID*
   - *Application (client) ID*

3. **Create a client secret.**
   *Certificates & secrets* → *Client secrets* → *New client secret*.
   - Set an expiry matching your rotation policy (e.g. 1 year).
   - **Copy the Value immediately** — it is only shown once.

4. **Grant the `Mail.Send` application permission.**
   *API permissions* → *Add a permission* → *Microsoft Graph* → *Application permissions* → expand *Mail* → check `Mail.Send` → *Add permissions*.
   Click **Grant admin consent for \<tenant\>** and confirm. The row must show a green "Granted" status.

   > By default `Mail.Send` lets the app send as any mailbox in the tenant. To restrict it to specific mailboxes, apply an `New-ApplicationAccessPolicy` in Exchange Online. This is optional — the relay's **Authorised senders** list is an independent gate regardless.

5. Done. No SMTP AUTH configuration needed anywhere.

---

## Day-to-day operation

- **Dashboard** — relay status, mail stats (24h/7d/30d), Graph token state, disk usage, recent audit events.
- **Queue** — filter by status (`pending / sending / sent / failed / dead`). Retry individual messages or all dead ones at once.
- **Archive** — browse by date, preview headers and body, download the raw `.eml`, or resend.
- **Audit log** — filter by event type, outcome, user, IP, date. Export as CSV.
- **SMTP accounts** — create, edit, enable/disable, delete.
- **Config → Bans** — view and clear active IP and username bans.

---

## Admin password reset

If you lose the admin password or TOTP device:

1. Edit `.env`:
   ```
   ADMIN_RESET=1
   ADMIN_NEW_PASSWORD=<new password, min 12 chars>
   ```

2. Restart the UI container:
   ```sh
   docker compose up -d ui
   ```

3. Sign in with the new password — the UI forces a password change and fresh TOTP enrolment.

4. **Revert and restart:**
   ```
   ADMIN_RESET=0
   ADMIN_NEW_PASSWORD=
   ```
   ```sh
   docker compose up -d
   ```

---

## Hardening

**Network:** bind SMTP to a specific interface with `SMTP_BIND_HOST=<LAN-IP>` in `.env`. Keep the UI behind a VPN — it is not designed to be internet-facing.

**TLS:** replace the self-signed certificate by copying a real `fullchain.pem` and `privkey.pem` into the `smtp-relay-certs` volume:

```sh
docker run --rm \
    -v smtp-relay-certs:/certs \
    -v /path/to/real/certs:/real \
    alpine sh -c 'cp /real/fullchain.pem /certs/ && cp /real/privkey.pem /certs/'
docker compose restart nginx
```

---

## Retention

Three settings under *Config → Settings*:

| Setting | Default | Minimum enforced |
|---------|---------|-----------------|
| Archive retention | 30 days | 3 days |
| Audit log retention | 90 days | 30 days |
| Sent queue row retention | 30 days | none |

The minimums prevent an attacker who gains UI access from immediately erasing evidence.

---

## Backups

```sh
# Snapshot (database + archive):
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

Back up `.env` too — without `ENCRYPTION_KEY` the saved client secret is unrecoverable.

---

## Troubleshooting

**`ENCRYPTION_KEY is not set`** — `.env` is missing or the variable is empty.

**UI keeps restarting / "Schema not ready"** — migration failed; check `docker compose logs ui`. Fix then run:
```sh
docker compose run --rm ui alembic -c ui/alembic.ini upgrade head
```

**`AADSTS7000215: Invalid client secret`** — secret is wrong or expired; generate a new one in Entra ID.

**`AADSTS700016: Application was not found`** — wrong client ID or tenant ID.

**Message stuck in `pending`** — Graph connection is broken; go to *Config → Tenant*, fix and test, then retry the message from *Queue*.

**`530 Authentication required` from a whitelisted IP** — the relay sees the Docker bridge NAT address. Check the actual source IP in *Queue → \<row\>* and whitelist that.

**`550 Sender not authorized`** — address missing from *Config → Authorised senders* or disabled there.

**Lost admin password and TOTP** — see [Admin password reset](#admin-password-reset).

---

## Building from source

Clone the repo only if you want to modify the code:

```sh
git clone https://github.com/nicolafilippetto/smtp-relay.git
cd smtp-relay
cp .env.example .env
# fill in ENCRYPTION_KEY and SECRET_KEY
docker compose -f docker-compose.build.yml up -d --build
```
