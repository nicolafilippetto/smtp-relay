# SMTP Relay on Windows (native services)

This is the **native Windows** packaging of SMTP Relay. Instead of Docker, it
installs two background **Windows services** from a single installer:

| Service | What it does | Listens on |
|---------|--------------|-----------|
| `smtp-relay-relay` | Accepts SMTP and forwards mail to Microsoft 365 (Graph API) | TCP **2525** |
| `smtp-relay-ui` | Admin web panel (uvicorn) | **http://127.0.0.1:8000** (localhost only) |

There is **no nginx and no HTTPS** in this build by design: the panel is
reachable only from the machine itself, over plain HTTP on loopback. The relay
and the UI talk only through a shared SQLite database — exactly like the Docker
deployment.

> The Docker deployment is unchanged and fully supported. This is an
> alternative for sites that prefer not to run Docker on Windows.

---

## Install

1. Download `smtp-relay-setup.exe` from the project Releases page.
2. Run it (you will be prompted for Administrator rights).
3. Follow the wizard. At the end the installer prints a **temporary admin
   password** and also saves it to `C:\ProgramData\smtp-relay\FIRST-LOGIN.txt`.
4. Open **http://127.0.0.1:8000**, log in as `admin` with that password. You
   will be required to change the password and enrol two-factor authentication
   (TOTP) on first login.
5. In the panel, configure your Microsoft 365 (Entra ID) application and your
   SMTP accounts — same as the Docker version.

> The installer is currently **not code-signed**, so Windows SmartScreen may
> show an "unknown publisher" warning. Choose *More info → Run anyway*.

---

## Where things live

```
C:\Program Files\smtp-relay\        <- application (installed by the wizard)
    app\smtp-relay.exe              <- the actual program
    smtp-relay-relay.exe / .xml     <- WinSW service wrapper + config
    smtp-relay-ui.exe    / .xml
    install.ps1 / uninstall.ps1

C:\ProgramData\smtp-relay\          <- your data (keep backed up, holds secrets)
    config.env                      <- ENCRYPTION_KEY, SECRET_KEY, optional knobs
    data\relay.db                   <- the database
    data\archive\                   <- sent-mail archive (.eml)
    logs\relay\ , logs\ui\          <- service logs
    FIRST-LOGIN.txt                 <- temporary admin password (delete after use)
```

**Do not change `ENCRYPTION_KEY` after first start** — every encrypted secret
(such as the Microsoft 365 client secret) would become unreadable.

---

## Manage the services

Use **Services** (`services.msc`) — look for *SMTP Relay - Relay* and
*SMTP Relay - Web UI* — or from an elevated PowerShell:

```powershell
Get-Service smtp-relay-*            # status
Restart-Service smtp-relay-ui      # restart the panel
Restart-Service smtp-relay-relay   # restart the relay
```

Both start automatically at boot and restart on failure.

---

## Configuration

Edit `C:\ProgramData\smtp-relay\config.env` and restart the services. Common
options (all optional, with safe defaults) are documented inline in the file:
the SMTP listen host/port, the message size limit, the UI port, and the
database/archive locations. Values set here override the built-in defaults.

---

## Uninstall

Use *Add or remove programs* → **SMTP Relay** → Uninstall. This stops and
removes both services and the firewall rule. Your data directory
(`C:\ProgramData\smtp-relay`) is **kept** by default so you don't lose the
database or keys. To remove it too, run from an elevated PowerShell:

```powershell
& "C:\Program Files\smtp-relay\uninstall.ps1" -RemoveData
```

---

## Security notes

- Services run under **low-privilege per-service accounts**
  (`NT SERVICE\smtp-relay-relay` and `...-ui`), not LocalSystem. Only those
  accounts and Administrators can read/write the data directory.
- The web panel is **loopback-only** (127.0.0.1). To administer it from another
  machine you would need to add a reverse proxy with HTTPS — not included here.
- Only the SMTP port (2525) is opened in the firewall, restricted to the
  Private and Domain profiles. **Never expose the relay directly to the
  internet** (open relays get abused).
- The application-level protections are identical to the Docker build: admin
  password + TOTP, login throttling, security headers, and secrets encrypted
  at rest.

---

## Building the installer yourself

You normally don't need to: the installer is built automatically by the
`Windows build` GitHub Actions workflow on a Windows runner and attached to
each release. To build locally on a Windows machine with Python 3.12 and
[Inno Setup 6](https://jrsoftware.org/isdl.php):

```powershell
pip install -r windows\requirements.txt
pyinstaller --noconfirm windows\smtp-relay.spec
# stage dist\smtp-relay\* into staging\app\, add WinSW + the windows\ assets,
# then:
iscc /DMyAppVersion=1.0.0 /DStageDir=<abs path to staging> windows\smtp-relay.iss
```

(The CI workflow `.github/workflows/windows-build.yml` performs exactly these
steps and is the reference.)
