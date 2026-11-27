# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not open a public issue**.

Instead, use GitHub's private disclosure mechanism:

👉 [Report a vulnerability](https://github.com/nicolafilippetto/smtp-relay/security/advisories/new)

This keeps the details private until a fix is available.

There are no formal SLAs or response time guarantees — this is a personal open
source project maintained on a best-effort basis.

---

## Known Accepted Risks

The `ui` and `relay` images are based on `python:3.12-slim-trixie` (Debian 13).
Debian 12 (bookworm), used up to v2.7.3, left full Debian security support on
2026-07-11 and is in LTS only.

Last Trivy scan (2026-11-27, MEDIUM and above): **no CRITICAL findings** in
any image, and none at all in the `nginx` image. The remaining HIGH/MEDIUM
findings in `ui` and `relay` are OS-level CVEs that are **not fixable at this
time** because Debian has not released patches for them (status `affected` /
`fix_deferred`). They are resolved automatically by the periodic image rebuilds
(`apt-get upgrade`) once Debian ships fixes. Notable entries:

| CVE | Package | Severity | Status |
|---|---|---|---|
| CVE-2025-69720 | ncurses | HIGH | No fix available |
| CVE-2025-47273 | setuptools 70.3.0 (vendored by pip) | HIGH | Not applicable — accepted until 2027-05-31 |
| CVE-2026-59890 | setuptools 70.3.0 (vendored by pip) | MEDIUM | Not applicable — accepted until 2027-05-31 |

setuptools is not installed in the images. pip vendors only `pkg_resources`
from setuptools 70.3.0 and lists that version in `pip/_vendor/vendor.txt`,
which is what Trivy reports. The vulnerable code (`PackageIndex.download` and
the sdist `MANIFEST.in` handling) is not shipped. Drop the two entries once pip
vendors a fixed setuptools.

The CVEs previously accepted on Debian 12 (glibc CVE-2026-0861, libsqlite3
CVE-2025-7458, systemd CVE-2026-29111, zlib CVE-2023-45853, perl-base
CVE-2026-8376 / CVE-2026-42496) are no longer reported.

All CVEs in the Python dependencies (`requirements.txt`) have been resolved.

[`.trivyignore`](.trivyignore) holds the accepted CVEs, so that the security
scan (which fails on fixable HIGH/CRITICAL findings) passes with the risk
acceptance recorded in version control. Entries carry an expiry date, after
which Trivy reports them again and they must be reviewed. Keep the file in
sync with this section.

---

## Keeping dependencies up to date

Automated:

- **Dependabot version updates** (`.github/dependabot.yml`), weekly:
  - `docker`: digest bumps of the pinned base images (relay, ui, nginx);
  - `pip`: the pinned Python dependencies of relay, ui and the Windows
    package, updated together in one pull request so the three
    `requirements.txt` files stay in sync (aiosmtpd and major updates get a
    pull request of their own);
  - `github-actions`: the actions used by the workflows.
- **Dependabot alerts and security updates** (repository settings), for
  advisories against the declared dependencies.
- **Security scan** (`.github/workflows/security-scan.yml`): builds the three
  images and scans them with Trivy on every pull request into `main`, on every
  push to `main` and every Monday. It fails on HIGH/CRITICAL vulnerabilities
  that have a fix, and when the base image's OS has reached end of life. On
  `main` and on the weekly run the findings also go to the Security tab. A
  failing weekly run means the images need a rebuild or an update.
- **Smoke test** (`.github/workflows/smoke-test.yml`): on every pull request
  into `main` and every push to `main`, starts the whole stack and uses it
  (admin login with password + TOTP, every UI page reachable from the
  dashboard, SMTP AUTH and a message accepted into the queue, no tracebacks
  in the logs). A dependency update that builds but breaks the app fails here.
- **Windows build** (`.github/workflows/windows-build.yml`) also runs on pull
  requests that touch the Windows package, Dependabot's included.

Review Dependabot pull requests before merging, even when green: read the
changelog of any update that jumps several versions (FastAPI 0.x releases, for
example, can contain breaking changes), and merge only when the security
scan, the smoke test and the Windows build all pass.

Manual, every few months (no tool reports these):

- **Base image names**: check on Docker Hub that `python` and
  `nginx/nginx-unprivileged` are still the maintained names (the nginx image
  moved from `nginxinc/` in 2026 and the old name silently stopped updating).
- **Debian release**: Dependabot never moves the `-trixie` suffix. Plan the
  move to the next Debian release before Debian 13 leaves full support.
- **Python 3.12**: upstream security support ends in October 2028.
- **Trivy**: the scanner image is pinned by digest in `security-scan.yml` and
  is not updated by Dependabot. Bump it to a recent release (at least two
  weeks old) with its new digest.
- **`.trivyignore`**: review entries close to their expiry date.

---

## Cache-Control on Static Assets

ZAP baseline scan reports a `Re-examine Cache-control Directives` warning on
`app.css` and `app.js`. This is a known accepted risk:

- Both files are small public assets (CSS ~12KB, JS ~600 bytes)
- Neither contains sensitive information
- Disabling caching would increase latency and bandwidth on every page load

---

## Disclaimer

This software is provided **as-is** under the MIT License, without warranty of
any kind. The author is not responsible for any damage or security incidents
arising from the use of this software. See [LICENSE](LICENSE) for full details.
