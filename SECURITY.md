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

Last Trivy scan (2026-11-26, MEDIUM and above): **no CRITICAL findings** in
any image, and none at all in the `nginx` image. The remaining HIGH/MEDIUM
findings in `ui` and `relay` are OS-level CVEs that are **not fixable at this
time** because Debian has not released patches for them (status `affected` /
`fix_deferred`). They are resolved automatically by the periodic image rebuilds
(`apt-get upgrade`) once Debian ships fixes. Notable entry:

| CVE | Package | Severity | Status |
|---|---|---|---|
| CVE-2025-69720 | ncurses | HIGH | No fix available |

The CVEs previously accepted on Debian 12 (glibc CVE-2026-0861, libsqlite3
CVE-2025-7458, systemd CVE-2026-29111, zlib CVE-2023-45853, perl-base
CVE-2026-8376 / CVE-2026-42496) are no longer reported.

All CVEs in the Python dependencies (`requirements.txt`) have been resolved.

[`.trivyignore`](.trivyignore) holds the accepted CVEs, so that a Trivy scan
configured to fail on CRITICAL findings passes with the risk acceptance
recorded in version control. It is currently empty. Keep it in sync with this
section.

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
