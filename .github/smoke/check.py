"""Smoke test: exercise a running stack from the outside, like a user would.

Run on the host after seed.py (standard library only):

    SMOKE_ADMIN_PASSWORD=... SMOKE_TOTP_SECRET=... SMOKE_SMTP_PASSWORD=... \
        python3 .github/smoke/check.py

Ports come from SMOKE_HTTP_PORT / SMOKE_HTTPS_PORT / SMOKE_SMTP_PORT
(defaults 18080 / 18443 / 12525, as set in the smoke-test workflow).
Exits non-zero if any check fails.
"""

import base64
import hashlib
import hmac
import http.cookiejar
import os
import re
import smtplib
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HTTP_PORT = int(os.environ.get("SMOKE_HTTP_PORT", "18080"))
HTTPS_PORT = int(os.environ.get("SMOKE_HTTPS_PORT", "18443"))
SMTP_PORT = int(os.environ.get("SMOKE_SMTP_PORT", "12525"))
ADMIN_PASSWORD = os.environ["SMOKE_ADMIN_PASSWORD"]
TOTP_SECRET = os.environ["SMOKE_TOTP_SECRET"]
SMTP_PASSWORD = os.environ["SMOKE_SMTP_PASSWORD"]
BASE = f"https://127.0.0.1:{HTTPS_PORT}"

failures = 0


def check(name: str, ok: bool, info: object = "") -> None:
    global failures
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {info}", flush=True)


# The stack uses a self-signed certificate: no verification, test only.
# TLS 1.0/1.1 are refused explicitly; nginx is expected to negotiate 1.3.
ctx = ssl.create_default_context()
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    _NoRedirect,
)


def request(url: str, form: dict | None = None):
    data = urllib.parse.urlencode(form).encode() if form else None
    try:
        r = opener.open(urllib.request.Request(url, data=data), timeout=15)
        return r.status, r.headers, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode(errors="replace")


def csrf(body: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', body)
    return m.group(1) if m else ""


def totp_code(secret: str, step: int) -> str:
    key = base64.b32decode(secret)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


# --- wait until the stack answers ----------------------------------------
deadline = time.time() + 180
while True:
    try:
        status, _, _ = request(f"{BASE}/login")
        with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=5) as s:
            banner = s.recv(512)
        if status == 200 and banner.startswith(b"220"):
            break
    except OSError:
        pass
    if time.time() > deadline:
        check("stack answers on HTTPS and SMTP within 180 s", False)
        sys.exit(1)
    time.sleep(3)

# --- nginx ---------------------------------------------------------------
status, headers, _ = request(f"http://127.0.0.1:{HTTP_PORT}/login")
check(
    "HTTP redirects to HTTPS",
    status in (301, 302, 307, 308) and headers.get("Location", "").startswith("https://"),
    (status, headers.get("Location")),
)
with socket.create_connection(("127.0.0.1", HTTPS_PORT)) as raw, ctx.wrap_socket(raw) as tls:
    check("TLS 1.3", tls.version() == "TLSv1.3", tls.version())

# --- UI: password + TOTP login -------------------------------------------
status, _, body = request(f"{BASE}/login")
check("login page", status == 200 and csrf(body), status)
status, headers, _ = request(
    f"{BASE}/login",
    {"username": "admin", "password": ADMIN_PASSWORD, "csrf_token": csrf(body)},
)
check("password accepted, TOTP requested", status == 303 and headers.get("Location") == "/login/totp", (status, headers.get("Location")))
status, _, body = request(f"{BASE}/login/totp")
status, headers, _ = request(
    f"{BASE}/login/totp",
    {"code": totp_code(TOTP_SECRET, int(time.time()) // 30), "csrf_token": csrf(body)},
)
check("TOTP code accepted", status == 303 and headers.get("Location") == "/dashboard", (status, headers.get("Location")))

# --- UI: every page reachable from the dashboard (3 levels) ---------------
SKIP = ("logout", "download", "export", "delete", "reset", "revoke")
seen: dict[str, int] = {}
todo = ["/dashboard"]
for _ in range(3):
    found = []
    for path in todo:
        if path in seen or any(word in path for word in SKIP):
            continue
        status, _, body = request(f"{BASE}{path}")
        seen[path] = status
        found += [p for p in re.findall(r'href="(/[^"#?]*)', body) if not p.startswith("/static")]
    todo = found
broken = {p: s for p, s in seen.items() if s >= 500 or s == 404}
check(f"{len(seen)} UI pages load (no 5xx/404)", len(seen) >= 5 and not broken, broken or sorted(seen))

# --- SMTP relay ----------------------------------------------------------
smtp = smtplib.SMTP("127.0.0.1", SMTP_PORT, timeout=15)
smtp.ehlo()
start = time.time()
try:
    smtp.login("smoke", "wrong-password")
    result: object = "accepted"
except smtplib.SMTPAuthenticationError as e:
    result = e
except Exception as e:  # noqa: BLE001
    result = e
check(
    "SMTP wrong password -> 535",
    isinstance(result, smtplib.SMTPAuthenticationError) and result.smtp_code == 535,
    f"{result!r} after {time.time() - start:.1f}s",
)
smtp.close()

smtp = smtplib.SMTP("127.0.0.1", SMTP_PORT, timeout=15)
smtp.ehlo()
code, _ = smtp.login("smoke", SMTP_PASSWORD)
check("SMTP correct password -> 235", code == 235, code)
refused = smtp.sendmail(
    "sender@example.com",
    ["rcpt@example.com"],
    "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: smoke\r\n\r\nsmoke test\r\n",
)
check("SMTP message accepted into the queue", refused == {}, refused)
smtp.quit()

print(f"\n{failures} check(s) failed" if failures else "\nall checks passed")
sys.exit(1 if failures else 0)
