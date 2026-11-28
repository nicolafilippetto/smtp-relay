"""Check an nginx version against the official nginx security advisories.

Trivy does not report CVEs for nginx itself in our image: nginx comes from
the nginx.org Alpine repository, which Trivy has no advisory data for (it
listed nginx 1.31.7 with zero CVEs while 11 published advisories applied).
This script closes that gap by reading https://nginx.org/en/security_advisories.html.

Usage:  python3 check_nginx_advisories.py 1.31.10
Exit:   0 = no advisory applies, 1 = the version is vulnerable,
        2 = the advisories page could not be fetched or parsed (fail loudly
            rather than report a false "all clear").

An advisory applies when the version lies in one of its "Vulnerable" ranges
and is not covered by its "Not vulnerable" list. "X.Y.Z+" covers X.Y.Z and
later on the same X.Y branch; the highest entry also covers every newer
branch (e.g. "1.31.10+, 1.30.8+" -> 1.30.8+, 1.31.10+, and 1.32.x).
"""

import html
import re
import sys
import urllib.request

URL = "https://nginx.org/en/security_advisories.html"
VERSION = re.compile(r"\d+\.\d+\.\d+")


def parse(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def not_vulnerable(version: tuple[int, ...], fixed: list[tuple[int, ...]]) -> bool:
    if not fixed:
        return False
    if version >= max(fixed):
        return True
    return any(version[:2] == f[:2] and version >= f for f in fixed)


def in_ranges(version: tuple[int, ...], text: str) -> bool:
    for lo, hi in re.findall(r"(\d+\.\d+\.\d+)-(\d+\.\d+\.\d+)", text):
        if parse(lo) <= version <= parse(hi):
            return True
    # Single versions listed without a range (e.g. "Vulnerable: 1.5.10").
    singles = re.sub(r"\d+\.\d+\.\d+-\d+\.\d+\.\d+", "", text)
    return any(version == parse(v) for v in VERSION.findall(singles))


def main() -> int:
    if len(sys.argv) != 2 or not VERSION.fullmatch(sys.argv[1]):
        print("usage: check_nginx_advisories.py <nginx version, e.g. 1.31.10>")
        return 2
    version = parse(sys.argv[1])
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "nginx-advisory-check"})
        page = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        print(f"::error::cannot fetch {URL}: {e}")
        return 2

    entries = re.findall(r"<li><p>(.*?)</p></li>", page, re.S)
    hits, parsed = [], 0
    for raw in entries:
        parts = [html.unescape(re.sub(r"<[^>]+>", "", p)).strip() for p in re.split(r"<br\s*/?>", raw)]
        vuln = next((p for p in parts if p.startswith("Vulnerable:")), None)
        if vuln is None:
            continue
        parsed += 1
        fixed_line = next((p for p in parts if p.startswith("Not vulnerable:")), "")
        fixed = [parse(v) for v in VERSION.findall(fixed_line)]
        if in_ranges(version, vuln) and not not_vulnerable(version, fixed):
            cves = ", ".join(p for p in parts if p.startswith("CVE-")) or "no CVE id"
            hits.append(f"{parts[0]} ({cves}) -- {fixed_line or 'no fixed version listed'}")

    if parsed < 20:
        print(f"::error::only {parsed} advisories parsed from {URL}; the page layout may have changed")
        return 2
    print(f"nginx {sys.argv[1]}: checked against {parsed} advisories from {URL}")
    if hits:
        for h in hits:
            print(f"::error::nginx {sys.argv[1]} is affected by: {h}")
        print(f"{len(hits)} advisory(ies) apply: update the nginx base image.")
        return 1
    print("no published advisory applies to this version")
    return 0


if __name__ == "__main__":
    sys.exit(main())
