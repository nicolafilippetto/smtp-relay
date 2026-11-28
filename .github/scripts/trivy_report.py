"""Summarise a full Trivy JSON report as Markdown (for the job summary).

The blocking scan only fails on HIGH/CRITICAL vulnerabilities that have a
fix. This report is informational: every severity, with or without a fix,
including the CVEs accepted in .trivyignore, so the remaining risk is visible.

Usage:  python3 trivy_report.py <trivy.json> <service> [.trivyignore]
Prints Markdown to stdout; never fails the job on findings.
"""

import collections
import datetime as dt
import json
import re
import sys

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def accepted_ids(path: str | None) -> dict[str, str]:
    """CVE id -> expiry date ('' if none) from a .trivyignore file."""
    out: dict[str, str] = {}
    if not path:
        return out
    try:
        for line in open(path, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.search(r"exp:(\d{4}-\d{2}-\d{2})", line)
            out[line.split()[0]] = m.group(1) if m else ""
    except FileNotFoundError:
        pass
    return out


def main() -> int:
    report_path, service = sys.argv[1], sys.argv[2]
    accepted = accepted_ids(sys.argv[3] if len(sys.argv) > 3 else None)
    today = dt.date.today().isoformat()
    report = json.load(open(report_path, encoding="utf-8"))

    rows = []
    seen = set()
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            key = (v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion"))
            if key in seen:
                continue
            seen.add(key)
            exp = accepted.get(v["VulnerabilityID"])
            rows.append({
                "id": v["VulnerabilityID"],
                "sev": v.get("Severity", "UNKNOWN"),
                "pkg": v["PkgName"],
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", ""),
                "status": v.get("Status", ""),
                "title": (v.get("Title") or "").replace("|", "/")[:90],
                "accepted": exp is not None and (exp == "" or exp >= today),
            })

    os_meta = (report.get("Metadata") or {}).get("OS") or {}
    distinct = len({r["id"] for r in rows})
    print(f"### `{service}` image: {distinct} distinct CVEs, {len(rows)} findings (all severities)\n")
    print("A CVE in a library shipped as several packages counts once per package in the table.\n")
    if os_meta:
        eosl = " — **END OF LIFE**" if os_meta.get("EOSL") else ""
        print(f"Base OS: {os_meta.get('Family', '?')} {os_meta.get('Name', '?')}{eosl}\n")

    print("| Severity | Total | Fix available | No fix yet | Accepted (.trivyignore) |")
    print("|---|---:|---:|---:|---:|")
    by_sev = collections.defaultdict(list)
    for r in rows:
        by_sev[r["sev"]].append(r)
    for sev in SEVERITIES:
        items = by_sev.get(sev, [])
        fix = sum(1 for r in items if r["fixed"])
        acc = sum(1 for r in items if r["accepted"])
        print(f"| {sev} | {len(items)} | {fix} | {len(items) - fix} | {acc} |")

    top = [r for r in rows if r["sev"] in ("CRITICAL", "HIGH")]
    if top:
        print("\n<details><summary>CRITICAL and HIGH findings</summary>\n")
        print("| CVE | Severity | Package | Installed | Fixed in | Status | Note |")
        print("|---|---|---|---|---|---|---|")
        order = {s: i for i, s in enumerate(SEVERITIES)}
        for r in sorted(top, key=lambda r: (order[r["sev"]], not r["fixed"], r["pkg"], r["id"])):
            note = "accepted" if r["accepted"] else ("**fix available**" if r["fixed"] else "")
            print(f"| {r['id']} | {r['sev']} | {r['pkg']} | {r['installed']} | {r['fixed'] or '—'} "
                  f"| {r['status']} | {note} |")
        print("\n</details>")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
