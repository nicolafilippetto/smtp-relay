"""Mail archive on the shared volume.

Layout:
    /data/archive/YYYY/MM/DD/<id>-<sanitised-subject>.eml

Every successful send writes an .eml file here. The pruner is called
periodically by the relay and the UI; it deletes files whose mtime is
older than the configured retention, clamped to the hard-coded floor
defined in `common/constants.py`.

The floor is enforced *here*, at the only write path that touches the
filesystem. UI validation also clamps, but defense-in-depth means a
compromised caller still cannot cause immediate data loss.
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import re
from pathlib import Path
from typing import Iterable

from .constants import ARCHIVE_RETENTION_MIN_DAYS

_log = logging.getLogger("relay.archive")


def _archive_root() -> Path:
    return Path(os.environ.get("ARCHIVE_PATH", "/data/archive"))


_SAFE_SUBJECT = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitise(subject: str | None, max_len: int = 48) -> str:
    if not subject:
        return "nosubject"
    cleaned = _SAFE_SUBJECT.sub("_", subject).strip("_")
    return (cleaned or "nosubject")[:max_len]


def write_eml(
    *,
    message_id: int,
    subject: str | None,
    raw_mime: bytes,
    when: _dt.datetime | None = None,
) -> Path:
    """Persist a raw MIME message to the archive. Returns the path."""
    if not isinstance(raw_mime, (bytes, bytearray)):
        raise TypeError("raw_mime must be bytes")

    stamp = when or _dt.datetime.now(_dt.timezone.utc)
    day_dir = _archive_root() / f"{stamp.year:04d}" / f"{stamp.month:02d}" / f"{stamp.day:02d}"
    day_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{message_id:010d}-{_sanitise(subject)}.eml"
    path = day_dir / filename

    # Atomic write via rename so a crash mid-write never leaves a
    # half-written .eml visible.
    tmp = path.with_suffix(".eml.part")
    with open(tmp, "wb") as fh:
        fh.write(raw_mime)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)

    # Files are read-only once archived (0640 -> owner rw, group r).
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass

    return path


def read_eml(path: str | Path) -> bytes:
    """Read a single .eml. Path must live inside the archive root."""
    root = _archive_root().resolve()
    resolved = Path(path).resolve()
    if root not in resolved.parents and resolved != root:
        raise PermissionError("Refusing to read outside the archive root.")
    return resolved.read_bytes()


def effective_retention_days(requested: int) -> int:
    """Clamp a requested retention to the hard floor.

    This is THE chokepoint: UI, API, cron, Alembic data migrations —
    every path that wants to set retention must call this helper,
    because the pruner only uses the effective value.
    """
    if requested is None:
        return ARCHIVE_RETENTION_MIN_DAYS
    return max(int(requested), ARCHIVE_RETENTION_MIN_DAYS)


def _walk_archive() -> Iterable[Path]:
    root = _archive_root()
    if not root.exists():
        return []
    return (p for p in root.rglob("*.eml") if p.is_file())


def prune(retention_days: int) -> int:
    """Delete .eml files older than the effective retention.

    Returns the number of files removed. Empty day/month/year
    directories are pruned as a side effect.
    """
    days = effective_retention_days(retention_days)
    cutoff = _dt.datetime.now(_dt.timezone.utc).timestamp() - days * 86400

    removed = 0
    for f in _walk_archive():
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        except FileNotFoundError:
            continue
        except OSError as exc:
            _log.warning("Could not delete %s: %s", f, exc)

    # Second pass: remove empty dirs bottom-up, but never the root.
    root = _archive_root()
    if root.exists():
        for dirpath, dirnames, filenames in os.walk(root, topdown=False):
            p = Path(dirpath)
            if p == root:
                continue
            if not any(p.iterdir()):
                try:
                    p.rmdir()
                except OSError:
                    pass

    if removed:
        _log.info("Archive prune: removed %d files older than %d days", removed, days)
    return removed


def archive_disk_usage_bytes() -> int:
    """Total bytes consumed by archived .eml files."""
    total = 0
    for f in _walk_archive():
        try:
            total += f.stat().st_size
        except OSError:
            continue
    return total
