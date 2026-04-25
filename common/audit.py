"""Audit log writer.

Both the relay and the UI call `record(...)` to append a row. The
function scrubs obviously sensitive fields (`password`, `client_secret`,
`token`, `secret`, `auth`, `authorization`) from the supplied details
dict to avoid leaking secrets into the audit trail itself.

This helper never raises on bad input — audit writes must not be the
reason a request fails. It logs a warning and returns.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Mapping

from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEventType, AuditLog, AuditOutcome

_log = logging.getLogger("relay.audit")

# Any key matching one of these (case-insensitive substring match) has
# its value replaced with "***" before being serialised.
_SENSITIVE_KEY_PARTS = (
    "password",
    "client_secret",
    "token",
    "secret",
    "authorization",
    "auth",
    "totp",
)


def _scrub(details: Mapping[str, Any] | None) -> str | None:
    if not details:
        return None
    scrubbed: dict[str, Any] = {}
    for k, v in details.items():
        lk = str(k).lower()
        if any(part in lk for part in _SENSITIVE_KEY_PARTS):
            scrubbed[k] = "***"
        else:
            scrubbed[k] = v
    try:
        return json.dumps(scrubbed, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return json.dumps({"_error": "details not serialisable"})


async def record(
    session: AsyncSession,
    *,
    event_type: AuditEventType,
    outcome: AuditOutcome,
    source_ip: str | None = None,
    username: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> None:
    """Append one row to the audit log. Never raises."""
    try:
        entry = AuditLog(
            event_type=event_type,
            outcome=outcome,
            source_ip=source_ip,
            username=username,
            details_json=_scrub(details),
        )
        session.add(entry)
        # Caller is expected to commit; we flush so the row is visible
        # within the caller's transaction.
        await session.flush()
    except Exception as exc:  # pragma: no cover - defensive
        _log.warning("Failed to record audit event %s: %s", event_type, exc)
