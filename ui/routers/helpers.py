"""Shared helpers for UI routers.

Keeping per-router code lean. The only helper here, for now, is
`audit_config_change` — used by every config mutation endpoint to
write a uniform audit record without repeating the same boilerplate.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from common.audit import record as audit_record
from common.models import AuditEventType, AuditOutcome

from ..security import SessionPayload


async def audit_config_change(
    s: AsyncSession,
    session: SessionPayload,
    request: Request,
    details: dict[str, Any],
) -> None:
    await audit_record(
        s,
        event_type=AuditEventType.CONFIG_CHANGE,
        outcome=AuditOutcome.SUCCESS,
        username=session.username,
        source_ip=request.client.host if request.client else None,
        details=details,
    )
